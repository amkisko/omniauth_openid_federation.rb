require_relative "../logger"
require_relative "../errors"

# Metadata Policy Merger for OpenID Federation 1.0
# @see https://openid.net/specs/openid-federation-1_0.html#section-5.1 Section 5.1: Metadata Policy
#
# Merges metadata policies from a Trust Chain and applies them to entity metadata.
# Policies are merged from Trust Anchor down to the immediate issuer, then applied
# to the leaf entity's metadata.
#
# @example Merge and apply metadata policies
#   merger = MetadataPolicyMerger.new(trust_chain: trust_chain_statements)
#   effective_metadata = merger.merge_and_apply(leaf_metadata)
module OmniauthOpenidFederation
  module Federation
    # Metadata Policy Merger for OpenID Federation 1.0
    #
    # Merges metadata policies from Subordinate Statements in a Trust Chain
    # and applies them to entity metadata.
    class MetadataPolicyMerger
      # Initialize merger
      #
      # @param trust_chain [Array<EntityStatement, Hash>] Array of entity statements in trust chain
      #   (from Leaf to Trust Anchor)
      def initialize(trust_chain:)
        @trust_chain = trust_chain
        @merged_policies = nil
      end

      # Merge all metadata policies from the trust chain
      #
      # @return [Hash] Merged metadata policies by entity type and parameter
      # @raise [ValidationError] If policy merging fails due to conflicts
      def merge_policies
        return @merged_policies if @merged_policies

        @merged_policies = {}

        # Extract policies from Subordinate Statements (skip Entity Configurations)
        subordinate_statements = @trust_chain.select do |statement|
          parsed = statement.is_a?(Hash) ? statement : statement.parse
          parsed[:is_subordinate_statement] || parsed["is_subordinate_statement"]
        end

        # Merge policies from Trust Anchor down to immediate issuer
        # (reverse order: Trust Anchor first, then intermediates, then immediate issuer)
        subordinate_statements.reverse_each do |statement|
          parsed = statement.is_a?(Hash) ? statement : statement.parse
          metadata_policy = parsed[:metadata_policy] || parsed["metadata_policy"]
          next unless metadata_policy

          merge_single_policy(metadata_policy)
        end

        @merged_policies
      end

      # Apply merged policies to entity metadata
      #
      # @param entity_metadata [Hash] Original entity metadata
      # @return [Hash] Effective metadata after applying policies
      # @raise [ValidationError] If metadata does not comply with policies
      def apply_policies(entity_metadata)
        merged = merge_policies
        effective_metadata = deep_dup(entity_metadata)

        # Apply policies for each entity type
        merged.each do |entity_type, type_policies|
          entity_type_metadata = effective_metadata[entity_type.to_sym] || effective_metadata[entity_type.to_s] || {}

          # Apply policies for each metadata parameter
          type_policies.each do |param_name, param_policy|
            apply_parameter_policy(entity_type_metadata, param_name, param_policy)
          end

          # Store back to effective metadata
          effective_metadata[entity_type.to_sym] = entity_type_metadata
        end

        # Validate final metadata against policies
        validate_metadata_compliance(effective_metadata, merged)

        effective_metadata
      end

      # Merge and apply policies in one step
      #
      # @param entity_metadata [Hash] Original entity metadata
      # @return [Hash] Effective metadata after applying policies
      # @raise [ValidationError] If merging or application fails
      def merge_and_apply(entity_metadata)
        apply_policies(entity_metadata)
      end

      private

      def merge_single_policy(metadata_policy)
        metadata_policy.each do |entity_type, type_policies|
          entity_type_str = entity_type.to_s
          @merged_policies[entity_type_str] ||= {}

          type_policies.each do |param_name, param_policy|
            param_name_str = param_name.to_s
            existing_policy = @merged_policies[entity_type_str][param_name_str]

            @merged_policies[entity_type_str][param_name_str] = if existing_policy
              merge_parameter_policies(
                existing_policy,
                param_policy
              )
            else
              normalize_keys_to_strings(deep_dup(param_policy))
            end
          end
        end
      end

      def merge_parameter_policies(existing_policy, new_policy)
        merged = deep_dup(existing_policy)
        # Normalize merged to use string keys for consistency
        merged = normalize_keys_to_strings(merged)

        new_policy.each do |operator, value|
          operator_str = operator.to_s

          case operator_str
          when "value"
            # value operator: values must be equal, or this is an error
            if merged["value"] && merged["value"] != value
              raise ValidationError, "Conflicting 'value' operators in metadata policy: #{merged["value"]} vs #{value}"
            end
            merged["value"] = value

          when "add"
            # add operator: union of values
            existing_add = merged["add"] || []
            new_add = value.is_a?(Array) ? value : [value]
            merged["add"] = (existing_add + new_add).uniq

          when "one_of"
            # one_of operator: intersection of values
            existing_one_of = merged["one_of"] || []
            new_one_of = value.is_a?(Array) ? value : [value]
            intersection = existing_one_of & new_one_of
            if intersection.empty? && !existing_one_of.empty? && !new_one_of.empty?
              raise ValidationError, "Conflicting 'one_of' operators: no intersection between #{existing_one_of} and #{new_one_of}"
            end
            merged["one_of"] = intersection.empty? ? new_one_of : intersection

          when "subset_of"
            # subset_of operator: intersection of values
            existing_subset = merged["subset_of"] || []
            new_subset = value.is_a?(Array) ? value : [value]
            intersection = existing_subset & new_subset
            merged["subset_of"] = intersection.empty? ? new_subset : intersection

          when "default"
            # default operator: values must be equal
            if merged["default"] && merged["default"] != value
              raise ValidationError, "Conflicting 'default' operators in metadata policy: #{merged["default"]} vs #{value}"
            end
            merged["default"] = value

          when "superset_of", "essential"
            # These operators are preserved as-is (validation only, no merging needed)
            merged[operator_str] = value

          else
            # Unknown operator - preserve it
            OmniauthOpenidFederation::Logger.warn("[MetadataPolicyMerger] Unknown operator: #{operator_str}")
            merged[operator_str] = value
          end
        end

        merged
      end

      def apply_parameter_policy(metadata, param_name, policy)
        param_value = metadata[param_name.to_sym] || metadata[param_name.to_s]

        # Apply operators in order: value -> add -> default -> one_of/subset_of/superset_of
        if policy.key?("value")
          # value operator: set to specific value (or remove if null)
          if policy["value"].nil?
            metadata.delete(param_name.to_sym)
            metadata.delete(param_name.to_s)
            param_value = nil
          else
            metadata[param_name.to_sym] = policy["value"]
            param_value = policy["value"]
          end
        end

        if policy["add"] && param_value.is_a?(Array)
          # add operator: add values to array
          add_values = policy["add"]
          param_value = (param_value + add_values).uniq
          metadata[param_name.to_sym] = param_value
        end

        if policy["default"] && (param_value.nil? || (param_value.is_a?(Array) && param_value.empty?))
          # default operator: set default if absent
          metadata[param_name.to_sym] = policy["default"]
          param_value = policy["default"]
        end

        # Validation operators (check but don't modify)
        if policy["one_of"] && param_value
          unless policy["one_of"].include?(param_value)
            raise ValidationError, "Metadata parameter '#{param_name}' value '#{param_value}' is not in one_of list: #{policy["one_of"]}"
          end
        end

        if policy["subset_of"] && param_value.is_a?(Array)
          subset = param_value & policy["subset_of"]
          if subset != param_value
            raise ValidationError, "Metadata parameter '#{param_name}' values are not a subset of allowed values: #{policy["subset_of"]}"
          end
          # subset_of also modifies: set to intersection
          metadata[param_name.to_sym] = subset
        end

        if policy["superset_of"] && param_value.is_a?(Array)
          unless (policy["superset_of"] - param_value).empty?
            raise ValidationError, "Metadata parameter '#{param_name}' does not contain all required values: #{policy["superset_of"]}"
          end
        end

        if policy["essential"] && param_value.nil?
          raise ValidationError, "Metadata parameter '#{param_name}' is marked as essential but is absent"
        end
      end

      def validate_metadata_compliance(effective_metadata, merged_policies)
        merged_policies.each do |entity_type, type_policies|
          entity_type_metadata = effective_metadata[entity_type.to_sym] || effective_metadata[entity_type.to_s] || {}

          type_policies.each do |param_name, param_policy|
            param_value = entity_type_metadata[param_name.to_sym] || entity_type_metadata[param_name.to_s]

            # Final validation checks
            if param_policy["essential"] && param_value.nil?
              raise ValidationError, "Essential metadata parameter '#{param_name}' for entity type '#{entity_type}' is missing"
            end
          end
        end
      end

      def deep_dup(obj)
        case obj
        when Hash
          obj.each_with_object({}) do |(k, v), h|
            h[k] = deep_dup(v)
          end
        when Array
          obj.map { |e| deep_dup(e) }
        else
          obj
        end
      end

      def normalize_keys_to_strings(obj)
        case obj
        when Hash
          obj.each_with_object({}) do |(k, v), h|
            h[k.to_s] = normalize_keys_to_strings(v)
          end
        when Array
          obj.map { |e| normalize_keys_to_strings(e) }
        else
          obj
        end
      end
    end
  end
end

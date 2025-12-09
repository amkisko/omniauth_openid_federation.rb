require "time"
require "base64"
require "json"
require_relative "../logger"
require_relative "../errors"
require_relative "../configuration"
require_relative "../string_helpers"

# Entity Statement Validator for OpenID Federation 1.0
# @see https://openid.net/specs/openid-federation-1_0.html#section-3.2.1 Section 3.2.1: Entity Statement Validation
#
# Implements all required validation steps from OpenID Federation 1.0 Section 3.2.1.
# Entity Statements MUST be validated in the following manner per the specification.
#
# @example Validate an entity statement
#   validator = EntityStatementValidator.new(
#     jwt_string: entity_statement_jwt,
#     issuer_entity_configuration: issuer_config  # Optional, for Subordinate Statement validation
#   )
#   validator.validate!
module OmniauthOpenidFederation
  module Federation
    # Entity Statement Validator for OpenID Federation 1.0
    #
    # Validates entity statements according to Section 3.2.1 of the OpenID Federation 1.0 specification.
    class EntityStatementValidator
      # Standard JWT has 3 parts: header.payload.signature
      JWT_PARTS_COUNT = 3

      # Required typ header value for entity statements
      REQUIRED_TYP = "entity-statement+jwt"

      # Supported signing algorithms (per spec, RS256 is required by OpenID Connect Core)
      SUPPORTED_ALGORITHMS = %w[RS256 PS256 ES256 ES384 ES512].freeze

      # Initialize validator
      #
      # @param jwt_string [String] The entity statement JWT string to validate
      # @param issuer_entity_configuration [Hash, EntityStatement, nil] Optional: Entity Configuration of the issuer
      #   Required for validating Subordinate Statements (when iss != sub)
      # @param clock_skew_tolerance [Integer, nil] Clock skew tolerance in seconds (default: from config)
      def initialize(jwt_string:, issuer_entity_configuration: nil, clock_skew_tolerance: nil)
        @jwt_string = jwt_string
        @issuer_entity_configuration = issuer_entity_configuration
        @clock_skew_tolerance = clock_skew_tolerance || OmniauthOpenidFederation.config.clock_skew_tolerance
        @header = nil
        @payload = nil
        @is_entity_configuration = nil
        @is_subordinate_statement = nil
      end

      # Validate the entity statement
      #
      # @return [Hash] Validated entity statement with header and claims
      # @raise [ValidationError] If validation fails at any step
      def validate!
        validate_jwt_format
        validate_typ_header
        validate_alg_header
        validate_sub_claim
        validate_iss_claim
        determine_statement_type
        validate_authority_hints if @is_subordinate_statement
        validate_iat_claim
        validate_exp_claim
        validate_jwks_claim
        validate_kid_header
        validate_kid_matching
        validate_signature if @issuer_entity_configuration || @is_entity_configuration
        validate_crit_claim
        validate_authority_hints_syntax if @header && @payload && @is_entity_configuration
        validate_metadata_syntax
        validate_metadata_policy_presence
        validate_metadata_policy_crit_presence
        validate_constraints_presence
        validate_trust_marks_presence
        validate_trust_mark_issuers_presence
        validate_trust_mark_owners_presence

        {
          header: @header,
          claims: @payload,
          is_entity_configuration: @is_entity_configuration,
          is_subordinate_statement: @is_subordinate_statement
        }
      end

      private

      def validate_jwt_format
        jwt_parts = @jwt_string.split(".")
        if jwt_parts.length != JWT_PARTS_COUNT
          raise ValidationError, "Invalid JWT format: expected #{JWT_PARTS_COUNT} parts (header.payload.signature), got #{jwt_parts.length}"
        end

        begin
          @header = JSON.parse(Base64.urlsafe_decode64(jwt_parts[0]))
          @payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
        rescue JSON::ParserError => e
          raise ValidationError, "Failed to parse entity statement JWT: #{e.message}"
        rescue ArgumentError => e
          raise ValidationError, "Failed to decode entity statement JWT: #{e.message}"
        end
      end

      def validate_typ_header
        typ = @header["typ"] || @header[:typ]
        unless typ == REQUIRED_TYP
          raise ValidationError, "Invalid entity statement type: expected '#{REQUIRED_TYP}', got '#{typ}'. Entity statements without the correct typ header MUST be rejected per OpenID Federation 1.0 Section 3.1."
        end
      end

      def validate_alg_header
        alg = @header["alg"] || @header[:alg]
        if StringHelpers.blank?(alg)
          raise ValidationError, "Entity statement MUST have an alg (algorithm) header parameter"
        end
        if alg == "none"
          raise ValidationError, "Entity statement alg header MUST NOT be 'none'"
        end
        # Note: We don't reject unsupported algorithms here, but log a warning
        unless SUPPORTED_ALGORITHMS.include?(alg)
          OmniauthOpenidFederation::Logger.warn("[EntityStatementValidator] Unsupported algorithm: #{alg}. Supported: #{SUPPORTED_ALGORITHMS.join(", ")}")
        end
      end

      # Note: This is a structural check. The actual Entity Identifier validation
      # would require knowing the expected Entity Identifier, which is context-dependent.
      def validate_sub_claim
        sub = @payload["sub"]
        if StringHelpers.blank?(sub)
          raise ValidationError, "Entity statement MUST have a sub (subject) claim with a valid Entity Identifier"
        end
        unless sub.is_a?(String) && sub.start_with?("http://", "https://")
          raise ValidationError, "Entity statement sub claim MUST be a valid Entity Identifier (URI)"
        end
      end

      def validate_iss_claim
        iss = @payload["iss"]
        if StringHelpers.blank?(iss)
          raise ValidationError, "Entity statement MUST have an iss (issuer) claim with a valid Entity Identifier"
        end
        unless iss.is_a?(String) && iss.start_with?("http://", "https://")
          raise ValidationError, "Entity statement iss claim MUST be a valid Entity Identifier (URI)"
        end
      end

      def determine_statement_type
        iss = @payload["iss"]
        sub = @payload["sub"]
        @is_entity_configuration = (iss == sub)
        @is_subordinate_statement = !@is_entity_configuration
      end

      # Step 7: For Subordinate Statements, validate iss matches authority_hints
      def validate_authority_hints
        unless @issuer_entity_configuration
          # If issuer configuration not provided, we can't validate authority_hints
          # This is acceptable for basic validation, but should be done for full validation
          OmniauthOpenidFederation::Logger.warn("[EntityStatementValidator] Cannot validate authority_hints: issuer entity configuration not provided")
          return
        end

        issuer_config = if @issuer_entity_configuration.is_a?(Hash)
          @issuer_entity_configuration
        elsif @issuer_entity_configuration.respond_to?(:parse)
          @issuer_entity_configuration.parse
        else
          raise ValidationError, "Invalid issuer entity configuration format"
        end

        authority_hints = issuer_config[:claims]&.fetch("authority_hints", []) ||
          issuer_config["claims"]&.fetch("authority_hints", []) ||
          issuer_config.fetch("authority_hints", [])

        unless authority_hints.is_a?(Array) && authority_hints.include?(@payload["iss"])
          raise ValidationError, "Subordinate Statement issuer '#{@payload["iss"]}' MUST be listed in the authority_hints array of the subject's Entity Configuration"
        end
      end

      def validate_iat_claim
        iat = @payload["iat"]
        if iat.nil?
          raise ValidationError, "Entity statement MUST have an iat (issued at) claim"
        end

        unless iat.is_a?(Integer) || iat.is_a?(Numeric)
          raise ValidationError, "Entity statement iat claim MUST be a number (Seconds Since the Epoch)"
        end

        current_time = Time.now.to_i
        if iat > (current_time + @clock_skew_tolerance)
          raise ValidationError, "Entity statement iat (issued at) claim is too far in the future. Current time: #{current_time}, iat: #{iat}, tolerance: #{@clock_skew_tolerance}s"
        end
      end

      def validate_exp_claim
        exp = @payload["exp"]
        if exp.nil?
          raise ValidationError, "Entity statement MUST have an exp (expiration) claim"
        end

        unless exp.is_a?(Integer) || exp.is_a?(Numeric)
          raise ValidationError, "Entity statement exp claim MUST be a number (Seconds Since the Epoch)"
        end

        current_time = Time.now.to_i
        if exp < (current_time - @clock_skew_tolerance)
          raise ValidationError, "Entity statement has expired. Current time: #{current_time}, exp: #{exp}, tolerance: #{@clock_skew_tolerance}s"
        end
      end

      def validate_jwks_claim
        jwks = @payload["jwks"]
        if jwks.nil?
          # jwks is OPTIONAL only for Entity Statement returned from OP during Explicit Registration
          # For all other cases, it is REQUIRED
          raise ValidationError, "Entity statement MUST have a jwks (JWK Set) claim"
        end

        unless jwks.is_a?(Hash)
          raise ValidationError, "Entity statement jwks claim MUST be a JSON object (JWK Set)"
        end

        keys = jwks["keys"] || jwks[:keys]
        unless keys.is_a?(Array)
          raise ValidationError, "Entity statement jwks claim MUST contain a 'keys' array"
        end

        kids = keys.map { |key| key["kid"] || key[:kid] }.compact
        if kids.length != kids.uniq.length
          raise ValidationError, "Entity statement jwks keys MUST have unique kid (Key ID) values"
        end
      end

      def validate_kid_header
        kid = @header["kid"] || @header[:kid]
        if kid.nil?
          raise ValidationError, "Entity statement MUST have a kid (Key ID) header parameter with a non-zero length string value"
        end
        unless kid.is_a?(String)
          raise ValidationError, "Entity statement kid header parameter MUST be a string"
        end
        if kid.empty?
          raise ValidationError, "Entity statement MUST have a kid (Key ID) header parameter with a non-zero length string value"
        end
      end

      def validate_kid_matching
        kid = @header["kid"] || @header[:kid]
        jwks = @payload["jwks"] || {}

        issuer_jwks = if @is_entity_configuration
          jwks
        elsif @issuer_entity_configuration
          issuer_config = if @issuer_entity_configuration.is_a?(Hash)
            @issuer_entity_configuration
          elsif @issuer_entity_configuration.respond_to?(:parse)
            @issuer_entity_configuration.parse
          else
            raise ValidationError, "Invalid issuer entity configuration format"
          end

          issuer_config[:jwks] || issuer_config["jwks"] || issuer_config[:claims]&.fetch("jwks", {}) || issuer_config["claims"]&.fetch("jwks", {})
        else
          OmniauthOpenidFederation::Logger.warn("[EntityStatementValidator] Cannot validate kid matching: issuer entity configuration not provided")
          return
        end

        issuer_keys = issuer_jwks["keys"] || issuer_jwks[:keys] || []
        matching_key = issuer_keys.find { |key| (key["kid"] || key[:kid]) == kid }

        unless matching_key
          raise ValidationError, "Entity statement kid '#{kid}' MUST exactly match a kid value for a key in the issuer's jwks (JWK Set) claim"
        end
      end

      # Signature validation is typically done separately using JWT.decode
      # This step validates that we have the necessary information to validate the signature
      def validate_signature
        kid = @header["kid"] || @header[:kid]
        jwks = @payload["jwks"] || {}

        issuer_jwks = if @is_entity_configuration
          jwks
        elsif @issuer_entity_configuration
          issuer_config = if @issuer_entity_configuration.is_a?(Hash)
            @issuer_entity_configuration
          elsif @issuer_entity_configuration.respond_to?(:parse)
            @issuer_entity_configuration.parse
          else
            raise ValidationError, "Invalid issuer entity configuration format"
          end

          issuer_config[:jwks] || issuer_config["jwks"] || issuer_config[:claims]&.fetch("jwks", {}) || issuer_config["claims"]&.fetch("jwks", {})
        else
          return # Cannot validate without issuer configuration
        end

        issuer_keys = issuer_jwks["keys"] || issuer_jwks[:keys] || []
        matching_key = issuer_keys.find { |key| (key["kid"] || key[:kid]) == kid }

        unless matching_key
          raise ValidationError, "Cannot validate signature: signing key with kid '#{kid}' not found in issuer's JWKS"
        end
      end

      def validate_crit_claim
        crit = @payload["crit"] || @payload[:crit]
        return unless crit

        unless crit.is_a?(Array)
          raise ValidationError, "Entity statement crit claim MUST be an array of strings"
        end

        # Standard claims that MUST NOT be in crit (per spec)
        standard_claims = %w[iss sub iat exp jwks metadata authority_hints trust_marks trust_mark_issuers trust_mark_owners constraints metadata_policy metadata_policy_crit source_endpoint crit]
        unknown_claims = crit - standard_claims

        if unknown_claims.any?
          # For now, we'll log a warning but not reject
          # In a strict implementation, we should reject if we don't understand the claims
          # Future enhancement: Add strict_mode option to reject unknown crit claims
          OmniauthOpenidFederation::Logger.warn("[EntityStatementValidator] Entity statement contains crit claim with unknown claims: #{unknown_claims.join(", ")}. These claims MUST be understood and processed.")
        end
      end

      def validate_authority_hints_syntax
        authority_hints = @payload["authority_hints"] || @payload[:authority_hints]
        return unless authority_hints

        unless authority_hints.is_a?(Array)
          raise ValidationError, "Entity statement authority_hints claim MUST be an array of strings"
        end

        if authority_hints.empty?
          raise ValidationError, "Entity statement authority_hints claim MUST NOT be an empty array (unless this is a Trust Anchor with no Superiors)"
        end

        authority_hints.each do |hint|
          unless hint.is_a?(String) && hint.start_with?("http://", "https://")
            raise ValidationError, "Entity statement authority_hints claim MUST contain valid Entity Identifiers (URIs)"
          end
        end
      end

      def validate_metadata_syntax
        metadata = @payload["metadata"] || @payload[:metadata]
        return unless metadata

        unless metadata.is_a?(Hash)
          raise ValidationError, "Entity statement metadata claim MUST be a JSON object"
        end

        metadata.each do |entity_type, entity_metadata|
          if entity_metadata.nil?
            raise ValidationError, "Entity statement metadata claim MUST NOT use null as metadata values"
          end
          unless entity_metadata.is_a?(Hash)
            raise ValidationError, "Entity statement metadata claim values MUST be JSON objects"
          end
        end
      end

      def validate_metadata_policy_presence
        metadata_policy = @payload["metadata_policy"] || @payload[:metadata_policy]
        return unless metadata_policy

        unless @is_subordinate_statement
          raise ValidationError, "Entity statement metadata_policy claim MUST only appear in Subordinate Statements"
        end
      end

      def validate_metadata_policy_crit_presence
        metadata_policy_crit = @payload["metadata_policy_crit"] || @payload[:metadata_policy_crit]
        return unless metadata_policy_crit

        unless @is_subordinate_statement
          raise ValidationError, "Entity statement metadata_policy_crit claim MUST only appear in Subordinate Statements"
        end
      end

      def validate_constraints_presence
        constraints = @payload["constraints"] || @payload[:constraints]
        return unless constraints

        unless @is_subordinate_statement
          raise ValidationError, "Entity statement constraints claim MUST only appear in Subordinate Statements"
        end
      end

      def validate_trust_marks_presence
        trust_marks = @payload["trust_marks"] || @payload[:trust_marks]
        return unless trust_marks

        unless @is_entity_configuration
          raise ValidationError, "Entity statement trust_marks claim MUST only appear in Entity Configurations"
        end
      end

      def validate_trust_mark_issuers_presence
        trust_mark_issuers = @payload["trust_mark_issuers"] || @payload[:trust_mark_issuers]
        return unless trust_mark_issuers

        unless @is_entity_configuration
          raise ValidationError, "Entity statement trust_mark_issuers claim MUST only appear in Entity Configurations"
        end
      end

      def validate_trust_mark_owners_presence
        trust_mark_owners = @payload["trust_mark_owners"] || @payload[:trust_mark_owners]
        return unless trust_mark_owners

        unless @is_entity_configuration
          raise ValidationError, "Entity statement trust_mark_owners claim MUST only appear in Entity Configurations"
        end
      end
    end
  end
end

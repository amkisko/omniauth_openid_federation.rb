require_relative "entity_statement"
require_relative "entity_statement_validator"
require_relative "../http_client"
require_relative "../logger"
require_relative "../errors"
require_relative "../utils"
require_relative "../string_helpers"
require "cgi"

# Trust Chain Resolver for OpenID Federation 1.0
# @see https://openid.net/specs/openid-federation-1_0.html#section-10 Section 10: Trust Chain Resolution
#
# Resolves trust chains from a Leaf Entity up to a Trust Anchor by:
# 1. Fetching the Leaf Entity's Entity Configuration
# 2. Following authority_hints to fetch Subordinate Statements
# 3. Validating each statement in the chain
# 4. Continuing until a Trust Anchor is reached
#
# @example Resolve a trust chain
#   resolver = TrustChainResolver.new(
#     leaf_entity_id: "https://rp.example.com",
#     trust_anchors: [
#       {
#         entity_id: "https://ta.example.com",
#         jwks: trust_anchor_jwks
#       }
#     ]
#   )
#   trust_chain = resolver.resolve!
module OmniauthOpenidFederation
  module Federation
    # Trust Chain Resolver for OpenID Federation 1.0
    #
    # Resolves and validates trust chains from a Leaf Entity to a Trust Anchor.
    class TrustChainResolver
      # Initialize resolver
      #
      # @param leaf_entity_id [String] Entity Identifier of the Leaf Entity
      # @param trust_anchors [Array<Hash>] Array of Trust Anchor configurations
      #   Each hash must have:
      #   - :entity_id or "entity_id" - Trust Anchor Entity Identifier
      #   - :jwks or "jwks" - Trust Anchor JWKS for validation
      # @param max_chain_length [Integer] Maximum chain length to prevent infinite loops (default: 10)
      # @param timeout [Integer] HTTP request timeout in seconds (default: 10)
      def initialize(leaf_entity_id:, trust_anchors:, max_chain_length: 10, timeout: 10)
        @leaf_entity_id = leaf_entity_id
        @trust_anchors = normalize_trust_anchors(trust_anchors)
        @max_chain_length = max_chain_length
        @timeout = timeout
        @resolved_statements = []
        @visited_entities = Set.new
      end

      # Resolve the trust chain
      #
      # @return [Array<Hash>] Array of validated entity statements in order (Leaf to Trust Anchor)
      # @raise [ValidationError] If trust chain resolution fails
      # @raise [FetchError] If fetching entity statements fails
      def resolve!
        OmniauthOpenidFederation::Logger.debug("[TrustChainResolver] Starting trust chain resolution for: #{@leaf_entity_id}")

        leaf_config = fetch_entity_configuration(@leaf_entity_id)
        validate_entity_statement(leaf_config, nil)
        @resolved_statements << leaf_config
        @visited_entities.add(@leaf_entity_id)

        current_entity_id = @leaf_entity_id
        current_config = leaf_config

        while current_config && !is_trust_anchor?(current_config)
          authority_hints = extract_authority_hints(current_config)

          if StringHelpers.blank?(authority_hints)
            raise ValidationError, "Entity #{current_entity_id} has no authority_hints and is not a Trust Anchor"
          end

          found_next = false
          authority_hints.each do |authority_id|
            next if @visited_entities.include?(authority_id)

            if @resolved_statements.length >= @max_chain_length
              raise ValidationError, "Trust chain length exceeds maximum (#{@max_chain_length})"
            end

            begin
              subordinate_statement = fetch_subordinate_statement(
                issuer: authority_id,
                subject: current_entity_id
              )

              issuer_config = fetch_entity_configuration(authority_id)
              validate_entity_statement(subordinate_statement, issuer_config)

              @resolved_statements << subordinate_statement
              @visited_entities.add(authority_id)

              current_entity_id = authority_id
              current_config = issuer_config
              found_next = true
              break
            rescue ValidationError, FetchError => e
              OmniauthOpenidFederation::Logger.warn("[TrustChainResolver] Failed to resolve via #{authority_id}: #{e.message}")
              OmniauthOpenidFederation::Instrumentation.notify_trust_chain_validation_failed(
                entity_id: current_entity_id,
                trust_anchor: authority_id,
                validation_step: "subordinate_statement_validation",
                error_message: e.message,
                error_class: e.class.name
              )
              next
            end
          end

          unless found_next
            raise ValidationError, "Could not resolve trust chain from #{current_entity_id}: no valid authority found"
          end
        end

        unless is_trust_anchor?(current_config)
          error_msg = "Trust chain did not terminate at a configured Trust Anchor"
          OmniauthOpenidFederation::Instrumentation.notify_trust_chain_validation_failed(
            entity_id: @leaf_entity_id,
            trust_anchor: current_entity_id,
            validation_step: "trust_anchor_verification",
            error_message: error_msg
          )
          raise ValidationError, error_msg
        end

        OmniauthOpenidFederation::Logger.debug("[TrustChainResolver] Trust chain resolved: #{@resolved_statements.length} statements")
        @resolved_statements
      end

      private

      def normalize_trust_anchors(trust_anchors)
        trust_anchors.map do |ta|
          {
            entity_id: ta[:entity_id] || ta["entity_id"],
            jwks: ta[:jwks] || ta["jwks"]
          }
        end
      end

      def fetch_entity_configuration(entity_id)
        entity_statement_url = OmniauthOpenidFederation::Utils.build_entity_statement_url(entity_id)
        OmniauthOpenidFederation::Logger.debug("[TrustChainResolver] Fetching Entity Configuration from: #{entity_statement_url}")

        begin
          EntityStatement.fetch!(entity_statement_url, timeout: @timeout)
        rescue OmniauthOpenidFederation::NetworkError => e
          raise FetchError, "Failed to fetch entity configuration from #{entity_statement_url}: #{e.message}"
        end
      end

      def fetch_subordinate_statement(issuer:, subject:)
        issuer_config = fetch_entity_configuration(issuer)
        fetch_endpoint = extract_fetch_endpoint(issuer_config)

        unless fetch_endpoint
          raise FetchError, "Issuer #{issuer} does not provide a fetch endpoint"
        end

        fetch_url = "#{fetch_endpoint}?iss=#{CGI.escape(issuer)}&sub=#{CGI.escape(subject)}"
        OmniauthOpenidFederation::Logger.debug("[TrustChainResolver] Fetching Subordinate Statement from: #{fetch_url}")

        begin
          response = HttpClient.get(fetch_url, timeout: @timeout)
          unless response.status.success?
            raise FetchError, "Failed to fetch subordinate statement from #{fetch_url}: HTTP #{response.status}"
          end

          subordinate_statement_jwt = response.body.to_s
          EntityStatement.new(subordinate_statement_jwt)
        rescue OmniauthOpenidFederation::NetworkError => e
          raise FetchError, "Failed to fetch subordinate statement from #{fetch_url}: #{e.message}"
        end
      end

      def extract_fetch_endpoint(entity_config)
        # Fetch endpoint is typically at /.well-known/openid-federation/fetch
        # or can be specified in metadata
        parsed = entity_config.parse
        issuer = parsed[:issuer] || parsed[:iss] || parsed["issuer"] || parsed["iss"]
        return nil unless issuer

        "#{issuer}/.well-known/openid-federation/fetch"
      end

      def extract_authority_hints(entity_config)
        parsed = entity_config.parse
        parsed[:authority_hints] || parsed["authority_hints"]
      end

      def validate_entity_statement(statement, issuer_config)
        validator = EntityStatementValidator.new(
          jwt_string: statement.entity_statement,
          issuer_entity_configuration: issuer_config
        )
        validator.validate!
      end

      def is_trust_anchor?(entity_config)
        parsed = entity_config.parse
        entity_id = parsed[:issuer] || parsed[:iss] || parsed["issuer"] || parsed["iss"]

        @trust_anchors.any? do |ta|
          ta[:entity_id] == entity_id
        end
      end
    end
  end
end

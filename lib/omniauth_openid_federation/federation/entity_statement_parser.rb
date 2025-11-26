require "jwt"
require "base64"
require_relative "../key_extractor"
require_relative "../logger"
require_relative "../errors"
require_relative "entity_statement_validator"

# Entity Statement Parser for OpenID Federation 1.0
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
# @see https://openid.net/specs/openid-federation-1_0.html#section-3 Section 3: Entity Statement
#
# Parses entity statement JWTs and extracts:
# - Header information (algorithm, key ID)
# - Claims (issuer, subject, expiration, issued at)
# - JWKS for signature validation
# - Provider metadata (endpoints, configuration)
#
# Supports optional signature validation using keys from the entity statement's own JWKS
# (self-signed entity statements).
module OmniauthOpenidFederation
  module Federation
    # Entity Statement Parser for OpenID Federation 1.0
    #
    # @example Parse an entity statement
    #   parser = EntityStatementParser.new(jwt_string, validate_signature: true)
    #   metadata = parser.parse
    class EntityStatementParser
      # Compatibility alias for backward compatibility
      ParseError = OmniauthOpenidFederation::ValidationError
      # Standard JWT has 3 parts: header.payload.signature
      JWT_PARTS_COUNT = 3

      # Parse entity statement JWT
      #
      # @param jwt_string [String] The JWT string to parse
      # @param validate_signature [Boolean] Whether to validate the signature (default: false)
      # @param validate_full [Boolean] Whether to perform full OpenID Federation validation (default: true)
      # @param issuer_entity_configuration [Hash, EntityStatement, nil] Optional: Issuer's Entity Configuration for Subordinate Statement validation
      # @return [Hash] Parsed entity statement with header, claims, and metadata
      # @raise [ParseError] If parsing fails
      def self.parse(jwt_string, validate_signature: false, validate_full: true, issuer_entity_configuration: nil)
        new(jwt_string, validate_signature: validate_signature, validate_full: validate_full, issuer_entity_configuration: issuer_entity_configuration).parse
      end

      # Initialize parser
      #
      # @param jwt_string [String] The JWT string to parse
      # @param validate_signature [Boolean] Whether to validate the signature
      # @param validate_full [Boolean] Whether to perform full OpenID Federation validation
      # @param issuer_entity_configuration [Hash, EntityStatement, nil] Optional: Issuer's Entity Configuration
      def initialize(jwt_string, validate_signature: false, validate_full: true, issuer_entity_configuration: nil)
        @jwt_string = jwt_string
        @validate_signature = validate_signature
        @validate_full = validate_full
        @issuer_entity_configuration = issuer_entity_configuration
      end

      # Parse the entity statement
      #
      # @return [Hash] Parsed entity statement with header, claims, and metadata
      # @raise [ParseError] If parsing fails
      def parse
        # Perform full OpenID Federation validation if requested
        if @validate_full
          validator = EntityStatementValidator.new(
            jwt_string: @jwt_string,
            issuer_entity_configuration: @issuer_entity_configuration
          )
          validated = validator.validate!
          @header = validated[:header]
          @payload = validated[:claims]
        else
          # Basic parsing without full validation (for backward compatibility)
          jwt_parts = @jwt_string.split(".")
          raise ParseError, "Invalid JWT format: expected #{JWT_PARTS_COUNT} parts, got #{jwt_parts.length}" if jwt_parts.length != JWT_PARTS_COUNT

          # Decode header
          @header = JSON.parse(Base64.urlsafe_decode64(jwt_parts[0]))

          # Validate typ header per OpenID Federation 1.0 Section 3.1 and 3.2.1
          # Entity Statement JWTs MUST have typ: "entity-statement+jwt"
          typ = @header["typ"] || @header[:typ]
          unless typ == "entity-statement+jwt"
            raise ValidationError, "Invalid entity statement type: expected 'entity-statement+jwt', got '#{typ}'. Entity statements without the correct typ header MUST be rejected per OpenID Federation 1.0 Section 3.1."
          end

          # Decode payload
          @payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
        end

        header = @header
        payload = @payload

        # Extract JWKS from entity statement for signature validation
        entity_jwks = payload.fetch("jwks", {}).fetch("keys", [])

        if @validate_signature && entity_jwks.any?
          # For signature validation, we need the JWT parts
          jwt_parts = @jwt_string.split(".")
          validate_signature(jwt_parts, entity_jwks, header)
        end

        # Extract metadata for all entity types
        metadata_section = payload.fetch("metadata", {})
        provider_metadata = metadata_section.fetch("openid_provider", {})
        rp_metadata = metadata_section.fetch("openid_relying_party", {})

        result = {
          header: header,
          claims: payload,
          issuer: payload["iss"],
          sub: payload["sub"],
          exp: payload["exp"],
          iat: payload["iat"],
          jwks: payload.fetch("jwks", {}),
          metadata: {},
          # Advanced claims (Entity Configuration specific)
          authority_hints: payload["authority_hints"] || payload[:authority_hints],
          trust_marks: payload["trust_marks"] || payload[:trust_marks],
          trust_mark_issuers: payload["trust_mark_issuers"] || payload[:trust_mark_issuers],
          trust_mark_owners: payload["trust_mark_owners"] || payload[:trust_mark_owners],
          # Advanced claims (Subordinate Statement specific)
          metadata_policy: payload["metadata_policy"] || payload[:metadata_policy],
          metadata_policy_crit: payload["metadata_policy_crit"] || payload[:metadata_policy_crit],
          constraints: payload["constraints"] || payload[:constraints],
          source_endpoint: payload["source_endpoint"] || payload[:source_endpoint],
          # Other claims
          crit: payload["crit"] || payload[:crit],
          # Determine statement type
          is_entity_configuration: (payload["iss"] == payload["sub"]),
          is_subordinate_statement: (payload["iss"] != payload["sub"])
        }

        # Extract OpenID Provider metadata if present
        if provider_metadata.any?
          result[:metadata][:openid_provider] = {
            issuer: provider_metadata["issuer"],
            authorization_endpoint: provider_metadata["authorization_endpoint"],
            token_endpoint: provider_metadata["token_endpoint"],
            userinfo_endpoint: provider_metadata["userinfo_endpoint"],
            jwks_uri: provider_metadata["jwks_uri"],
            signed_jwks_uri: provider_metadata["signed_jwks_uri"],
            end_session_endpoint: provider_metadata["end_session_endpoint"],
            client_registration_types_supported: provider_metadata["client_registration_types_supported"],
            federation_registration_endpoint: provider_metadata["federation_registration_endpoint"]
          }
        end

        # Extract OpenID Relying Party metadata if present
        if rp_metadata.any?
          result[:metadata][:openid_relying_party] = {
            application_type: rp_metadata["application_type"],
            redirect_uris: rp_metadata["redirect_uris"],
            client_registration_types: rp_metadata["client_registration_types"],
            signed_jwks_uri: rp_metadata["signed_jwks_uri"],
            jwks_uri: rp_metadata["jwks_uri"],
            organization_name: rp_metadata["organization_name"],
            logo_uri: rp_metadata["logo_uri"],
            grant_types: rp_metadata["grant_types"],
            response_types: rp_metadata["response_types"],
            scope: rp_metadata["scope"]
          }
        end

        result
      rescue JSON::ParserError => e
        raise ValidationError, "Failed to parse entity statement: #{e.message}"
      rescue ArgumentError => e
        raise ValidationError, "Failed to decode entity statement: #{e.message}"
      end

      private

      def validate_signature(jwt_parts, entity_jwks, header)
        # Find the key used for signing
        kid = header["kid"]
        signing_key_data = entity_jwks.find { |key| key["kid"] == kid }

        unless signing_key_data
          raise ValidationError, "Signing key with kid '#{kid}' not found in entity statement JWKS"
        end

        # Convert JWK to OpenSSL key
        public_key = OmniauthOpenidFederation::KeyExtractor.jwk_to_openssl_key(signing_key_data)

        # Verify signature using the full JWT string
        begin
          JWT.decode(@jwt_string, public_key, true, {algorithm: "RS256"})
        # Return decoded payload for validation
        rescue => e
          error_msg = "Entity statement signature validation failed for kid '#{kid}': #{e.class} - #{e.message}"
          OmniauthOpenidFederation::Logger.error("[EntityStatementParser] #{error_msg}")
          raise SignatureError, error_msg, e.backtrace
        end
      end
    end
  end
end

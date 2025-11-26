require "net/http"
require "digest"
require "jwt"
require "base64"
require "openssl"
require "timeout"
require_relative "../key_extractor"
require_relative "../logger"
require_relative "../errors"
require_relative "../configuration"
require_relative "../http_client"
require_relative "../utils"
require_relative "entity_statement_parser"

# Entity Statement implementation for OpenID Federation 1.0
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
# @see https://openid.github.io/federation/main.html OpenID Federation Documentation
#
# Entity Statements are self-signed JWTs that contain provider metadata and JWKS.
# This implementation supports:
# - Fetching entity statements from /.well-known/openid-federation endpoint (Section 9)
# - Fingerprint validation (SHA-256 hash) for integrity verification
# - Previous statement validation for update verification
# - Metadata extraction for OpenID Provider configuration
#
# Note: This implementation handles self-signed entity statements directly.
# Full trust chain resolution (Section 10) is not implemented as it's not required
# for direct entity statement validation use cases.
module OmniauthOpenidFederation
  module Federation
    # Entity Statement implementation for OpenID Federation 1.0
    #
    # @example Fetch and validate an entity statement from full URL
    #   statement = EntityStatement.fetch!(
    #     "https://provider.example.com/.well-known/openid-federation",
    #     fingerprint: "expected-fingerprint-hash"
    #   )
    #   metadata = statement.parse
    #
    # @example Fetch and validate an entity statement from issuer and endpoint
    #   statement = EntityStatement.fetch_from_issuer!(
    #     "https://provider.example.com",
    #     entity_statement_endpoint: "/.well-known/openid-federation",
    #     fingerprint: "expected-fingerprint-hash"
    #   )
    #   metadata = statement.parse
    class EntityStatement
      # Compatibility aliases for backward compatibility
      FetchError = OmniauthOpenidFederation::FetchError
      ValidationError = OmniauthOpenidFederation::ValidationError
      attr_reader :entity_statement, :fingerprint, :metadata

      # Fetch entity statement from URL
      #
      # @param url [String] The URL to fetch the entity statement from
      # @param fingerprint [String, nil] Expected SHA-256 fingerprint for validation
      # @param previous_statement [String, EntityStatement, Hash, nil] Previous statement for validation
      # @param timeout [Integer] HTTP request timeout in seconds (default: 10)
      # @return [EntityStatement] The fetched and validated entity statement
      # @raise [FetchError] If fetching fails
      # @raise [ValidationError] If validation fails

      def initialize(entity_statement_content, fingerprint: nil)
        @entity_statement = entity_statement_content
        @fingerprint = fingerprint || calculate_fingerprint
        @metadata = nil
      end

      # Fetch entity statement from issuer and endpoint path
      #
      # @param issuer_uri [String, URI] Issuer URI (e.g., "https://provider.example.com")
      # @param entity_statement_endpoint [String, nil] Entity statement endpoint path (defaults to "/.well-known/openid-federation")
      # @param fingerprint [String, nil] Expected SHA-256 fingerprint for validation
      # @param previous_statement [String, EntityStatement, Hash, nil] Previous statement for validation
      # @param timeout [Integer] HTTP request timeout in seconds (default: 10)
      # @return [EntityStatement] The fetched and validated entity statement
      # @raise [FetchError] If fetching fails
      # @raise [ValidationError] If validation fails
      def self.fetch_from_issuer!(issuer_uri, entity_statement_endpoint: nil, fingerprint: nil, previous_statement: nil, timeout: 10)
        url = OmniauthOpenidFederation::Utils.build_entity_statement_url(
          issuer_uri,
          entity_statement_endpoint: entity_statement_endpoint
        )
        fetch!(url, fingerprint: fingerprint, previous_statement: previous_statement, timeout: timeout)
      end

      # Fetch entity statement from URL
      #
      # @param url [String] The URL to fetch the entity statement from
      # @param fingerprint [String, nil] Expected SHA-256 fingerprint for validation
      # @param previous_statement [String, EntityStatement, Hash, nil] Previous statement for validation
      # @param timeout [Integer] HTTP request timeout in seconds (default: 10)
      # @return [EntityStatement] The fetched and validated entity statement
      # @raise [FetchError] If fetching fails
      # @raise [ValidationError] If validation fails
      def self.fetch!(url, fingerprint: nil, previous_statement: nil, timeout: 10)
        # Use HttpClient for retry logic and configurable SSL verification
        # Note: HttpClient uses HTTP gem, but entity statements might need Net::HTTP
        # For now, we'll use a simple HTTP.get approach with HttpClient's retry logic
        begin
          # Convert URL to URI for HttpClient
          response = HttpClient.get(url, timeout: timeout)
        rescue OmniauthOpenidFederation::NetworkError => e
          OmniauthOpenidFederation::Logger.error("[EntityStatement] Failed to fetch entity statement: #{e.message}")
          raise FetchError, "Failed to fetch entity statement from #{url}: #{e.message}", e.backtrace
        end

        unless response.status.success?
          error_msg = "Failed to fetch entity statement from #{url}: HTTP #{response.status}"
          OmniauthOpenidFederation::Logger.error("[EntityStatement] #{error_msg}")
          raise FetchError, error_msg
        end

        # HTTP gem returns body as StringIO or similar, convert to string
        entity_statement = response.body.to_s

        instance = new(entity_statement, fingerprint: nil) # Don't set fingerprint in constructor

        # Validate using full OpenID Federation validation (includes signature validation)
        # This is required for OpenID Federation compliance
        begin
          EntityStatementParser.parse(entity_statement, validate_signature: true, validate_full: true)
          OmniauthOpenidFederation::Logger.debug("[EntityStatement] Full validation successful")
        rescue SignatureError, ValidationError => e
          error_msg = "Entity statement validation failed: #{e.message}"
          OmniauthOpenidFederation::Logger.error("[EntityStatement] #{error_msg}")
          # Instrument entity statement validation failure
          OmniauthOpenidFederation::Instrumentation.notify_entity_statement_validation_failed(
            entity_statement_url: url,
            validation_step: "full_validation",
            error_message: e.message,
            error_class: e.class.name
          )
          raise ValidationError, error_msg, e.backtrace
        end

        # Validate if fingerprint provided
        if fingerprint
          calculated_fingerprint = instance.calculate_fingerprint
          unless instance.validate_fingerprint(fingerprint)
            error_msg = "Entity statement fingerprint mismatch. Expected: #{fingerprint}, Got: #{calculated_fingerprint}"
            OmniauthOpenidFederation::Logger.error("[EntityStatement] #{error_msg}")
            # Instrument fingerprint mismatch
            OmniauthOpenidFederation::Instrumentation.notify_fingerprint_mismatch(
              entity_statement_url: url,
              expected_fingerprint: fingerprint,
              calculated_fingerprint: calculated_fingerprint
            )
            raise ValidationError, error_msg
          end
          OmniauthOpenidFederation::Logger.debug("[EntityStatement] Fingerprint validation successful: #{fingerprint}")
        end

        # Validate against previous statement if provided
        if previous_statement
          unless instance.validate_against_previous(previous_statement)
            error_msg = "Entity statement validation against previous statement failed"
            OmniauthOpenidFederation::Logger.error("[EntityStatement] #{error_msg}")
            raise ValidationError, error_msg
          end
          OmniauthOpenidFederation::Logger.debug("[EntityStatement] Previous statement validation successful")
        end

        instance
      end

      # Calculate SHA-256 fingerprint of the entity statement
      #
      # @return [String] The lowercase hexadecimal fingerprint
      def calculate_fingerprint
        Digest::SHA256.hexdigest(entity_statement).downcase
      end

      # Validate fingerprint against expected value
      #
      # @param expected_fingerprint [String] The expected fingerprint
      # @return [Boolean] true if fingerprints match
      def validate_fingerprint(expected_fingerprint)
        calculated = fingerprint.downcase
        expected = expected_fingerprint.to_s.downcase
        calculated == expected
      end

      # Validate against a previous entity statement
      #
      # @param previous_statement [String, EntityStatement, Hash] The previous statement to validate against
      # @return [Boolean] true if validation passes
      def validate_against_previous(previous_statement)
        # Decode current statement
        current_payload = decode_payload

        # Handle different input types
        previous_payload = if previous_statement.is_a?(String)
          decode_jwt_payload(previous_statement)
        elsif previous_statement.instance_of?(::OmniauthOpenidFederation::Federation::EntityStatement)
          # If it's an EntityStatement instance, decode its payload
          previous_statement.decode_payload
        else
          previous_statement
        end

        # Check if issuer matches
        return false unless current_payload["iss"] == previous_payload["iss"]

        # Check if this is a valid update (e.g., exp time is later)
        current_exp = current_payload["exp"]
        previous_exp = previous_payload["exp"]

        return false if current_exp && previous_exp && current_exp < previous_exp

        # Additional validation can be added here (e.g., check authority_hints)
        true
      end

      # Parse entity statement and extract metadata
      #
      # @return [Hash] Hash containing issuer, subject, expiration, JWKS, and provider metadata
      def parse
        return @metadata if @metadata

        payload = decode_payload

        # Extract provider metadata
        metadata_section = payload.fetch("metadata", {})
        metadata_section.fetch("openid_provider", {})

        # Extract entity JWKS - ensure it's a hash with keys array
        entity_jwks = payload.fetch("jwks", {})
        # Normalize to ensure it has :keys or "keys" key
        if entity_jwks.nil? || !entity_jwks.is_a?(Hash)
          entity_jwks = {keys: []}
        elsif !entity_jwks.key?(:keys) && !entity_jwks.key?("keys")
          entity_jwks = {keys: []}
        end

        # Extract all entity types from metadata
        metadata_section = payload.fetch("metadata", {})
        provider_metadata = metadata_section.fetch("openid_provider", {})
        rp_metadata = metadata_section.fetch("openid_relying_party", {})

        @metadata = {
          issuer: payload["iss"],
          sub: payload["sub"],
          exp: payload["exp"],
          iat: payload["iat"],
          jwks: entity_jwks,
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
          @metadata[:metadata][:openid_provider] = {
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
          @metadata[:metadata][:openid_relying_party] = {
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

        @metadata
      end

      # Save entity statement to file
      #
      # @param file_path [String] Path to save the entity statement
      def save_to_file(file_path)
        File.write(file_path, entity_statement)
      end

      # Decode and return the JWT payload
      #
      # @return [Hash] The decoded JWT payload
      def decode_payload
        decode_jwt_payload(entity_statement)
      end

      private

      # Standard JWT has 3 parts: header.payload.signature
      JWT_PARTS_COUNT = 3

      def decode_jwt_payload(jwt_string)
        jwt_parts = jwt_string.split(".")
        raise ValidationError, "Invalid JWT format" if jwt_parts.length != JWT_PARTS_COUNT

        # Decode payload (second part)
        JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
      rescue JSON::ParserError => e
        raise ValidationError, "Failed to parse entity statement payload: #{e.message}"
      rescue ArgumentError => e
        raise ValidationError, "Failed to decode entity statement: #{e.message}"
      end
    end
  end
end

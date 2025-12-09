require "jwt"
require "base64"
require "openssl"
require "time"
require_relative "../logger"
require_relative "../errors"
require_relative "../string_helpers"

# Entity Statement Builder for OpenID Federation 1.0
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
#
# Builds self-signed entity statement JWTs that contain provider metadata and JWKS.
# Entity statements are used to publish provider configuration and enable signed JWKS support.
#
# @example Generate an entity statement
#   builder = EntityStatementBuilder.new(
#     issuer: "https://provider.example.com",
#     subject: "https://provider.example.com",
#     private_key: private_key,
#     jwks: jwks_hash,
#     metadata: {
#       openid_provider: {
#         issuer: "https://provider.example.com",
#         authorization_endpoint: "https://provider.example.com/oauth2/authorize",
#         token_endpoint: "https://provider.example.com/oauth2/token",
#         userinfo_endpoint: "https://provider.example.com/oauth2/userinfo",
#         jwks_uri: "https://provider.example.com/.well-known/jwks.json",
#         signed_jwks_uri: "https://provider.example.com/.well-known/signed-jwks.json"
#       }
#     }
#   )
#   entity_statement_jwt = builder.build
module OmniauthOpenidFederation
  module Federation
    # Entity Statement Builder for OpenID Federation 1.0
    #
    # Builds self-signed entity statement JWTs for publishing provider configuration.
    class EntityStatementBuilder
      # @param issuer [String] Entity issuer (typically the provider URL)
      # @param subject [String] Entity subject (typically same as issuer for self-issued statements)
      # @param private_key [OpenSSL::PKey::RSA] Private key for signing the entity statement
      # @param jwks [Hash] JWKS hash with "keys" array containing public keys
      # @param metadata [Hash] Provider metadata hash with openid_provider section
      # @param expiration_seconds [Integer] Expiration time in seconds from now (default: 86400 = 24 hours)
      # @param kid [String, nil] Key ID to use for signing (defaults to first key's kid in JWKS)
      # @param authority_hints [Array<String>, nil] Optional: Array of Entity Identifiers for Immediate Superiors (Entity Configuration only)
      # @param trust_marks [Array<Hash>, nil] Optional: Array of Trust Mark objects (Entity Configuration only)
      # @param trust_mark_issuers [Hash, nil] Optional: Trust Mark issuers configuration (Trust Anchor only)
      # @param trust_mark_owners [Hash, nil] Optional: Trust Mark owners configuration (Trust Anchor only)
      # @param metadata_policy [Hash, nil] Optional: Metadata policy (Subordinate Statement only)
      # @param metadata_policy_crit [Array<String>, nil] Optional: Critical metadata policy operators (Subordinate Statement only)
      # @param constraints [Hash, nil] Optional: Trust Chain constraints (Subordinate Statement only)
      # @param source_endpoint [String, nil] Optional: Fetch endpoint URL (Subordinate Statement only)
      # @param crit [Array<String>, nil] Optional: Critical claims that must be understood
      def initialize(issuer:, subject:, private_key:, jwks:, metadata:, expiration_seconds: 86400, kid: nil,
        authority_hints: nil, trust_marks: nil, trust_mark_issuers: nil, trust_mark_owners: nil,
        metadata_policy: nil, metadata_policy_crit: nil, constraints: nil, source_endpoint: nil, crit: nil)
        @issuer = issuer
        @subject = subject
        @private_key = private_key
        @jwks = normalize_jwks(jwks)
        @metadata = metadata
        @expiration_seconds = expiration_seconds
        @kid = kid || extract_kid_from_jwks(@jwks)
        @authority_hints = authority_hints
        @trust_marks = trust_marks
        @trust_mark_issuers = trust_mark_issuers
        @trust_mark_owners = trust_mark_owners
        @metadata_policy = metadata_policy
        @metadata_policy_crit = metadata_policy_crit
        @constraints = constraints
        @source_endpoint = source_endpoint
        @crit = crit
      end

      # Build and sign the entity statement JWT
      #
      # @return [String] The signed entity statement JWT string
      # @raise [ConfigurationError] If required parameters are missing
      # @raise [SignatureError] If signing fails
      def build
        validate_parameters

        payload = build_payload

        # Per OpenID Federation 1.0 Section 3.1: typ MUST be "entity-statement+jwt"
        header = {
          alg: "RS256",
          typ: "entity-statement+jwt",
          kid: @kid
        }

        begin
          JWT.encode(payload, @private_key, "RS256", header)
        rescue => e
          error_msg = "Failed to sign entity statement: #{e.class} - #{e.message}"
          OmniauthOpenidFederation::Logger.error("[EntityStatementBuilder] #{error_msg}")
          raise SignatureError, error_msg, e.backtrace
        end
      end

      private

      def validate_parameters
        raise ConfigurationError, "Issuer is required" if StringHelpers.blank?(@issuer)
        raise ConfigurationError, "Subject is required" if StringHelpers.blank?(@subject)
        raise ConfigurationError, "Private key is required" if @private_key.nil?
        raise ConfigurationError, "JWKS is required" if StringHelpers.blank?(@jwks)
        raise ConfigurationError, "Metadata is required" if StringHelpers.blank?(@metadata)
        raise ConfigurationError, "JWKS must contain at least one key" if StringHelpers.blank?(@jwks["keys"])
        raise ConfigurationError, "Key ID (kid) is required" if StringHelpers.blank?(@kid)
      end

      def build_payload
        now = Time.now.to_i
        is_entity_configuration = (@issuer == @subject)
        is_subordinate_statement = !is_entity_configuration

        payload = {
          iss: @issuer,
          sub: @subject,
          iat: now,
          exp: now + @expiration_seconds,
          jwks: @jwks,
          metadata: @metadata
        }

        if is_entity_configuration
          payload[:authority_hints] = @authority_hints if @authority_hints
          payload[:trust_marks] = @trust_marks if @trust_marks
          payload[:trust_mark_issuers] = @trust_mark_issuers if @trust_mark_issuers
          payload[:trust_mark_owners] = @trust_mark_owners if @trust_mark_owners
        end

        if is_subordinate_statement
          payload[:metadata_policy] = @metadata_policy if @metadata_policy
          payload[:metadata_policy_crit] = @metadata_policy_crit if @metadata_policy_crit
          payload[:constraints] = @constraints if @constraints
          payload[:source_endpoint] = @source_endpoint if @source_endpoint
        end

        payload[:crit] = @crit if @crit

        payload
      end

      def normalize_jwks(jwks)
        if jwks.is_a?(Hash)
          if jwks.key?(:keys) || jwks.key?("keys")
            keys = jwks[:keys] || jwks["keys"]
            {"keys" => normalize_keys(keys)}
          else
            {"keys" => [jwks]}
          end
        elsif jwks.is_a?(Array)
          {"keys" => normalize_keys(jwks)}
        else
          raise ConfigurationError, "JWKS must be a Hash or Array"
        end
      end

      def normalize_keys(keys)
        keys.map do |key|
          if key.is_a?(Hash)
            key.transform_keys(&:to_s)
          else
            key
          end
        end
      end

      def extract_kid_from_jwks(jwks)
        keys = jwks["keys"] || jwks[:keys] || []
        return nil if keys.empty?

        first_key = keys.first
        first_key["kid"] || first_key[:kid]
      end
    end
  end
end

require "jwt"
require "digest"
require "base64"
require_relative "../logger"
require_relative "../errors"
require_relative "../cache"
require_relative "fetch"

# JWT decoding service with automatic key rotation handling
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
# @see https://openid.net/specs/openid-federation-1_0.html#section-11.1 Section 11.1: Protocol Key Rollover
#
# Decodes and validates JWTs using JWKS from the provider. Implements automatic
# key rotation handling by:
# - Detecting signature verification failures (possible key rotation)
# - Clearing JWKS cache and re-fetching fresh keys
# - Retrying JWT validation with updated keys
#
# This handles provider key rotation automatically without manual intervention.
# Providers will notify before key rotation, and this implementation handles it gracefully.
module OmniauthOpenidFederation
  module Jwks
    class Decode
      # Decode JWT with automatic key rotation handling
      #
      # @param encoded_jwt [String] The JWT to decode
      # @param jwks_uri [String] The JWKS URI for key lookup
      # @param retried [Boolean] Internal flag for retry logic (default: false)
      # @param entity_statement_keys [Hash, Array, nil] Entity statement keys for validation
      # @yield [jwks] Optional block to process JWKS before decoding
      # @yieldparam jwks [Hash] The JWKS hash
      # @return [Object] Result from block or JWKS hash
      # @raise [ValidationError] If JWT validation fails
      # @raise [SignatureError] If signature verification fails after retry
      def self.run(encoded_jwt, jwks_uri, retried: false, entity_statement_keys: nil, &block)
        # Fetch JWKS
        jwks = OmniauthOpenidFederation::Jwks::Fetch.run(jwks_uri, entity_statement_keys: entity_statement_keys)

        begin
          # Try to decode
          if block_given?
            yield(jwks)
          else
            jwks
          end
        rescue JWT::ExpiredSignature, JWT::InvalidJtiError, JWT::InvalidIatError, JWT::InvalidAudError, JWT::InvalidIssuerError => e
          # These are JWT validation errors that shouldn't trigger retry
          # They indicate the token itself is invalid (expired, wrong audience, etc.), not that the keys are wrong
          OmniauthOpenidFederation::Logger.error("[Jwks::Decode] JWT validation failed: #{e.class} - #{e.message}")
          raise ValidationError, e.message, e.backtrace
        rescue JWT::DecodeError => e
          # JWT::DecodeError can be either:
          # - Format errors (invalid JWT structure) - shouldn't retry
          # - Verification errors (signature mismatch) - should retry (might be key rotation)
          # - Key not found errors (kid not found) - should raise ValidationError
          if e.message.include?("Could not find public key for kid") || e.message.include?("Key with kid")
            # Key not found error - might indicate key rotation, so clear cache and retry once
            if retried
              # Already retried, raise ValidationError
              error_msg = "Key with kid not found in JWKS after cache refresh: #{e.message}"
              OmniauthOpenidFederation::Logger.error("[Jwks::Decode] #{error_msg}")
              raise ValidationError, error_msg, e.backtrace
            else
              # First attempt - clear cache and retry (might be key rotation)
              OmniauthOpenidFederation::Logger.warn("[Jwks::Decode] Key with kid not found (clearing cache and retrying - possible key rotation): #{e.message}")
              # Instrument key rotation detection
              OmniauthOpenidFederation::Instrumentation.notify_key_rotation_detected(
                jwks_uri: jwks_uri,
                error_message: e.message,
                error_class: e.class.name,
                reason: "kid_not_found"
              )
              OmniauthOpenidFederation::Cache.delete_jwks(jwks_uri)
              run(encoded_jwt, jwks_uri, retried: true, entity_statement_keys: entity_statement_keys, &block)
            end
          elsif e.is_a?(JWT::VerificationError) || e.message.include?("verification") || e.message.include?("signature")
            # Verification error - might be key rotation, so retry
            if retried
              error_msg = "JWT signature verification failed after cache refresh (possible key rotation issue): #{e.class} - #{e.message}"
              OmniauthOpenidFederation::Logger.error("[Jwks::Decode] #{error_msg}")
              # Instrument signature verification failure after retry
              OmniauthOpenidFederation::Instrumentation.notify_signature_verification_failed(
                token_type: "jwt",
                jwks_uri: jwks_uri,
                error_message: e.message,
                error_class: e.class.name,
                retried: true
              )
              raise SignatureError, error_msg, e.backtrace
            else
              OmniauthOpenidFederation::Logger.warn("[Jwks::Decode] JWT signature verification failed (clearing cache and retrying - possible key rotation): #{e.class} - #{e.message}")
              # Instrument key rotation detection
              OmniauthOpenidFederation::Instrumentation.notify_key_rotation_detected(
                jwks_uri: jwks_uri,
                error_message: e.message,
                error_class: e.class.name
              )
              OmniauthOpenidFederation::Cache.delete_jwks(jwks_uri)
              run(encoded_jwt, jwks_uri, retried: true, entity_statement_keys: entity_statement_keys, &block)
            end
          else
            # Format error - don't retry
            error_msg = "JWT format error: #{e.class} - #{e.message}"
            OmniauthOpenidFederation::Logger.error("[Jwks::Decode] #{error_msg}")
            raise ValidationError, error_msg, e.backtrace
          end
        rescue ArgumentError => e
          # Argument errors from invalid JWT format
          if e.message.include?("Invalid")
            error_msg = "JWT decode failed due to invalid format: #{e.class} - #{e.message}"
            OmniauthOpenidFederation::Logger.error("[Jwks::Decode] #{error_msg}")
            raise ValidationError, error_msg, e.backtrace
          else
            raise e
          end
        rescue => e
          # Other errors might be due to key rotation
          if retried
            # If already re-tried to fetch, raise error
            error_msg = "JWT decode failed after cache refresh: #{e.class} - #{e.message}"
            OmniauthOpenidFederation::Logger.error("[Jwks::Decode] #{error_msg}")
            raise ValidationError, error_msg, e.backtrace
          else
            OmniauthOpenidFederation::Logger.warn("[Jwks::Decode] JWT decode error (clearing cache and retrying - possible key rotation): #{e.class} - #{e.message}")
            # Reset cache to force re-fetching of keys
            OmniauthOpenidFederation::Cache.delete_jwks(jwks_uri)
            run(encoded_jwt, jwks_uri, retried: true, entity_statement_keys: entity_statement_keys, &block)
          end
        end
      end

      # Decode JWT using JWT gem
      #
      # @param encoded_jwt [String] The JWT to decode
      # @param jwks_uri [String] The JWKS URI for key lookup
      # @param retried [Boolean] Internal flag for retry logic (default: false)
      # @param entity_statement_keys [Hash, Array, nil] Entity statement keys for validation
      # @return [Array<Hash>] Array with [payload, header]
      # @raise [ValidationError] If JWT validation fails
      # @raise [SignatureError] If signature verification fails
      def self.jwt(encoded_jwt, jwks_uri, retried: false, entity_statement_keys: nil)
        run(encoded_jwt, jwks_uri, retried: retried, entity_statement_keys: entity_statement_keys) do |jwks|
          # jwks should be a HashWithIndifferentAccess with "keys" array
          jwks_for_decode = if jwks.is_a?(Hash) && jwks.key?("keys")
            jwks
          else
            {keys: jwks}
          end

          ::JWT.decode(
            encoded_jwt,
            nil,
            true,
            {algorithms: ["RS256"], jwks: jwks_for_decode}
          )
        end
      end
    end
  end
end

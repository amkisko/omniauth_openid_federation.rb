require "http"
require "jwt"
require "base64"
require "openssl"
require "digest"
require "json"
require_relative "../key_extractor"
require_relative "../logger"
require_relative "../errors"
require_relative "../http_client"
require_relative "../validators"
require_relative "../cache"
require_relative "../cache_adapter"
require_relative "../utils"
require_relative "../constants"
require_relative "../rate_limiter"
require_relative "../jwks/normalizer"

# Signed JWKS implementation for OpenID Federation 1.0
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
# @see https://openid.net/specs/openid-federation-1_0.html#section-5.2.1.1 Section 5.2.1.1: Usage of jwks, jwks_uri, and signed_jwks_uri
#
# Signed JWKS are JWTs containing a JWKS (JSON Web Key Set) that are signed using
# keys from the entity statement. This provides secure key rotation/updates as
# required by OpenID Federation 1.0 specification.
#
# The signed_jwks_uri endpoint returns a JWT that:
# - Contains the provider's current JWKS in the payload
# - Is signed using a key from the entity statement's JWKS
# - Can be validated to ensure keys haven't been tampered with
#
# This implementation:
# - Fetches signed JWKS from the signed_jwks_uri endpoint
# - Validates the signature using entity statement JWKS
# - Caches the result for performance
# - Handles errors gracefully with fallback to standard JWKS
module OmniauthOpenidFederation
  module Federation
    # Signed JWKS implementation for OpenID Federation 1.0
    #
    # @example Fetch and validate signed JWKS
    #   signed_jwks = SignedJWKS.fetch!(
    #     "https://provider.example.com/.well-known/signed-jwks",
    #     entity_jwks
    #   )
    class SignedJWKS
      # Compatibility aliases for backward compatibility
      FetchError = OmniauthOpenidFederation::FetchError
      ValidationError = OmniauthOpenidFederation::ValidationError

      # Fetch and validate signed JWKS
      #
      # @param signed_jwks_uri [String] The URI to fetch signed JWKS from
      # @param entity_jwks [Hash, Array] Entity statement JWKS for validation
      # @param cache_key [String, nil] Custom cache key (default: auto-generated)
      # @param cache_ttl [Integer, nil] Cache TTL in seconds (default: from configuration)
      #   - nil: Use configuration default (manual rotation if not set, or configured TTL)
      #   - positive integer: Cache expires after this many seconds
      # @param force_refresh [Boolean] Force refresh even if cached (default: false)
      # @return [Hash] The validated JWKS hash
      # @raise [FetchError] If fetching fails
      # @raise [ValidationError] If validation fails
      def self.fetch!(signed_jwks_uri, entity_jwks, cache_key: nil, cache_ttl: nil, force_refresh: false)
        cache_key ||= OmniauthOpenidFederation::Cache.key_for_signed_jwks(signed_jwks_uri)
        config = OmniauthOpenidFederation::Configuration.config
        cache_ttl ||= config.cache_ttl
        rotate_on_errors = config.rotate_on_errors

        # Use cache adapter if available, otherwise fetch directly
        if CacheAdapter.available?
          if force_refresh
            # Force refresh: clear cache and fetch fresh
            CacheAdapter.delete(cache_key)
          end

          if cache_ttl.nil?
            # Manual rotation: cache forever, only rotate on errors if rotate_on_errors is enabled
            begin
              CacheAdapter.fetch(cache_key, expires_in: nil) do
                new(signed_jwks_uri, entity_jwks).fetch_and_validate
              end
            rescue KeyRelatedError, KeyRelatedValidationError => e
              # Rotate on key-related errors if configured
              if rotate_on_errors
                OmniauthOpenidFederation::Logger.warn("[SignedJWKS] Key-related error detected, rotating cache: #{e.message}")
                CacheAdapter.delete(cache_key)
                new(signed_jwks_uri, entity_jwks).fetch_and_validate
              else
                raise
              end
            end
          else
            # TTL-based cache: expires after cache_ttl seconds
            # Rotate on errors if configured
            begin
              CacheAdapter.fetch(cache_key, expires_in: cache_ttl) do
                new(signed_jwks_uri, entity_jwks).fetch_and_validate
              end
            rescue KeyRelatedError, KeyRelatedValidationError => e
              # Rotate on key-related errors if configured
              if rotate_on_errors
                OmniauthOpenidFederation::Logger.warn("[SignedJWKS] Key-related error detected, rotating cache: #{e.message}")
                CacheAdapter.delete(cache_key)
                new(signed_jwks_uri, entity_jwks).fetch_and_validate
              else
                raise
              end
            end
          end
        else
          new(signed_jwks_uri, entity_jwks).fetch_and_validate
        end
      end

      # Initialize signed JWKS fetcher
      #
      # @param signed_jwks_uri [String] The URI to fetch signed JWKS from
      # @param entity_jwks [Hash, Array] Entity statement JWKS for validation
      def initialize(signed_jwks_uri, entity_jwks)
        @signed_jwks_uri = signed_jwks_uri
        @entity_jwks = entity_jwks
      end

      # Fetch and validate signed JWKS
      #
      # @return [Hash] The validated JWKS hash
      # @raise [FetchError] If fetching fails
      # @raise [ValidationError] If validation fails
      def fetch_and_validate
        # Rate limiting to prevent DoS
        unless RateLimiter.allow?(@signed_jwks_uri)
          raise FetchError, "Rate limit exceeded for signed JWKS fetching"
        end

        # Fetch signed JWKS using HttpClient with retry logic
        begin
          response = HttpClient.get(@signed_jwks_uri)
        rescue OmniauthOpenidFederation::NetworkError => e
          sanitized_uri = Utils.sanitize_uri(@signed_jwks_uri)
          OmniauthOpenidFederation::Logger.error("[SignedJWKS] Failed to fetch signed JWKS from #{sanitized_uri}")
          raise FetchError, "Failed to fetch signed JWKS: #{e.message}", e.backtrace
        end

        unless response.status.success?
          error_msg = "Failed to fetch signed JWKS: HTTP #{response.status}"
          OmniauthOpenidFederation::Logger.error("[SignedJWKS] #{error_msg}")
          # If it's a key-related error (401, 403, 404), this might indicate key rotation
          if Constants::KEY_ROTATION_HTTP_CODES.include?(response.status.code)
            raise KeyRelatedError, error_msg
          else
            raise FetchError, error_msg
          end
        end

        signed_jwks_jwt = response.body.to_s

        # Validate it's a JWT (must have exactly 3 parts: header.payload.signature)
        unless Utils.valid_jwt_format?(signed_jwks_jwt)
          raise ValidationError, "Signed JWKS is not in JWT format"
        end

        # Convert entity JWKS to format expected by JWT gem
        jwks_hash = Jwks::Normalizer.to_jwks_hash(@entity_jwks)

        # Decode and validate signed JWKS
        begin
          OmniauthOpenidFederation::Logger.debug("[SignedJWKS] Validating signed JWKS signature")
          decoded = ::JWT.decode(
            signed_jwks_jwt,
            nil,
            true,
            {algorithms: ["RS256"], jwks: jwks_hash}
          )

          # Extract JWKS from decoded JWT payload
          # The JWT payload can be in two formats:
          # 1. OpenID Federation format: { iss, sub, iat, exp, jwks: { keys: [...] } }
          # 2. Legacy format: { keys: [...] } (direct JWKS)
          full_payload = decoded.first

          # Check if payload has 'jwks' field (OpenID Federation format)
          if full_payload.key?("jwks") || full_payload.key?(:jwks)
            jwks_payload = full_payload["jwks"] || full_payload[:jwks]
          elsif full_payload.key?("keys") || full_payload.key?(:keys)
            # Legacy format: payload is the JWKS directly
            jwks_payload = full_payload
          else
            error_msg = "Signed JWKS payload does not contain 'jwks' or 'keys' field"
            OmniauthOpenidFederation::Logger.error("[SignedJWKS] #{error_msg}")
            raise ValidationError, error_msg
          end

          OmniauthOpenidFederation::Logger.debug("[SignedJWKS] Successfully validated signed JWKS")

          # Ensure it's a HashWithIndifferentAccess if available
          Utils.to_indifferent_hash(jwks_payload)
        rescue JWT::VerificationError => e
          # More specific exception must be rescued first
          error_msg = "Signed JWKS signature validation failed: #{e.class} - #{e.message}"
          OmniauthOpenidFederation::Logger.error("[SignedJWKS] #{error_msg}")
          raise KeyRelatedValidationError, error_msg
        rescue JWT::DecodeError => e
          error_msg = "Failed to decode signed JWKS: #{e.class} - #{e.message}"
          OmniauthOpenidFederation::Logger.error("[SignedJWKS] #{error_msg}")
          raise KeyRelatedValidationError, error_msg
        end
      end
    end
  end
end

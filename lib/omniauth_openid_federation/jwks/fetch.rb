require "http"
require "jwt"
require "openssl"
require_relative "../logger"
require_relative "../errors"
require_relative "../http_client"
require_relative "../cache"
require_relative "../cache_adapter"
require_relative "../utils"
require_relative "../constants"
require_relative "../rate_limiter"
require_relative "normalizer"

# JWKS fetching service with support for both standard and signed JWKS
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
# @see https://openid.net/specs/openid-federation-1_0.html#section-5.2.1.1 Section 5.2.1.1: Usage of jwks, jwks_uri, and signed_jwks_uri
#
# Fetches JWKS from either:
# - Standard JWKS endpoint (jwks_uri) - Returns JSON directly
# - Signed JWKS endpoint (signed_jwks_uri) - Returns a JWT containing JWKS, validated using entity statement keys
#
# Supports caching for performance (24 hour TTL by default) and handles both federation and standard OIDC scenarios.
# According to RFC 7517 and OpenID Connect best practices, JWKS should be cached to reduce latency and avoid
# unnecessary network requests. The cache TTL balances performance with key rotation needs.
#
# Key rotation is handled automatically via retry logic in Jwks::Decode which clears the cache
# on signature verification failures, allowing fresh keys to be fetched when providers rotate keys.
module OmniauthOpenidFederation
  module Jwks
    class Fetch
      # Fetch JWKS from provider with caching support
      #
      # @param jwks_uri [String] The JWKS URI to fetch from
      # @param entity_statement_keys [Hash, Array, nil] Entity statement keys for validating signed JWKS
      # @param cache_ttl [Integer, nil] Cache TTL in seconds (default: from configuration)
      #   - nil: Use configuration default (manual rotation if not set, or configured TTL)
      #   - positive integer: Cache expires after this many seconds
      # @param force_refresh [Boolean] Force refresh even if cached (default: false)
      # @return [Hash] JWKS hash with "keys" array
      # @raise [FetchError] If fetching fails
      def self.run(jwks_uri, entity_statement_keys: nil, cache_ttl: nil, force_refresh: false)
        cache_key = OmniauthOpenidFederation::Cache.key_for_jwks(jwks_uri)
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
                fetch_jwks(jwks_uri, entity_statement_keys)
              end
            rescue KeyRelatedError => e
              # Rotate on key-related errors if configured
              if rotate_on_errors
                OmniauthOpenidFederation::Logger.warn("[Jwks::Fetch] Key-related error detected, rotating cache: #{e.message}")
                CacheAdapter.delete(cache_key)
                fetch_jwks(jwks_uri, entity_statement_keys)
              else
                raise
              end
            end
          else
            # TTL-based cache: expires after cache_ttl seconds
            # Rotate on errors if configured
            begin
              CacheAdapter.fetch(cache_key, expires_in: cache_ttl) do
                fetch_jwks(jwks_uri, entity_statement_keys)
              end
            rescue KeyRelatedError => e
              # Rotate on key-related errors if configured
              if rotate_on_errors
                OmniauthOpenidFederation::Logger.warn("[Jwks::Fetch] Key-related error detected, rotating cache: #{e.message}")
                CacheAdapter.delete(cache_key)
                fetch_jwks(jwks_uri, entity_statement_keys)
              else
                raise
              end
            end
          end
        else
          fetch_jwks(jwks_uri, entity_statement_keys)
        end
      end

      def self.fetch_jwks(jwks_uri, entity_statement_keys)
        # Rate limiting to prevent DoS
        unless RateLimiter.allow?(jwks_uri)
          raise FetchError, "Rate limit exceeded for JWKS fetching"
        end

        # Use HTTP client with retry logic and configurable SSL verification
        begin
          response = HttpClient.get(jwks_uri)
        rescue OmniauthOpenidFederation::NetworkError => e
          sanitized_uri = Utils.sanitize_uri(jwks_uri)
          OmniauthOpenidFederation::Logger.error("[Jwks::Fetch] Failed to fetch JWKS from #{sanitized_uri}: #{e.message}")
          raise FetchError, "Failed to fetch JWKS: #{e.message}", e.backtrace
        end

        unless response.status.success?
          sanitized_uri = Utils.sanitize_uri(jwks_uri)
          error_msg = "Failed to fetch JWKS: HTTP #{response.status}"
          OmniauthOpenidFederation::Logger.error("[Jwks::Fetch] #{error_msg} from #{sanitized_uri}")
          # If it's a key-related error (401, 403, 404), this might indicate key rotation
          if Constants::KEY_ROTATION_HTTP_CODES.include?(response.status.code)
            raise KeyRelatedError, error_msg
          else
            raise FetchError, error_msg
          end
        end

        if entity_statement_keys
          # Validate signed JWKS using entity statement keys
          # If jwks_uri returns a JWT (signed JWKS), validate it
          if Utils.valid_jwt_format?(response.body.to_s)
            # It's a signed JWKS (JWT format)
            jwks_jwt = response.body.to_s

            # Convert entity statement keys to format expected by JWT gem
            jwks_hash = Normalizer.to_jwks_hash(entity_statement_keys)

            jwks_array = ::JWT.decode(
              jwks_jwt,
              nil,
              true,
              {algorithms: ["RS256"], jwks: jwks_hash}
            )

            # Extract JWKS from the decoded JWT payload
            jwks_payload = jwks_array.first
            Utils.to_indifferent_hash(jwks_payload)
          else
            # Standard JWKS JSON
            json = response.parse(:json)
            Utils.to_indifferent_hash(json)
          end
        else
          # Standard JWKS without validation
          json = response.parse(:json)
          Utils.to_indifferent_hash(json)
        end
      end
    end
  end
end

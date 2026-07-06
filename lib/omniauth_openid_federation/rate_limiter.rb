require "digest"
require_relative "cache_adapter"
require_relative "utils"
require_relative "logger"

# Rate limiting for JWKS fetching to prevent DoS attacks
module OmniauthOpenidFederation
  module RateLimiter
    # Default rate limiting configuration
    DEFAULT_MAX_REQUESTS = 10
    DEFAULT_WINDOW_SECONDS = 60

    # Check if request should be throttled
    #
    # Best-effort only: read-modify-write on the cache adapter is not atomic, so parallel
    # workers can briefly exceed the limit. Treat this as a DoS soft guard, not a hard quota.
    #
    # @param key [String] Unique identifier for the rate limit (e.g., jwks_uri)
    # @param max_requests [Integer] Maximum requests allowed in window (default: 10)
    # @param window [Integer] Time window in seconds (default: 60)
    # @return [Boolean] true if request should be allowed, false if throttled
    def self.allow?(key, max_requests: DEFAULT_MAX_REQUESTS, window: DEFAULT_WINDOW_SECONDS)
      return true unless CacheAdapter.available?

      cache_key = "omniauth_openid_federation:rate_limit:#{Digest::SHA256.hexdigest(key)}"
      current_time = Time.now.to_i
      window_start = current_time - window

      timestamps = CacheAdapter.read(cache_key) || []
      timestamps = timestamps.select { |ts| ts > window_start }

      if timestamps.length >= max_requests
        OmniauthOpenidFederation::Logger.warn("[RateLimiter] Rate limit exceeded for #{Utils.sanitize_uri(key)}: #{timestamps.length}/#{max_requests} requests in #{window}s")
        return false
      end

      timestamps << current_time
      CacheAdapter.write(cache_key, timestamps, expires_in: window)

      true
    end

    # Reset rate limit for a key (useful for testing or manual override)
    #
    # @param key [String] Unique identifier for the rate limit
    def self.reset!(key)
      return unless CacheAdapter.available?

      cache_key = "omniauth_openid_federation:rate_limit:#{Digest::SHA256.hexdigest(key)}"
      CacheAdapter.delete(cache_key)
    end
  end
end

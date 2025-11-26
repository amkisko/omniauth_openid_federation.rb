require_relative "../logger"
require_relative "../cache"
require_relative "../cache_adapter"
require_relative "fetch"

# JWKS Cache with automatic invalidation on kid_not_found
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
#
# Provides intelligent caching for JWKS with automatic cache invalidation when a key ID (kid)
# is not found. This handles provider key rotation gracefully by:
# - Caching JWKS for performance
# - Invalidating cache when kid_not_found error occurs (after timeout)
# - Automatically reloading JWKS source on cache miss
#
# This prevents malicious requests from triggering cache invalidations by enforcing
# a grace period (timeout) between invalidations.
module OmniauthOpenidFederation
  module Jwks
    class Cache
      attr_reader :jwks_source, :timeout_sec, :cache_last_update

      # Initialize JWKS cache
      #
      # @param jwks_source [Object] The JWKS source (must respond to #jwks and optionally #reload!)
      # @param timeout_sec [Integer] Minimum seconds between cache invalidations (default: 300 = 5 minutes)
      def initialize(jwks_source, timeout_sec = 300)
        @jwks_source = jwks_source
        @timeout_sec = timeout_sec
        @cache_last_update = 0
        @cached_keys = nil
      end

      # Get JWKS with automatic cache invalidation on kid_not_found
      #
      # @param options [Hash] Options hash
      # @option options [Boolean] :kid_not_found Whether kid was not found (triggers invalidation if timeout passed)
      # @option options [String] :kid The key ID that was not found
      # @return [Array<Hash>] Array of signing keys (filtered from JWKS)
      def call(options = {})
        # Check if we should invalidate cache due to kid_not_found
        if options[:kid_not_found] && @cache_last_update < Time.now.to_i - @timeout_sec
          kid = options[:kid]
          OmniauthOpenidFederation::Logger.info("[Jwks::Cache] Invalidating JWK cache. Kid '#{kid}' not found from previous cache")
          @cached_keys = nil
          @jwks_source.reload! if @jwks_source.respond_to?(:reload!)
        end

        # Return cached keys or fetch fresh
        @cached_keys ||= begin
          @cache_last_update = Time.now.to_i
          jwks = @jwks_source.jwks

          # Ensure jwks is in the expected format
          keys = if jwks.is_a?(Hash) && (jwks.key?("keys") || jwks.key?(:keys))
            jwks["keys"] || jwks[:keys] || []
          elsif jwks.is_a?(Array)
            jwks
          else
            []
          end

          # Filter to signing keys only (for JWT verification)
          keys.select { |key| (key[:use] || key["use"]) == "sig" }
        end
      end

      # Clear the cache
      #
      # @return [void]
      def clear!
        @cached_keys = nil
        @cache_last_update = 0
      end
    end
  end
end

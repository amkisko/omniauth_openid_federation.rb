require "digest"
require_relative "cache_adapter"

# Cache utilities for JWKS caching
module OmniauthOpenidFederation
  module Cache
    # Generate cache key for JWKS
    #
    # @param jwks_uri [String] The JWKS URI
    # @return [String] Cache key
    def self.key_for_jwks(jwks_uri)
      "omniauth_openid_federation:jwks:#{Digest::SHA256.hexdigest(jwks_uri)}"
    end

    # Generate cache key for signed JWKS
    #
    # @param signed_jwks_uri [String] The signed JWKS URI
    # @return [String] Cache key
    def self.key_for_signed_jwks(signed_jwks_uri)
      "omniauth_openid_federation:signed_jwks:#{Digest::SHA256.hexdigest(signed_jwks_uri)}"
    end

    # Delete JWKS cache
    #
    # @param jwks_uri [String] The JWKS URI
    def self.delete_jwks(jwks_uri)
      return unless CacheAdapter.available?
      CacheAdapter.delete(key_for_jwks(jwks_uri))
    end

    # Delete signed JWKS cache
    #
    # @param signed_jwks_uri [String] The signed JWKS URI
    def self.delete_signed_jwks(signed_jwks_uri)
      return unless CacheAdapter.available?
      CacheAdapter.delete(key_for_signed_jwks(signed_jwks_uri))
    end
  end
end

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
    # @param entity_jwks [Hash, Array, nil] Entity JWKS used to verify the signed set
    # @return [String] Cache key
    def self.key_for_signed_jwks(signed_jwks_uri, entity_jwks: nil)
      material = "#{signed_jwks_uri}:#{canonical_jwks_digest(entity_jwks)}"
      "omniauth_openid_federation:signed_jwks:#{Digest::SHA256.hexdigest(material)}"
    end

    def self.canonical_jwks_digest(entity_jwks)
      return "none" if entity_jwks.nil?

      require "json"
      Digest::SHA256.hexdigest(JSON.generate(deep_sort_keys(entity_jwks)))
    end

    def self.deep_sort_keys(value)
      case value
      when Hash
        value.keys.map(&:to_s).sort.index_with { |key| deep_sort_keys(value[key] || value[key.to_sym]) }
      when Array
        value.map { |item| deep_sort_keys(item) }
      else
        value
      end
    end
    private_class_method :canonical_jwks_digest, :deep_sort_keys

    # Generate cache key for locally served JWKS (federation endpoint)
    #
    # @param issuer [String] Federation endpoint issuer entity identifier
    # @return [String] Cache key
    def self.key_for_served_jwks(issuer)
      "federation:jwks:#{Digest::SHA256.hexdigest(issuer)}"
    end

    # Generate cache key for locally served signed JWKS (federation endpoint)
    #
    # @param issuer [String] Federation endpoint issuer entity identifier
    # @return [String] Cache key
    def self.key_for_served_signed_jwks(issuer)
      "federation:signed_jwks:#{Digest::SHA256.hexdigest(issuer)}"
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
    # @param entity_jwks [Hash, Array, nil] Entity JWKS used when the entry was cached
    def self.delete_signed_jwks(signed_jwks_uri, entity_jwks: nil)
      return unless CacheAdapter.available?
      CacheAdapter.delete(key_for_signed_jwks(signed_jwks_uri, entity_jwks: entity_jwks))
    end
  end
end

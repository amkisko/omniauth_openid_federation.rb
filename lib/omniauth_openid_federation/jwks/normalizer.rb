require "json"
require_relative "../validators"

# JWKS normalization utilities
# Converts various JWKS formats to the format expected by JWT gem
module OmniauthOpenidFederation
  module Jwks
    class Normalizer
      # Convert JWKS to format expected by JWT gem
      # Handles various input formats: Hash with "keys" or :keys, Array of keys, etc.
      #
      # @param jwks [Hash, Array, Object] JWKS in various formats
      # @return [Hash] Normalized JWKS hash with "keys" array (string keys)
      def self.to_jwks_hash(jwks)
        if jwks.is_a?(Hash) && (jwks.key?("keys") || jwks.key?(:keys))
          # Hash with keys array
          keys = jwks["keys"] || jwks[:keys]
          normalize_keys_array(keys)
        elsif jwks.is_a?(Array)
          # Array of keys
          normalize_keys_array(jwks)
        else
          # Fallback: try to convert to hash
          normalized = Validators.normalize_hash(jwks || {})
          keys = normalized[:keys] || []
          normalize_keys_array(keys)
        end
      end

      # Normalize an array of JWK objects to hash format with string keys
      #
      # @param keys [Array] Array of JWK objects (Hash, etc.)
      # @return [Hash] Hash with "keys" array containing normalized JWKs
      def self.normalize_keys_array(keys)
        {
          "keys" => Array(keys).map do |jwk|
            if jwk.is_a?(Hash)
              stringify_hash_keys(jwk)
            else
              JSON.parse(jwk.to_json)
            end
          end
        }
      end

      def self.stringify_hash_keys(hash)
        hash.each_with_object({}) do |(key, value), result|
          result[key.to_s] = value.is_a?(Hash) ? stringify_hash_keys(value) : value
        end
      end

      private_class_method :normalize_keys_array, :stringify_hash_keys
    end
  end
end

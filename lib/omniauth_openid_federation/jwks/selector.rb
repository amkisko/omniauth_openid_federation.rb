require_relative "../logger"

# JWKS Selector utilities for filtering keys
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
#
# Provides utilities for selecting specific keys from a JWKS set, such as:
# - Current keys (first signing and encryption keys)
# - All keys (including previous keys for rotation support)
# - Keys by use (signing vs encryption)
# - Keys by kid (key ID)
module OmniauthOpenidFederation
  module Jwks
    class Selector
      # Get current keys from JWKS (first signing and encryption keys)
      # This is useful for operations that only need the current keys, not all keys
      # including previous keys from rotation.
      #
      # @param jwks [Hash, Array] JWKS hash with "keys" array or array of keys
      # @return [Hash] JWKS hash with only current keys (one signing, one encryption)
      def self.current_keys(jwks)
        keys = extract_keys_array(jwks)
        return {"keys" => []} if keys.empty?

        taken_uses = []
        current_keys = keys.select do |key|
          use = key[:use] || key["use"]
          if use == "sig" && !taken_uses.include?("sig")
            taken_uses << "sig"
            true
          elsif use == "enc" && !taken_uses.include?("enc")
            taken_uses << "enc"
            true
          else
            false
          end
        end

        {"keys" => current_keys}
      end

      # Get all keys from JWKS (including previous keys from rotation)
      #
      # @param jwks [Hash, Array] JWKS hash with "keys" array or array of keys
      # @return [Hash] JWKS hash with all keys
      def self.all_keys(jwks)
        keys = extract_keys_array(jwks)
        {"keys" => keys}
      end

      # Get signing keys only
      #
      # @param jwks [Hash, Array] JWKS hash with "keys" array or array of keys
      # @return [Array<Hash>] Array of signing keys
      def self.signing_keys(jwks)
        keys = extract_keys_array(jwks)
        keys.select { |key| (key[:use] || key["use"]) == "sig" }
      end

      # Get encryption keys only
      #
      # @param jwks [Hash, Array] JWKS hash with "keys" array or array of keys
      # @return [Array<Hash>] Array of encryption keys
      def self.encryption_keys(jwks)
        keys = extract_keys_array(jwks)
        keys.select { |key| (key[:use] || key["use"]) == "enc" }
      end

      # Get key by kid (key ID)
      #
      # @param jwks [Hash, Array] JWKS hash with "keys" array or array of keys
      # @param kid [String] The key ID to find
      # @return [Hash, nil] The key with matching kid, or nil if not found
      def self.key_by_kid(jwks, kid)
        keys = extract_keys_array(jwks)
        keys.find { |key| (key[:kid] || key["kid"]) == kid }
      end

      # Extract keys array from various JWKS formats
      #
      # @param jwks [Hash, Array] JWKS in various formats
      # @return [Array<Hash>] Array of key hashes
      def self.extract_keys_array(jwks)
        if jwks.is_a?(Hash)
          if jwks.key?("keys")
            jwks["keys"] || []
          elsif jwks.key?(:keys)
            jwks[:keys] || []
          else
            []
          end
        elsif jwks.is_a?(Array)
          jwks
        else
          []
        end
      end

      private_class_method :extract_keys_array
    end
  end
end

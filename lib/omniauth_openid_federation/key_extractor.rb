require "jwt"
require "openssl"
require "base64"
require_relative "validators"
require_relative "jwks/normalizer"

# Key extractor for OpenID Federation
# Extracts signing and encryption keys from JWKS according to OpenID Federation spec
# Supports both separate keys (use: "sig" and use: "enc") and single key (backward compatibility)
#
# According to OpenID Federation spec:
# - "When both signing and encryption keys are present" - separate keys are supported
# - Separate keys are not mandatory
# - Using the same key for both is allowed
module OmniauthOpenidFederation
  class KeyExtractor
    # Extract signing key from JWKS or metadata
    #
    # @param jwks [Hash, Array, nil] JWKS hash or array of keys
    # @param metadata [Hash, nil] Metadata hash containing JWKS
    # @param private_key [OpenSSL::PKey::RSA, String, nil] Fallback private key if JWKS not available
    # @return [OpenSSL::PKey::RSA, nil] Signing key or nil if not found
    def self.extract_signing_key(jwks: nil, metadata: nil, private_key: nil)
      # Try to extract from JWKS first
      if jwks || metadata
        keys = extract_keys_from_jwks(jwks: jwks, metadata: metadata)
        signing_key_data = find_key_by_use(keys, "sig")

        if signing_key_data
          return jwk_to_openssl_key(signing_key_data)
        end

        # If no signing key found but keys exist, try first key without use field (backward compatibility)
        if keys.any?
          first_key = keys.first
          unless first_key["use"] # Only use if no use field specified
            return jwk_to_openssl_key(first_key)
          end
        end
      end

      # Fallback to provided private_key (backward compatibility)
      if private_key
        return normalize_private_key(private_key)
      end

      nil
    end

    # Extract encryption key from JWKS or metadata
    #
    # @param jwks [Hash, Array, nil] JWKS hash or array of keys
    # @param metadata [Hash, nil] Metadata hash containing JWKS
    # @param private_key [OpenSSL::PKey::RSA, String, nil] Fallback private key if JWKS not available
    # @return [OpenSSL::PKey::RSA, nil] Encryption key or nil if not found
    def self.extract_encryption_key(jwks: nil, metadata: nil, private_key: nil)
      # Try to extract from JWKS first
      if jwks || metadata
        keys = extract_keys_from_jwks(jwks: jwks, metadata: metadata)
        encryption_key_data = find_key_by_use(keys, "enc")

        if encryption_key_data
          return jwk_to_openssl_key(encryption_key_data)
        end

        # If no encryption key found but keys exist, try first key without use field (backward compatibility)
        if keys.any?
          first_key = keys.first
          unless first_key["use"] # Only use if no use field specified
            return jwk_to_openssl_key(first_key)
          end
        end
      end

      # Fallback to provided private_key (backward compatibility)
      if private_key
        return normalize_private_key(private_key)
      end

      nil
    end

    # Extract key by use value or fallback to single key
    #
    # @param jwks [Hash, Array, nil] JWKS hash or array of keys
    # @param metadata [Hash, nil] Metadata hash containing JWKS
    # @param use [String, nil] Use value ("sig" or "enc")
    # @param private_key [OpenSSL::PKey::RSA, String, nil] Fallback private key
    # @return [OpenSSL::PKey::RSA, nil] Key or nil if not found
    def self.extract_key(jwks: nil, metadata: nil, use: nil, private_key: nil)
      if use == "sig"
        extract_signing_key(jwks: jwks, metadata: metadata, private_key: private_key)
      elsif use == "enc"
        extract_encryption_key(jwks: jwks, metadata: metadata, private_key: private_key)
      else
        # No use specified, try signing first, then encryption, then fallback
        extract_signing_key(jwks: jwks, metadata: metadata, private_key: private_key) ||
          extract_encryption_key(jwks: jwks, metadata: metadata, private_key: private_key)
      end
    end

    # Extract keys array from JWKS or metadata
    #
    # @param jwks [Hash, Array, nil] JWKS hash or array
    # @param metadata [Hash, nil] Metadata hash
    # @return [Array<Hash>] Array of key hashes
    def self.extract_keys_from_jwks(jwks: nil, metadata: nil)
      if jwks
        normalized = Jwks::Normalizer.to_jwks_hash(jwks)
        return normalized["keys"] || []
      end

      if metadata
        jwks_data = metadata["jwks"] || metadata[:jwks]
        if jwks_data
          normalized = Jwks::Normalizer.to_jwks_hash(jwks_data)
          return normalized["keys"] || []
        end
      end

      []
    end

    # Find key by use value
    #
    # @param keys [Array<Hash>] Array of key hashes
    # @param use [String] Use value ("sig" or "enc")
    # @return [Hash, nil] Key hash or nil
    def self.find_key_by_use(keys, use)
      keys.find { |key| key["use"] == use || key[:use] == use }
    end

    # Normalize private key to OpenSSL::PKey::RSA
    #
    # @param private_key [OpenSSL::PKey::RSA, String] Private key
    # @return [OpenSSL::PKey::RSA] Normalized private key
    def self.normalize_private_key(private_key)
      if private_key.is_a?(String)
        OpenSSL::PKey::RSA.new(private_key)
      elsif private_key.is_a?(OpenSSL::PKey::RSA)
        private_key
      else
        raise ArgumentError, "Invalid private key type: #{private_key.class}"
      end
    end

    # Convert JWK hash to OpenSSL key (private or public)
    #
    # @param jwk_data [Hash] JWK hash
    # @return [OpenSSL::PKey::RSA] OpenSSL key
    def self.jwk_to_openssl_key(jwk_data)
      # Use JWT::JWK if available (jwt gem 2.7+)
      # JWT::JWK.import handles both public and private keys and is OpenSSL 3.0 compatible
      if defined?(JWT::JWK)
        jwk = JWT::JWK.import(jwk_data)
        # JWT::JWK::RSA has keypair method for private keys, public_key for public keys
        if jwk_data[:d] || jwk_data["d"]
          # Private key - use keypair method
          jwk.keypair
        else
          # Public key
          jwk.public_key
        end
      else
        # Fallback: Manual conversion (OpenSSL 2.x compatible only)
        # For OpenSSL 3.0, JWT::JWK is required
        raise ArgumentError, "JWT::JWK is required for OpenSSL 3.0 compatibility. Please ensure jwt gem >= 2.7 is installed."
      end
    end

    private_class_method :extract_keys_from_jwks, :find_key_by_use, :normalize_private_key
  end
end

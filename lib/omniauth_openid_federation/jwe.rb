require "json/jwt"

require_relative "errors"

module OmniauthOpenidFederation
  # Compact-serialization JWE helpers for nested JWTs (sign then encrypt).
  # Uses json-jwt (same stack as openid_connect) instead of the standalone jwe gem.
  module Jwe
    PARTS_COUNT = JSON::JWE::NUM_OF_SEGMENTS

    def self.encrypted?(token)
      token.to_s.count(".") + 1 == PARTS_COUNT
    end

    def self.encrypt(plaintext, public_key, alg:, enc:)
      jwe = JSON::JWE.new(plaintext.to_s)
      jwe.alg = alg.to_sym
      jwe.enc = enc.to_sym
      jwe.encrypt!(public_key).to_s
    end

    def self.decrypt(ciphertext, private_key)
      JSON::JWE.decode_compact_serialized(ciphertext.to_s, private_key).plain_text
    rescue JSON::JWE::DecryptionFailed, JSON::JWT::InvalidFormat => error
      raise OmniauthOpenidFederation::DecryptionError,
        "Failed to decrypt JWE: #{error.message}",
        error.backtrace
    end
  end
end

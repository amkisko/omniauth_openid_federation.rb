require "jwe"

require_relative "errors"

module OmniauthOpenidFederation
  # Compact-serialization JWE helpers for nested JWTs (sign then encrypt).
  module Jwe
    PARTS_COUNT = 5

    def self.encrypted?(token)
      token.to_s.count(".") + 1 == PARTS_COUNT
    end

    def self.encrypt(plaintext, public_key, alg:, enc:)
      ::JWE.encrypt(plaintext.to_s, public_key, alg: alg.to_s, enc: enc.to_s)
    end

    def self.decrypt(ciphertext, private_key)
      ::JWE.decrypt(ciphertext.to_s, private_key)
    rescue ::JWE::DecodeError, ::JWE::InvalidData, ::JWE::BadCEK, ::JWE::NotImplementedError, ArgumentError => error
      raise OmniauthOpenidFederation::DecryptionError,
        "Failed to decrypt JWE: #{error.message}",
        error.backtrace
    end
  end
end

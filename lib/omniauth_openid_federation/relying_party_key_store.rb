# frozen_string_literal: true

require "openssl"
require "base64"
require_relative "errors"
require_relative "constants"
require_relative "cache_adapter"

module OmniauthOpenidFederation
  # Optional RP private-key storage. Hosts may keep keys in file, ENV, or cache.
  class RelyingPartyKeyStore
    Record = Data.define(:signing_key, :encryption_key)

    def load
      raise NotImplementedError, "#{self.class}#load"
    end

    def store(signing_key:, encryption_key:)
      raise NotImplementedError, "#{self.class}#store"
    end

    def rotate
      signing_key = OpenSSL::PKey::RSA.new(Constants::MIN_RSA_KEY_BITS)
      encryption_key = OpenSSL::PKey::RSA.new(Constants::MIN_RSA_KEY_BITS)
      store(signing_key: signing_key, encryption_key: encryption_key)
      Record.new(signing_key: signing_key, encryption_key: encryption_key)
    end

    class FileStore < RelyingPartyKeyStore
      def initialize(signing_path:, encryption_path: nil)
        @signing_path = signing_path
        @encryption_path = encryption_path || signing_path
      end

      def load
        Record.new(
          signing_key: OpenSSL::PKey::RSA.new(File.read(@signing_path)),
          encryption_key: OpenSSL::PKey::RSA.new(File.read(@encryption_path))
        )
      end

      def store(signing_key:, encryption_key:)
        File.write(@signing_path, signing_key.to_pem)
        File.chmod(0o600, @signing_path)
        File.write(@encryption_path, encryption_key.to_pem)
        File.chmod(0o600, @encryption_path)
        Record.new(signing_key: signing_key, encryption_key: encryption_key)
      end
    end

    class EnvStore < RelyingPartyKeyStore
      def initialize(signing_env:, encryption_env: nil, base64: true)
        @signing_env = signing_env
        @encryption_env = encryption_env || signing_env
        @base64 = base64
      end

      def load
        Record.new(
          signing_key: decode(ENV.fetch(@signing_env)),
          encryption_key: decode(ENV.fetch(@encryption_env))
        )
      end

      def store(signing_key:, encryption_key:)
        raise ConfigurationError, "EnvStore is read-only; set #{@signing_env} / #{@encryption_env}"
      end

      private

      def decode(value)
        pem = @base64 ? Base64.decode64(value) : value
        OpenSSL::PKey::RSA.new(pem)
      end
    end

    class CacheStore < RelyingPartyKeyStore
      SIGNING_SUFFIX = "signing_pem"
      ENCRYPTION_SUFFIX = "encryption_pem"

      def initialize(cache_key_prefix:, expires_in: nil)
        @prefix = cache_key_prefix
        @expires_in = expires_in
      end

      def load
        signing_pem = CacheAdapter.read(key(SIGNING_SUFFIX))
        encryption_pem = CacheAdapter.read(key(ENCRYPTION_SUFFIX))
        raise ConfigurationError, "RP keys missing from cache (#{@prefix})" if signing_pem.nil? || encryption_pem.nil?

        Record.new(
          signing_key: OpenSSL::PKey::RSA.new(signing_pem),
          encryption_key: OpenSSL::PKey::RSA.new(encryption_pem)
        )
      end

      def store(signing_key:, encryption_key:)
        CacheAdapter.write(key(SIGNING_SUFFIX), signing_key.to_pem, expires_in: @expires_in)
        CacheAdapter.write(key(ENCRYPTION_SUFFIX), encryption_key.to_pem, expires_in: @expires_in)
        Record.new(signing_key: signing_key, encryption_key: encryption_key)
      end

      private

      def key(suffix)
        "#{@prefix}:#{suffix}"
      end
    end
  end
end

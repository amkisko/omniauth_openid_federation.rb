# frozen_string_literal: true

require "openssl"
require_relative "errors"

module OmniauthOpenidFederation
  # Resolves RP key material at use time (object, PEM string, or callable).
  module KeyResolver
    MAX_DEPTH = 5

    module_function

    # @param value [OpenSSL::PKey::RSA, String, #call, nil]
    # @return [OpenSSL::PKey::RSA, nil]
    def resolve(value, depth: 0)
      return nil if value.nil?
      raise ConfigurationError, "Key resolver recursion limit exceeded" if depth > MAX_DEPTH

      case value
      when OpenSSL::PKey::RSA
        value
      when String
        OpenSSL::PKey::RSA.new(value)
      else
        if value.respond_to?(:call)
          resolve(value.call, depth: depth + 1)
        else
          raise ConfigurationError,
            "Private key must be an OpenSSL::PKey::RSA instance, PEM string, or callable (got #{value.class})"
        end
      end
    rescue OpenSSL::PKey::PKeyError, ArgumentError => error
      raise ConfigurationError, "Invalid private key format: #{error.message}"
    end
  end
end

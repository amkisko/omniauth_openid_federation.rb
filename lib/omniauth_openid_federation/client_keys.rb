# frozen_string_literal: true

require_relative "key_resolver"
require_relative "validators"

module OmniauthOpenidFederation
  # Resolves signing and encryption keys from client_options / strategy options.
  module ClientKeys
    module_function

    def signing_key(normalized_client_options, strategy_options = {})
      KeyResolver.resolve(
        pick(normalized_client_options, :signing_key) ||
          strategy_options[:signing_key] ||
          pick(normalized_client_options, :private_key)
      )
    end

    def encryption_key(normalized_client_options, strategy_options = {})
      KeyResolver.resolve(
        pick(normalized_client_options, :encryption_key) ||
          strategy_options[:encryption_key] ||
          pick(normalized_client_options, :private_key)
      )
    end

    def validate_signing_key!(normalized_client_options, strategy_options = {})
      key = signing_key(normalized_client_options, strategy_options)
      Validators.validate_private_key!(key)
      key
    end

    def pick(hash, key)
      hash[key] || hash[key.to_s]
    end
    private_class_method :pick
  end
end

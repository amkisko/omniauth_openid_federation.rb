# frozen_string_literal: true

# Shared helpers for OpenIDConnect::AccessToken specs
module AccessTokenHelpers
  def create_client_with_strategy_options(strategy_options = {})
    default_client_options = {
      identifier: "test-client-id",
      redirect_uri: "https://example.com/callback",
      host: URI.parse(provider_issuer).host,
      jwks_uri: "#{provider_issuer}/.well-known/jwks.json",
      private_key: private_key
    }

    default_options = {
      client_options: default_client_options,
      entity_statement_path: nil
    }

    # Merge strategy options
    merged_client_options = default_client_options.merge(strategy_options[:client_options] || {})
    merged_options = default_options.merge(strategy_options)
    merged_options[:client_options] = merged_client_options

    client = double(
      jwks_uri: URI.parse(merged_options[:client_options][:jwks_uri]),
      private_key: merged_options[:client_options][:private_key]
    )
    client.instance_variable_set(:@strategy_options, merged_options)
    client
  end

  def provider_issuer
    "https://provider.example.com"
  end

  def private_key
    @private_key ||= OpenSSL::PKey::RSA.new(2048)
  end

  def public_key
    @public_key ||= private_key.public_key
  end
end

RSpec.configure do |config|
  config.include AccessTokenHelpers, type: :access_token
end

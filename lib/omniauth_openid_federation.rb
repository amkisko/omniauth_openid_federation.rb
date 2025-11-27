# OmniAuth OpenID Federation
#
# Custom OmniAuth strategy for OpenID Federation providers using openid_connect gem
# supporting signed request objects, ID token encryption, and OpenID Federation.
#
# @see https://openid.net/specs/openid-federation-1_0.html
module OmniauthOpenidFederation
  # Configure the gem
  #
  # @yield [config] Yields the configuration object
  # @example
  #   OmniauthOpenidFederation.configure do |config|
  #     config.verify_ssl = false # Only for development
  #     config.cache_ttl = 3600
  #   end
  def self.configure
    yield(Configuration.config) if block_given?
    Configuration.config
  end

  # Get the global configuration
  #
  # @return [Configuration] The configuration instance
  def self.config
    Configuration.config
  end
end

require_relative "omniauth_openid_federation/version"
require_relative "omniauth_openid_federation/string_helpers"
require_relative "omniauth_openid_federation/logger"
require_relative "omniauth_openid_federation/configuration"
require_relative "omniauth_openid_federation/errors"
require_relative "omniauth_openid_federation/instrumentation"
require_relative "omniauth_openid_federation/validators"
require_relative "omniauth_openid_federation/key_extractor"
require_relative "omniauth_openid_federation/constants"
require_relative "omniauth_openid_federation/cache"
require_relative "omniauth_openid_federation/cache_adapter"
require_relative "omniauth_openid_federation/utils"
require_relative "omniauth_openid_federation/jws"
require_relative "omniauth_openid_federation/jwks/normalizer"
require_relative "omniauth_openid_federation/jwks/fetch"
require_relative "omniauth_openid_federation/jwks/decode"
require_relative "omniauth_openid_federation/jwks/cache"
require_relative "omniauth_openid_federation/jwks/selector"
require_relative "omniauth_openid_federation/jwks/rotate"
require_relative "omniauth_openid_federation/federation/entity_statement"
require_relative "omniauth_openid_federation/federation/entity_statement_fetcher"
require_relative "omniauth_openid_federation/federation/entity_statement_parser"
require_relative "omniauth_openid_federation/federation/entity_statement_validator"
require_relative "omniauth_openid_federation/federation/entity_statement_helper"
require_relative "omniauth_openid_federation/federation/entity_statement_builder"
require_relative "omniauth_openid_federation/federation/trust_chain_resolver"
require_relative "omniauth_openid_federation/federation/metadata_policy_merger"
require_relative "omniauth_openid_federation/federation/signed_jwks"
require_relative "omniauth_openid_federation/federation_endpoint"
require_relative "omniauth_openid_federation/rack_endpoint"
require_relative "omniauth_openid_federation/entity_statement_reader"
require_relative "omniauth_openid_federation/tasks_helper"
require_relative "omniauth_openid_federation/endpoint_resolver"
require_relative "omniauth_openid_federation/strategy"
require_relative "omniauth_openid_federation/access_token"

module OmniauthOpenidFederation
  # Rotate JWKS cache for a provider
  # This is useful for background jobs to proactively refresh keys
  #
  # @param jwks_uri [String] The JWKS URI to refresh
  # @param entity_statement_path [String, nil] Path to entity statement file (optional)
  # @return [Hash] The refreshed JWKS hash
  # @raise [FetchError] If fetching fails
  # @raise [ValidationError] If validation fails
  # @example
  #   # Rotate JWKS for a provider
  #   OmniauthOpenidFederation.rotate_jwks(
  #     "https://provider.example.com/.well-known/jwks.json",
  #     entity_statement_path: "config/provider-entity-statement.jwt"
  #   )
  def self.rotate_jwks(jwks_uri, entity_statement_path: nil)
    Jwks::Rotate.run(jwks_uri, entity_statement_path: entity_statement_path)
  end
end

# Load Engine for Rails integration (controllers, routes, etc.)
if defined?(Rails)
  require_relative "omniauth_openid_federation/engine"
  require_relative "omniauth_openid_federation/railtie"
end

# Create an alias for Devise's autoload mechanism
# Devise tries to autoload OpenidFederation (camelCase) from :openid_federation
# but our class is OpenIDFederation (with capital ID)
module OmniAuth
  module Strategies
    # Alias for Devise autoload compatibility
    OpenidFederation = OpenIDFederation unless defined?(OpenidFederation)
  end
end

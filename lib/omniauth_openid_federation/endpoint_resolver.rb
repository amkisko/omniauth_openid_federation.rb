require "uri"
require "json"
require_relative "string_helpers"
require_relative "logger"
require_relative "errors"
require_relative "utils"
require_relative "federation/entity_statement"

# Endpoint resolver for OpenID Federation
# Resolves OAuth 2.0 endpoints from entity statement metadata or configuration
module OmniauthOpenidFederation
  # Endpoint resolver for OpenID Federation
  #
  # Resolves OAuth 2.0 endpoints from entity statement metadata or configuration.
  #
  # @example Resolve endpoints from entity statement
  #   endpoints = EndpointResolver.resolve(
  #     entity_statement_path: "config/provider-entity-statement.jwt",
  #     config: {}
  #   )
  class EndpointResolver
    class << self
      # Resolve endpoints from entity statement or configuration
      #
      # Priority: config -> entity statement -> nil
      #
      # @param entity_statement_path [String, nil] Path to entity statement file
      # @param config [Hash] Configuration hash with endpoint keys
      # @return [Hash] Hash with :authorization_endpoint, :token_endpoint, :userinfo_endpoint, :jwks_uri, :entity_statement_endpoint, :audience
      def resolve(entity_statement_path: nil, config: {})
        # Try to get endpoints from entity statement if available
        entity_metadata = load_entity_statement_metadata(entity_statement_path)

        # Extract endpoints with priority: config -> entity statement -> nil
        # For entity statement, prefer full URLs if available, otherwise extract path
        # Entity statement metadata may contain full URLs (preferred) or paths
        entity_provider_metadata = entity_metadata&.dig(:metadata, :openid_provider) || {}

        # Get endpoint from entity statement (may be full URL or path)
        entity_auth_endpoint = entity_provider_metadata["authorization_endpoint"] || entity_provider_metadata[:authorization_endpoint]
        entity_token_endpoint = entity_provider_metadata["token_endpoint"] || entity_provider_metadata[:token_endpoint]
        entity_userinfo_endpoint = entity_provider_metadata["userinfo_endpoint"] || entity_provider_metadata[:userinfo_endpoint]
        entity_jwks_uri = entity_provider_metadata["jwks_uri"] || entity_provider_metadata[:jwks_uri]

        # Use config if provided, otherwise use entity statement value (full URL or path)
        authorization_endpoint = config[:authorization_endpoint] || entity_auth_endpoint
        token_endpoint = config[:token_endpoint] || entity_token_endpoint
        userinfo_endpoint = config[:userinfo_endpoint] || entity_userinfo_endpoint
        jwks_uri = config[:jwks_uri] || entity_jwks_uri

        # Entity statement endpoint (defaults to /.well-known/openid-federation if not specified)
        entity_statement_endpoint = config[:entity_statement_endpoint] ||
          extract_path_from_url(entity_metadata&.dig(:metadata, :openid_federation, "federation_entity_endpoint")) ||
          extract_path_from_url(entity_metadata&.dig(:metadata, :openid_federation, :federation_entity_endpoint)) ||
          "/.well-known/openid-federation"

        # Determine audience
        # For OpenID Federation, audience should be the provider issuer (not token endpoint)
        audience = config[:audience]
        unless audience
          # Try provider issuer from entity statement first (preferred for OpenID Federation)
          provider_issuer = entity_metadata&.dig(:metadata, :openid_provider, "issuer") ||
            entity_metadata&.dig(:metadata, :openid_provider, :issuer)
          if StringHelpers.present?(provider_issuer)
            audience = provider_issuer
          else
            # Fallback to token endpoint URL if provider issuer not available
            token_endpoint_url = entity_metadata&.dig(:metadata, :openid_provider, "token_endpoint") ||
              entity_metadata&.dig(:metadata, :openid_provider, :token_endpoint)
            audience = token_endpoint_url if StringHelpers.present?(token_endpoint_url)
          end
        end

        {
          authorization_endpoint: authorization_endpoint,
          token_endpoint: token_endpoint,
          userinfo_endpoint: userinfo_endpoint,
          jwks_uri: jwks_uri,
          entity_statement_endpoint: entity_statement_endpoint,
          audience: audience
        }
      end

      # Build full entity statement URL from issuer and endpoint path
      #
      # @param issuer_uri [String, URI] Issuer URI (e.g., "https://provider.example.com")
      # @param entity_statement_endpoint [String, nil] Entity statement endpoint path (e.g., "/.well-known/openid-federation")
      # @return [String] Full entity statement URL
      def build_entity_statement_url(issuer_uri, entity_statement_endpoint: nil)
        Utils.build_entity_statement_url(issuer_uri, entity_statement_endpoint: entity_statement_endpoint)
      end

      # Build full endpoint URL from issuer and endpoint path
      #
      # @param issuer_uri [String, URI] Issuer URI (e.g., "https://provider.example.com")
      # @param endpoint_path [String] Endpoint path (e.g., "/oauth2/authorize")
      # @return [String] Full endpoint URL
      def build_endpoint_url(issuer_uri, endpoint_path)
        Utils.build_endpoint_url(issuer_uri, endpoint_path)
      end

      # Validate that required endpoints are present
      # @param endpoints [Hash] Endpoints hash from resolve
      # @param issuer_uri [URI] Issuer URI for building audience if needed
      # @return [Hash] Validated endpoints with audience built if needed
      # @raise [ConfigurationError] If required endpoints are missing
      def validate_and_build_audience(endpoints, issuer_uri: nil)
        if StringHelpers.blank?(endpoints[:authorization_endpoint])
          raise ConfigurationError, "Authorization endpoint not configured. Provide authorization_endpoint in config or entity statement"
        end
        if StringHelpers.blank?(endpoints[:token_endpoint])
          raise ConfigurationError, "Token endpoint not configured. Provide token_endpoint in config or entity statement"
        end
        if StringHelpers.blank?(endpoints[:jwks_uri])
          raise ConfigurationError, "JWKS URI not configured. Provide jwks_uri in config or entity statement"
        end

        # Build audience from issuer + token_endpoint if not provided
        # Note: For OpenID Federation, audience should ideally be provider issuer,
        # but if not available, we build from issuer + token_endpoint path
        unless StringHelpers.present?(endpoints[:audience])
          if issuer_uri
            # For some providers, audience may be issuer + path prefix
            # But we'll use token_endpoint as fallback since we don't have provider issuer here
            audience_uri = issuer_uri.dup
            audience_uri.path = endpoints[:token_endpoint]
            endpoints[:audience] = audience_uri.to_s
          end
        end

        endpoints
      end

      private

      def load_entity_statement_metadata(entity_statement_path)
        return nil unless entity_statement_path && File.exist?(entity_statement_path)

        begin
          entity_statement = OmniauthOpenidFederation::Federation::EntityStatement.new(File.read(entity_statement_path))
          entity_statement.parse
        rescue => e
          OmniauthOpenidFederation::Logger.warn("[EndpointResolver] Failed to parse entity statement: #{e.message}")
          nil
        end
      end

      def extract_path_from_url(url)
        return nil if StringHelpers.blank?(url)
        return url.to_s if url.to_s.start_with?("http://", "https://") # Return full URL as-is

        begin
          uri = URI.parse(url.to_s)
          # If it's a full URL, return the path; if it's already a path, return as-is
          if uri.host
            StringHelpers.present?(uri.path) ? uri.path : nil
          else
            # No host means it's already a path
            url.to_s.start_with?("/") ? url.to_s : "/#{url}"
          end
        rescue URI::InvalidURIError
          # If it's already a path (starts with /), return as-is
          url.to_s.start_with?("/") ? url.to_s : nil
        end
      end
    end
  end
end

require "oauth2"
require "jwt"
require "securerandom"
require "uri"

require_relative "errors"
require_relative "access_token"

module OmniauthOpenidFederation
  class OidcClient < OAuth2::Client
    CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    CLIENT_ASSERTION_EXPIRATION_SECONDS = 180

    attr_accessor :private_key, :authorization_code, :jwks_uri
    attr_reader :authorization_endpoint, :token_endpoint, :userinfo_endpoint

    def initialize(identifier:, secret: nil, redirect_uri:, authorization_endpoint:, token_endpoint:,
      userinfo_endpoint: nil, jwks_uri: nil)
      token_uri = URI.parse(token_endpoint.to_s)
      site = build_site(token_uri)

      super(
        identifier,
        secret,
        site: site,
        authorize_url: authorization_endpoint,
        token_url: token_endpoint,
        redirect_uri: redirect_uri,
        auth_scheme: :private_key_jwt
      )

      @authorization_endpoint = authorization_endpoint
      @token_endpoint = token_endpoint
      @userinfo_endpoint = userinfo_endpoint
      @jwks_uri = jwks_uri
      @authorization_code = nil
    end

    def identifier
      id
    end

    def identifier=(value)
      @id = value
    end

    def redirect_uri
      options[:redirect_uri]
    end

    def redirect_uri=(value)
      options[:redirect_uri] = value
    end

    def host
      URI.parse(site.to_s).host
    end

    def access_token!(client_auth_method = :jwt_bearer)
      unless client_auth_method == :jwt_bearer
        raise ConfigurationError, "Unsupported client_auth_method: #{client_auth_method}"
      end

      OmniauthOpenidFederation::Validators.validate_private_key!(private_key)

      oauth_token = auth_code.get_token(
        authorization_code,
        redirect_uri: redirect_uri,
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: build_client_assertion
      )

      OmniauthOpenidFederation::AccessToken.from_oauth2_token(
        oauth_token,
        strategy_options: instance_variable_get(:@strategy_options)
      )
    end

    private

    def build_site(token_uri)
      site = "#{token_uri.scheme}://#{token_uri.host}"
      site += ":#{token_uri.port}" if token_uri.port && !token_uri.default_port
      site
    end

    def build_client_assertion
      now = Time.now.to_i
      payload = {
        iss: identifier,
        sub: identifier,
        aud: token_endpoint.to_s,
        jti: SecureRandom.hex(16),
        iat: now,
        exp: now + CLIENT_ASSERTION_EXPIRATION_SECONDS
      }

      JWT.encode(payload, private_key, "RS256")
    end
  end
end

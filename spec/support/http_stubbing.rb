# Helper module to ensure all HTTP requests are stubbed
# This prevents tests from making real HTTP requests
module HttpStubbing
  def create_valid_entity_statement(issuer:, private_key: nil)
    private_key ||= OpenSSL::PKey::RSA.new(2048)
    public_key = private_key.public_key
    jwk = JWT::JWK.new(public_key)
    jwk_export = jwk.export

    payload = {
      iss: issuer,
      sub: issuer,
      iat: Time.now.to_i,
      exp: Time.now.to_i + 3600,
      jwks: {
        keys: [jwk_export]
      },
      metadata: {
        openid_provider: {
          issuer: issuer,
          authorization_endpoint: "#{issuer}/oauth2/authorize",
          token_endpoint: "#{issuer}/oauth2/token",
          userinfo_endpoint: "#{issuer}/oauth2/userinfo",
          jwks_uri: "#{issuer}/.well-known/jwks.json"
        }
      }
    }

    header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
    JWT.encode(payload, private_key, "RS256", header)
  end

  def stub_provider_endpoints(provider_issuer: "https://provider.example.com", jwks: nil, id_token: nil, access_token: "mock-access-token", entity_statement: nil)
    URI.parse(provider_issuer).host

    # Stub OpenID Connect discovery endpoint
    WebMock.stub_request(:get, "#{provider_issuer}/.well-known/openid-configuration")
      .to_return(
        status: 200,
        body: {
          issuer: provider_issuer,
          authorization_endpoint: "#{provider_issuer}/oauth2/authorize",
          token_endpoint: "#{provider_issuer}/oauth2/token",
          userinfo_endpoint: "#{provider_issuer}/oauth2/userinfo",
          jwks_uri: "#{provider_issuer}/.well-known/jwks.json",
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
          request_object_signing_alg_values_supported: ["RS256"],
          token_endpoint_auth_methods_supported: ["private_key_jwt"],
          token_endpoint_auth_signing_alg_values_supported: ["RS256"]
        }.to_json,
        headers: {"Content-Type" => "application/json"}
      )

    # Stub JWKS endpoint
    if jwks
      WebMock.stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(
          status: 200,
          body: jwks.to_json,
          headers: {"Content-Type" => "application/json"}
        )
    end

    # Stub token endpoint (used by oidc_client.access_token!)
    token_response = {
      access_token: access_token,
      token_type: "Bearer",
      expires_in: 3600
    }
    token_response[:id_token] = id_token if id_token

    WebMock.stub_request(:post, "#{provider_issuer}/oauth2/token")
      .to_return(
        status: 200,
        body: token_response.to_json,
        headers: {"Content-Type" => "application/json"}
      )

    # Stub authorization endpoint (in case it's accessed)
    WebMock.stub_request(:get, "#{provider_issuer}/oauth2/authorize")
      .to_return(status: 200, body: "", headers: {"Content-Type" => "text/html"})

    # Stub userinfo endpoint
    WebMock.stub_request(:get, "#{provider_issuer}/oauth2/userinfo")
      .to_return(status: 200, body: {}.to_json, headers: {"Content-Type" => "application/json"})

    # Stub signed JWKS endpoint
    WebMock.stub_request(:get, "#{provider_issuer}/.well-known/signed-jwks.json")
      .to_return(status: 200, body: "", headers: {"Content-Type" => "application/jwt"})

    # Stub entity statement endpoint with valid entity statement
    entity_statement ||= create_valid_entity_statement(issuer: provider_issuer)
    WebMock.stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
      .to_return(status: 200, body: entity_statement, headers: {"Content-Type" => "application/jwt"})
  end

  # Stub endpoints built from relative paths with a host
  # When tests use relative paths like "/oauth2/token" with host "provider.example.com",
  # the strategy builds full URLs like "https://provider.example.com/oauth2/token"
  def stub_relative_path_endpoints(host:, scheme: "https", port: nil)
    base_url = "#{scheme}://#{host}"
    base_url += ":#{port}" if port

    # Stub all common endpoints that might be built from relative paths
    endpoints = [
      "/oauth2/authorize",
      "/oauth2/token",
      "/oauth2/userinfo",
      "/.well-known/jwks.json",
      "/.well-known/signed-jwks.json",
      "/.well-known/openid-federation",
      "/.well-known/openid-configuration"
    ]

    endpoints.each do |path|
      full_url = "#{base_url}#{path}"
      method = path.include?("token") ? :post : :get
      if path == "/.well-known/openid-federation"
        # Return valid entity statement for federation endpoint
        entity_statement = create_valid_entity_statement(issuer: base_url)
        WebMock.stub_request(method, full_url)
          .to_return(status: 200, body: entity_statement, headers: {"Content-Type" => "application/jwt"})
      else
        WebMock.stub_request(method, full_url)
          .to_return(status: 200, body: "{}", headers: {"Content-Type" => "application/json"})
      end
    end
  end
end

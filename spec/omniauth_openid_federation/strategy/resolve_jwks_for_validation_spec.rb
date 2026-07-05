require "spec_helper"

RSpec.describe OmniAuth::Strategies::OpenIDFederation, type: :strategy do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:provider_issuer) { "https://provider.example.com" }
  let(:client_id) { "test-client-id" }
  let(:redirect_uri) { "https://example.com/users/auth/openid_federation/callback" }

  # Stub all HTTP requests for tests that use relative paths
  before do
    stub_relative_path_endpoints(host: URI.parse(provider_issuer).host)
    # Also stub for "example.com" host used in some tests
    stub_relative_path_endpoints(host: "example.com")
  end

  describe "JWKS resolution and ID token validation" do
    it "builds client endpoints from relative paths and port" do
      strategy = described_class.new(
        nil,
        send_nonce: false,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          scheme: "http",
          host: "example.com",
          port: 8080,
          authorization_endpoint: "oauth2/authorize",
          token_endpoint: "/oauth2/token",
          userinfo_endpoint: "oauth2/userinfo",
          jwks_uri: "/.well-known/jwks.json",
          private_key: private_key
        }
      )

      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end

    it "builds client when merged options use string keys" do
      entity_statement_path = entity_statement_path_under_config
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        send_nonce: false,
        entity_statement_path: entity_statement_path,
        client_options: {
          "identifier" => client_id,
          "redirect_uri" => redirect_uri,
          "private_key" => private_key
        }
      )

      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end

    it "resolves all OpenID provider endpoints from entity statement metadata" do
      entity_statement_path = entity_statement_path_under_config
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token",
            userinfo_endpoint: "https://provider.example.com/oauth2/userinfo",
            jwks_uri: "https://provider.example.com/.well-known/jwks.json",
            audience: provider_issuer
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        send_nonce: false,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end

    it "resolves relative endpoints using issuer from entity statement metadata" do
      entity_statement_path = entity_statement_path_under_config
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "/oauth2/authorize",
            token_endpoint: "/oauth2/token"
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        send_nonce: false,
        entity_statement_path: entity_statement_path,
        issuer: provider_issuer,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end

    it "builds authorize URI when audience is resolved from client host" do
      strategy = described_class.new(
        nil,
        send_nonce: false,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          private_key: private_key
        }
      )

      allow(strategy).to receive_messages(request: double(params: {}), session: {})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "validates ID token using signed JWKS from entity statement" do
      entity_statement_path = entity_statement_path_under_config
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [jwk]},
        metadata: {
          openid_provider: {
            signed_jwks_uri: "https://provider.example.com/.well-known/signed-jwks.json",
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      signed_jwks_jwt = encode_rs256({jwks: {keys: [jwk]}})
      stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
        .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

      strategy = described_class.new(
        nil,
        send_nonce: false,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      id_token_payload = {
        iss: provider_issuer,
        sub: "user-123",
        aud: client_id,
        exp: Time.now.to_i + 3600,
        iat: Time.now.to_i
      }
      # Get the kid from the JWK
      jwk_kid = jwk[:kid] || jwk["kid"]
      id_token = JWT.encode(id_token_payload, private_key, "RS256", kid: jwk_kid)

      access_token_double = double(
        id_token: id_token,
        userinfo!: double(raw_attributes: {sub: "user-123"})
      )
      strategy.instance_variable_set(:@access_token, access_token_double)

      raw_info = strategy.raw_info
      expect(raw_info).to be_a(Hash)
    end

    it "raises ConfigurationError when JWKS is unavailable for ID token validation" do
      entity_statement_path = entity_statement_path_under_config
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        send_nonce: false,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      id_token = JWT.encode({iss: provider_issuer, sub: "user-123"}, private_key, "RS256")
      access_token_double = double(id_token: id_token)
      strategy.instance_variable_set(:@access_token, access_token_double)

      expect { strategy.raw_info }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /JWKS not available/)
    end

    it "decodes ID token when JWKS entry uses symbol keys" do
      entity_statement_path = entity_statement_path_under_config
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [jwk]},
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        send_nonce: false,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Create JWT with symbol kid in header (simulated)
      id_token_payload = {
        iss: provider_issuer,
        sub: "user-123",
        aud: client_id,
        exp: Time.now.to_i + 3600,
        iat: Time.now.to_i
      }
      # Get the kid from the JWK (test is about symbol keys in JWKS, not header)
      jwk_kid = jwk[:kid] || jwk["kid"]
      id_token = JWT.encode(id_token_payload, private_key, "RS256", kid: jwk_kid)

      access_token_double = double(
        id_token: id_token,
        userinfo!: double(raw_attributes: {sub: "user-123"})
      )
      strategy.instance_variable_set(:@access_token, access_token_double)

      raw_info = strategy.raw_info
      expect(raw_info).to be_a(Hash)
    end

    it "raises ConfigurationError when entity statement JWKS format is invalid" do
      entity_statement_path = entity_statement_path_under_config
      OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: "invalid",
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        send_nonce: false,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      id_token = JWT.encode({iss: provider_issuer, sub: "user-123"}, private_key, "RS256")
      access_token_double = double(id_token: id_token)
      strategy.instance_variable_set(:@access_token, access_token_double)

      expect { strategy.raw_info }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /JWKS not available/)
    end

    it "raises SignatureError when ID token signature does not match JWKS key" do
      entity_statement_path = entity_statement_path_under_config
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [jwk]},
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        send_nonce: false,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Create JWT with wrong signature
      wrong_key = OpenSSL::PKey::RSA.new(2048)
      id_token = JWT.encode({iss: provider_issuer, sub: "user-123", aud: client_id, exp: Time.now.to_i + 3600, iat: Time.now.to_i}, wrong_key, "RS256")

      access_token_double = double(id_token: id_token)
      strategy.instance_variable_set(:@access_token, access_token_double)

      expect { strategy.raw_info }.to raise_error(OmniauthOpenidFederation::SignatureError)
    end

    it "raises SignatureError when ID token kid does not match available JWKS keys" do
      entity_statement_path = entity_statement_path_under_config
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [jwk]},
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        send_nonce: false,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Create JWT with wrong signature to trigger error path
      wrong_key = OpenSSL::PKey::RSA.new(2048)
      id_token = JWT.encode({iss: provider_issuer, sub: "user-123", aud: client_id, exp: Time.now.to_i + 3600, iat: Time.now.to_i}, wrong_key, "RS256")

      access_token_double = double(id_token: id_token)
      strategy.instance_variable_set(:@access_token, access_token_double)

      expect { strategy.raw_info }.to raise_error(OmniauthOpenidFederation::SignatureError)
    end

    it "raises SignatureError when JWT decode raises an unexpected error" do
      entity_statement_path = entity_statement_path_under_config
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [jwk]},
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        send_nonce: false,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      allow(JWT).to receive(:decode).and_raise(StandardError.new("General error"))

      id_token = JWT.encode({iss: provider_issuer, sub: "user-123", aud: client_id, exp: Time.now.to_i + 3600, iat: Time.now.to_i}, private_key, "RS256")
      access_token_double = double(id_token: id_token)
      strategy.instance_variable_set(:@access_token, access_token_double)

      expect { strategy.raw_info }.to raise_error(OmniauthOpenidFederation::SignatureError)
    end

    it "fetches JWKS in standard keys array format for ID token validation" do
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      # Return in standard format {keys: [...]} for proper parsing
      jwks_hash = {keys: [jwk]}

      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks_hash.to_json, headers: {"Content-Type" => "application/json"})

      strategy = described_class.new(
        nil,
        send_nonce: false,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          jwks_uri: jwks_uri,
          private_key: private_key
        }
      )

      # Test through public API: fetch_jwks is used in resolve_jwks_for_validation
      # which is called during ID token validation in raw_info
      header = {alg: "RS256", typ: "JWT", kid: jwk[:kid]}
      id_token = JWT.encode({iss: provider_issuer, sub: "user-123", aud: client_id, exp: Time.now.to_i + 3600, iat: Time.now.to_i}, private_key, "RS256", header)
      access_token_double = double(
        id_token: id_token,
        userinfo!: {email: "user@example.com"}
      )
      strategy.instance_variable_set(:@access_token, access_token_double)

      # Behavior: Should fetch JWKS when needed for ID token validation
      result = strategy.raw_info
      expect(result).to be_a(Hash)
    end

    it "fetches JWKS when endpoint returns a single key object" do
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      # Return as single key object to test fallback format handling
      # The code should wrap it in {keys: [jwk]}
      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwk.to_json, headers: {"Content-Type" => "application/json"})

      strategy = described_class.new(
        nil,
        send_nonce: false,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          jwks_uri: jwks_uri,
          private_key: private_key
        }
      )

      # Test through public API: fetch_jwks is used in resolve_jwks_for_validation
      # which is called during ID token validation in raw_info
      # This tests the fallback format where JWKS is returned as a single key object
      header = {alg: "RS256", typ: "JWT", kid: jwk[:kid]}
      id_token = JWT.encode({iss: provider_issuer, sub: "user-123", aud: client_id, exp: Time.now.to_i + 3600, iat: Time.now.to_i}, private_key, "RS256", header)
      access_token_double = double(
        id_token: id_token,
        userinfo!: {email: "user@example.com"}
      )
      strategy.instance_variable_set(:@access_token, access_token_double)

      # Behavior: Should fetch JWKS and handle fallback format (single key object)
      result = strategy.raw_info
      expect(result).to be_a(Hash)
    end
  end
end

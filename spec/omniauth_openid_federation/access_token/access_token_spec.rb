require "spec_helper"

RSpec.describe OpenIDConnect::AccessToken do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:entity_jwk) { JWT::JWK.new(public_key) }
  let(:client) { double("client", private_key: private_key) }
  let(:access_token) { described_class.new(access_token: "test-token", client: client) }

  let(:entity_jwks) do
    {
      "keys" => [entity_jwk.export.stringify_keys]
    }
  end

  let(:jwks_payload) do
    {
      keys: [
        {
          kty: "RSA",
          kid: "provider-key-1",
          use: "sig",
          n: "test-n",
          e: "AQAB"
        }
      ]
    }
  end

  let(:signed_jwks_jwt) do
    header = {
      alg: "RS256",
      typ: "JWT",
      kid: entity_jwk.export[:kid]
    }
    JWT.encode(jwks_payload, private_key, "RS256", header)
  end

  let(:id_token_jwt) do
    payload = {
      sub: "user123",
      iss: "https://provider.example.com",
      aud: "client123",
      exp: Time.now.to_i + 3600,
      iat: Time.now.to_i
    }
    header = {
      alg: "RS256",
      typ: "JWT",
      kid: entity_jwk.export[:kid]
    }
    JWT.encode(payload, private_key, "RS256", header)
  end

  before do
    # Stub all HTTP requests for tests that use relative paths
    stub_relative_path_endpoints(host: "provider.example.com")

    # Stub Devise constant if not defined
    stub_const("Devise", Class.new) unless defined?(Devise)

    # Mock Devise.omniauth_configs
    devise_configs = double("omniauth_configs")
    strategy_config = double(
      options: {
        client_options: {
          identifier: "client123",
          redirect_uri: "https://example.com/callback",
          host: "provider.example.com",
          jwks_uri: "/.well-known/jwks.json",
          private_key: private_key
        },
        entity_statement_path: nil
      }
    )
    allow(devise_configs).to receive(:fetch).with(:openid_federation).and_return(strategy_config)
    allow(devise_configs).to receive(:fetch).with(:openid_connect).and_return(strategy_config)
    allow(::Devise).to receive(:omniauth_configs).and_return(devise_configs)
  end

  describe "#resource_request" do
    context "with JWT response (200 status)" do
      it "decrypts and decodes JWT using signed JWKS when entity statement is configured" do
        # Create temporary entity statement file
        entity_statement_path = File.join(Dir.tmpdir, "entity_statement_#{SecureRandom.hex}.jwt")
        entity_statement_payload = {
          iss: "https://provider.example.com",
          sub: "https://provider.example.com",
          jwks: entity_jwks,
          metadata: {
            openid_provider: {
              signed_jwks_uri: "https://provider.example.com/.well-known/signed-jwks"
            }
          }
        }
        header = {alg: "RS256", typ: "JWT", kid: entity_jwk.export[:kid]}
        entity_statement = JWT.encode(entity_statement_payload, private_key, "RS256", header)
        File.write(entity_statement_path, entity_statement)

        # Mock Devise config with entity statement path
        devise_configs = double("omniauth_configs")
        strategy_config = double(
          options: {
            client_options: {
              identifier: "client123",
              redirect_uri: "https://example.com/callback",
              host: "provider.example.com",
              jwks_uri: "/.well-known/jwks.json",
              private_key: private_key
            },
            entity_statement_path: entity_statement_path
          }
        )
        allow(devise_configs).to receive(:fetch).with(:openid_federation).and_return(strategy_config)
        allow(devise_configs).to receive(:fetch).with(:openid_connect).and_return(strategy_config)
        allow(::Devise).to receive(:omniauth_configs).and_return(devise_configs)

        # Mock signed JWKS fetch
        stub_request(:get, "https://provider.example.com/.well-known/signed-jwks")
          .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

        # Encrypt ID token (create JWT from payload and encrypt)
        # For nested JWTs (signed then encrypted), we encrypt the signed JWT string
        id_token_payload = {
          sub: "user123",
          iss: "https://provider.example.com",
          aud: "client123",
          exp: Time.now.to_i + 3600,
          iat: Time.now.to_i
        }
        # First sign the JWT, then encrypt it
        signed_jwt = JWT.encode(id_token_payload, private_key, "RS256", {kid: entity_jwk.export[:kid]})
        # JWE.encrypt(plaintext, key, alg, enc)
        encrypted_token = JWE.encrypt(signed_jwt, public_key, alg: "RSA-OAEP", enc: "A128CBC-HS256")

        # Mock HTTP response
        status_obj = double("status", code: 200, success?: true)
        response = double("response", status: status_obj, body: encrypted_token)

        result = access_token.resource_request { response }

        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result["sub"]).to eq("user123")
        end
      ensure
        File.delete(entity_statement_path) if File.exist?(entity_statement_path)
      end

      it "falls back to standard JWKS when signed JWKS is not available" do
        # Mock Devise config without entity statement
        devise_configs = double("omniauth_configs")
        strategy_config = double(
          options: {
            client_options: {
              identifier: "client123",
              redirect_uri: "https://example.com/callback",
              host: "provider.example.com",
              jwks_uri: "https://provider.example.com/.well-known/jwks.json",
              private_key: private_key
            },
            entity_statement_path: nil
          }
        )
        allow(devise_configs).to receive(:fetch).with(:openid_federation).and_return(strategy_config)
        allow(devise_configs).to receive(:fetch).with(:openid_connect).and_return(strategy_config)
        allow(::Devise).to receive(:omniauth_configs).and_return(devise_configs)

        # Mock standard JWKS fetch
        stub_request(:get, "https://provider.example.com/.well-known/jwks.json")
          .to_return(status: 200, body: entity_jwks.to_json, headers: {"Content-Type" => "application/json"})

        # Encrypt ID token (create JWT from payload and encrypt)
        # For nested JWTs (signed then encrypted), we encrypt the signed JWT string
        id_token_payload = {
          sub: "user123",
          iss: "https://provider.example.com",
          aud: "client123",
          exp: Time.now.to_i + 3600,
          iat: Time.now.to_i
        }
        # First sign the JWT, then encrypt it
        signed_jwt = JWT.encode(id_token_payload, private_key, "RS256", {kid: entity_jwk.export[:kid]})
        # JWE.encrypt(plaintext, key, alg, enc)
        encrypted_token = JWE.encrypt(signed_jwt, public_key, alg: "RSA-OAEP", enc: "A128CBC-HS256")

        # Mock HTTP response
        status_obj = double("status", code: 200, success?: true)
        response = double("response", status: status_obj, body: encrypted_token)

        # Mock Jwks::Decode.jwt
        # Decode JWT to get payload (skip signature part)
        jwt_parts = id_token_jwt.split(".")
        decoded_payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
        allow(OmniauthOpenidFederation::Jwks::Decode).to receive(:jwt).and_return([decoded_payload])

        result = access_token.resource_request { response }

        expect(result).to be_a(Hash)
      end

      it "handles non-JWT response (JSON)" do
        json_response = {user_id: "123", name: "Test User"}.to_json

        status_obj = double("status", code: 200, success?: true)
        response = double("response", status: status_obj, body: json_response)

        result = access_token.resource_request { response }

        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result["user_id"]).to eq("123")
        end
      end

      it "handles path traversal in entity statement path" do
        devise_configs = double("omniauth_configs")
        strategy_config = double(
          options: {
            client_options: {
              identifier: "client123",
              redirect_uri: "https://example.com/callback",
              host: "provider.example.com",
              jwks_uri: "/.well-known/jwks.json",
              private_key: private_key
            },
            entity_statement_path: "../../../etc/passwd"
          }
        )
        allow(devise_configs).to receive(:fetch).with(:openid_federation).and_return(strategy_config)
        allow(devise_configs).to receive(:fetch).with(:openid_connect).and_return(strategy_config)
        allow(::Devise).to receive(:omniauth_configs).and_return(devise_configs)

        # Encrypt ID token (create JWT from payload and encrypt directly)
        # For encrypted tokens, we encrypt the signed JWT as plaintext
        id_token_payload = {
          sub: "user123",
          iss: "https://provider.example.com",
          aud: "client123",
          exp: Time.now.to_i + 3600,
          iat: Time.now.to_i
        }
        signed_jwt = JWT.encode(id_token_payload, private_key, "RS256", {kid: entity_jwk.export[:kid]})
        encrypted_token = JWE.encrypt(signed_jwt, public_key, alg: "RSA-OAEP", enc: "A128CBC-HS256")

        status_obj = double("status", code: 200, success?: true)
        response = double("response", status: status_obj, body: encrypted_token)

        # Should fall back to standard JWKS when path traversal is detected
        stub_request(:get, "https://provider.example.com/.well-known/jwks.json")
          .to_return(status: 200, body: entity_jwks.to_json, headers: {"Content-Type" => "application/json"})

        # Decode JWT to get payload (skip signature part)
        jwt_parts = id_token_jwt.split(".")
        decoded_payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
        allow(OmniauthOpenidFederation::Jwks::Decode).to receive(:jwt).and_return([decoded_payload])

        result = access_token.resource_request { response }

        expect(result).to be_a(Hash)
      end

      it "handles missing entity statement file" do
        devise_configs = double("omniauth_configs")
        strategy_config = double(
          options: {
            client_options: {
              identifier: "client123",
              redirect_uri: "https://example.com/callback",
              host: "provider.example.com",
              jwks_uri: "/.well-known/jwks.json",
              private_key: private_key
            },
            entity_statement_path: "/nonexistent/path.jwt"
          }
        )
        allow(devise_configs).to receive(:fetch).with(:openid_federation).and_return(strategy_config)
        allow(devise_configs).to receive(:fetch).with(:openid_connect).and_return(strategy_config)
        allow(::Devise).to receive(:omniauth_configs).and_return(devise_configs)

        # Encrypt ID token (create JWT from payload and encrypt directly)
        # For encrypted tokens, we encrypt the signed JWT as plaintext
        id_token_payload = {
          sub: "user123",
          iss: "https://provider.example.com",
          aud: "client123",
          exp: Time.now.to_i + 3600,
          iat: Time.now.to_i
        }
        signed_jwt = JWT.encode(id_token_payload, private_key, "RS256", {kid: entity_jwk.export[:kid]})
        encrypted_token = JWE.encrypt(signed_jwt, public_key, alg: "RSA-OAEP", enc: "A128CBC-HS256")

        status_obj = double("status", code: 200, success?: true)
        response = double("response", status: status_obj, body: encrypted_token)

        stub_request(:get, "https://provider.example.com/.well-known/jwks.json")
          .to_return(status: 200, body: entity_jwks.to_json, headers: {"Content-Type" => "application/json"})

        # Decode JWT to get payload (skip signature part)
        jwt_parts = id_token_jwt.split(".")
        decoded_payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
        allow(OmniauthOpenidFederation::Jwks::Decode).to receive(:jwt).and_return([decoded_payload])

        result = access_token.resource_request { response }

        expect(result).to be_a(Hash)
      end
    end

    context "with error status codes" do
      it "raises BadRequest on 400 status" do
        status_obj = double("status", code: 400, success?: false)
        response = double("response", status: status_obj, body: "Bad Request")

        expect { access_token.resource_request { response } }.to raise_error(
          OpenIDConnect::BadRequest
        )
      end

      it "raises Unauthorized on 401 status" do
        status_obj = double("status", code: 401, success?: false)
        response = double("response", status: status_obj, body: "Unauthorized")

        expect { access_token.resource_request { response } }.to raise_error(
          OpenIDConnect::Unauthorized
        )
      end

      it "raises Forbidden on 403 status" do
        status_obj = double("status", code: 403, success?: false)
        response = double("response", status: status_obj, body: "Forbidden")

        expect { access_token.resource_request { response } }.to raise_error(
          OpenIDConnect::Forbidden
        )
      end

      it "raises HttpError on other status codes" do
        status_obj = double("status", code: 500, success?: false)
        response = double("response", status: status_obj, body: "Internal Server Error")

        expect { access_token.resource_request { response } }.to raise_error(
          OpenIDConnect::HttpError
        )
      end
    end

    context "with openid_connect fallback" do
      it "falls back to openid_connect when openid_federation is not configured" do
        devise_configs = double("omniauth_configs")
        strategy_config = double(
          options: {
            client_options: {
              identifier: "client123",
              redirect_uri: "https://example.com/callback",
              host: "provider.example.com",
              jwks_uri: "/.well-known/jwks.json",
              private_key: private_key
            },
            entity_statement_path: nil
          }
        )
        allow(devise_configs).to receive(:fetch).with(:openid_federation).and_raise(KeyError)
        allow(devise_configs).to receive(:fetch).with(:openid_connect).and_return(strategy_config)
        allow(::Devise).to receive(:omniauth_configs).and_return(devise_configs)

        json_response = {user_id: "123"}.to_json
        status_obj = double("status", code: 200, success?: true)
        response = double("response", status: status_obj, body: json_response)

        result = access_token.resource_request { response }

        expect(result).to be_a(Hash)
      end
    end

    context "with jwks_uri as full URL" do
      it "parses full URL jwks_uri correctly" do
        # Stub Devise constant if not defined
        stub_const("Devise", Class.new) unless defined?(Devise)

        devise_configs = double("omniauth_configs")
        strategy_config = double(
          options: {
            client_options: {
              identifier: "client123",
              redirect_uri: "https://example.com/callback",
              jwks_uri: "https://provider.example.com/.well-known/jwks.json",
              private_key: private_key
            },
            entity_statement_path: nil
          }
        )
        allow(devise_configs).to receive(:fetch).with(:openid_federation).and_return(strategy_config)
        allow(devise_configs).to receive(:fetch).with(:openid_connect).and_return(strategy_config)
        allow(::Devise).to receive(:omniauth_configs).and_return(devise_configs)

        json_response = {user_id: "123"}.to_json
        status_obj = double("status", code: 200, success?: true)
        response = double("response", status: status_obj, body: json_response)

        result = access_token.resource_request { response }

        expect(result).to be_a(Hash)
      end
    end
  end
end

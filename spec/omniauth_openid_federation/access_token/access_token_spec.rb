require "spec_helper"

RSpec.describe OmniauthOpenidFederation::AccessToken do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:access_token) { build_token_client }
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
  let(:public_key) { private_key.public_key }
  let(:entity_jwk) { JWT::JWK.new(public_key) }
  let(:access_token) { build_token_client }

  let(:entity_jwks) do
    {
      "keys" => [entity_jwk.export.stringify_keys]
    }
  end

  let(:jwks_payload) do
    {keys: [entity_jwk.export]}
  end

  def build_token_client(strategy_options = {})
    default_client_options = {
      identifier: "client123",
      redirect_uri: "https://example.com/callback",
      host: "provider.example.com",
      jwks_uri: "/.well-known/jwks.json",
      private_key: private_key
    }
    merged_client_options = default_client_options.merge(strategy_options[:client_options] || {})
    merged_options = {
      client_options: merged_client_options,
      entity_statement_path: nil
    }.merge(strategy_options)

    jwks_uri_value = merged_client_options[:jwks_uri].to_s
    jwks_uri = if jwks_uri_value.start_with?("http")
      URI(jwks_uri_value)
    else
      URI("https://provider.example.com#{jwks_uri_value}")
    end

    client = double(private_key: private_key, jwks_uri: jwks_uri)
    client.instance_variable_set(:@strategy_options, merged_options)
    described_class.new(access_token: "test-token", client: client)
  end

  before do
    stub_relative_path_endpoints(host: "provider.example.com")
  end

  describe "#resource_request" do
    context "with JWT response (200 status)" do
      it "decrypts and decodes JWT using signed JWKS when entity statement is configured" do
        entity_statement_path = entity_statement_path_under_config
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
        entity_statement = encode_entity_statement(entity_statement_payload)
        File.write(entity_statement_path, entity_statement)

        token = build_token_client(entity_statement_path: entity_statement_path)

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
        encrypted_token = OmniauthOpenidFederation::Jwe.encrypt(signed_jwt, public_key, alg: "RSA-OAEP", enc: "A128CBC-HS256")

        # Mock HTTP response
        status_obj = double("status", code: 200, success?: true)
        response = double("response", status: status_obj, body: encrypted_token)

        result = token.resource_request { response }

        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result["sub"]).to eq("user123")
        end
      end

      it "falls back to standard JWKS when signed JWKS is not available" do
        token = build_token_client(
          client_options: {
            jwks_uri: "https://provider.example.com/.well-known/jwks.json"
          }
        )

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
        encrypted_token = OmniauthOpenidFederation::Jwe.encrypt(signed_jwt, public_key, alg: "RSA-OAEP", enc: "A128CBC-HS256")

        # Mock HTTP response
        status_obj = double("status", code: 200, success?: true)
        response = double("response", status: status_obj, body: encrypted_token)

        # Mock Jwks::Decode.jwt
        # Decode JWT to get payload (skip signature part)
        jwt_parts = id_token_jwt.split(".")
        decoded_payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
        allow(OmniauthOpenidFederation::Jwks::Decode).to receive(:jwt).and_return([decoded_payload])

        result = token.resource_request { response }

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
        token = build_token_client(entity_statement_path: "../../../etc/passwd")
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
        encrypted_token = OmniauthOpenidFederation::Jwe.encrypt(signed_jwt, public_key, alg: "RSA-OAEP", enc: "A128CBC-HS256")

        status_obj = double("status", code: 200, success?: true)
        response = double("response", status: status_obj, body: encrypted_token)

        # Should fall back to standard JWKS when path traversal is detected
        stub_request(:get, "https://provider.example.com/.well-known/jwks.json")
          .to_return(status: 200, body: entity_jwks.to_json, headers: {"Content-Type" => "application/json"})

        # Decode JWT to get payload (skip signature part)
        jwt_parts = id_token_jwt.split(".")
        decoded_payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
        allow(OmniauthOpenidFederation::Jwks::Decode).to receive(:jwt).and_return([decoded_payload])

        result = token.resource_request { response }

        expect(result).to be_a(Hash)
      end

      it "handles missing entity statement file" do
        token = build_token_client(entity_statement_path: "/nonexistent/path.jwt")
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
        encrypted_token = OmniauthOpenidFederation::Jwe.encrypt(signed_jwt, public_key, alg: "RSA-OAEP", enc: "A128CBC-HS256")

        status_obj = double("status", code: 200, success?: true)
        response = double("response", status: status_obj, body: encrypted_token)

        stub_request(:get, "https://provider.example.com/.well-known/jwks.json")
          .to_return(status: 200, body: entity_jwks.to_json, headers: {"Content-Type" => "application/json"})

        # Decode JWT to get payload (skip signature part)
        jwt_parts = id_token_jwt.split(".")
        decoded_payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
        allow(OmniauthOpenidFederation::Jwks::Decode).to receive(:jwt).and_return([decoded_payload])

        result = token.resource_request { response }

        expect(result).to be_a(Hash)
      end
    end

    context "with error status codes" do
      it "raises BadRequest on 400 status" do
        status_obj = double("status", code: 400, success?: false)
        response = double("response", status: status_obj, body: "Bad Request")

        expect { access_token.resource_request { response } }.to raise_error(
          OmniauthOpenidFederation::BadRequest
        )
      end

      it "raises Unauthorized on 401 status" do
        status_obj = double("status", code: 401, success?: false)
        response = double("response", status: status_obj, body: "Unauthorized")

        expect { access_token.resource_request { response } }.to raise_error(
          OmniauthOpenidFederation::Unauthorized
        )
      end

      it "raises Forbidden on 403 status" do
        status_obj = double("status", code: 403, success?: false)
        response = double("response", status: status_obj, body: "Forbidden")

        expect { access_token.resource_request { response } }.to raise_error(
          OmniauthOpenidFederation::Forbidden
        )
      end

      it "raises HttpError on other status codes" do
        status_obj = double("status", code: 500, success?: false)
        response = double("response", status: status_obj, body: "Internal Server Error")

        expect { access_token.resource_request { response } }.to raise_error(
          OmniauthOpenidFederation::HttpError
        )
      end
    end

    context "with plain JSON response" do
      it "parses JSON when federation JWT handling is not required" do
        json_response = {user_id: "123"}.to_json
        status_obj = double("status", code: 200, success?: true)
        response = double("response", status: status_obj, body: json_response)

        result = access_token.resource_request { response }

        expect(result).to be_a(Hash)
      end
    end

    context "with jwks_uri as full URL" do
      it "parses full URL jwks_uri correctly" do
        token = build_token_client(
          client_options: {
            jwks_uri: "https://provider.example.com/.well-known/jwks.json"
          }
        )

        json_response = {user_id: "123"}.to_json
        status_obj = double("status", code: 200, success?: true)
        response = double("response", status: status_obj, body: json_response)

        result = token.resource_request { response }

        expect(result).to be_a(Hash)
      end
    end
  end
end

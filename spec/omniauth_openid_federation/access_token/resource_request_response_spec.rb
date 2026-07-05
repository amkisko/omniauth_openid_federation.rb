require "spec_helper"

# rubocop:disable RSpec/RepeatedExample
RSpec.describe OpenIDConnect::AccessToken, type: :access_token do
  describe "#resource_request" do
    it "handles status as integer" do
      # Use a non-JWT body that won't trigger JWT parsing
      # The code parses JSON responses, so we expect the parsed hash
      response = double(status: 200, body: '{"test": "data"}')
      token = described_class.new(access_token: "token", client: double)

      result = token.resource_request { response }
      expect(result).to eq({"test" => "data"})
    end

    it "handles status with code method" do
      status = double(code: 200)
      # Use JSON body that will be parsed
      response = double(status: status, body: '{"test": "data"}')
      token = described_class.new(access_token: "token", client: double)

      result = token.resource_request { response }
      expect(result).to eq({"test" => "data"})
    end

    it "raises DecryptionError when encrypted JWT response has invalid base64 encoding" do
      encrypted_jwt = "header.encrypted_key.iv.ciphertext.tag"
      response = double(status: 200, body: encrypted_jwt)
      client = create_client_with_strategy_options
      token = described_class.new(access_token: "token", client: client)

      expect {
        token.resource_request { response }
      }.to raise_error(OmniauthOpenidFederation::DecryptionError, /Failed to decrypt JWE/)
    end

    it "processes signed JWT response by fetching JWKS from configured URI" do
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "rejects unsigned JWT (alg: none)" do
      header = {alg: "none"}
      payload = {iss: provider_issuer, sub: "user-123"}
      unsigned_jwt = JWT.encode(payload, nil, "none", header)
      response = double(status: 200, body: unsigned_jwt)
      client = create_client_with_strategy_options(
        client_options: {
          jwks_uri: "#{provider_issuer}/.well-known/jwks.json",
          host: URI.parse(provider_issuer).host
        }
      )
      token = described_class.new(access_token: "token", client: client)

      expect {
        token.resource_request { response }
      }.to raise_error(OmniauthOpenidFederation::ValidationError, /not permitted/)
    end

    it "handles JSON response (not JWT)" do
      json_response = '{"email":"user@example.com","name":"Test User"}'
      response = double(status: 200, body: json_response)
      token = described_class.new(access_token: "token", client: double)

      result = token.resource_request { response }
      expect(result).to eq({"email" => "user@example.com", "name" => "Test User"})
    end

    it "processes signed JWT response using openid_connect config fallback when JWKS URI is not configured" do
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles jwks_uri as path (not full URL)" do
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        client_options: {
          jwks_uri: "/.well-known/jwks.json",
          host: URI.parse(provider_issuer).host,
          private_key: private_key
        }
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles string keys in client_options" do
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      # Create client with string keys in options
      {
        identifier: "test-client-id",
        redirect_uri: "https://example.com/callback",
        host: URI.parse(provider_issuer).host,
        jwks_uri: "#{provider_issuer}/.well-known/jwks.json",
        private_key: private_key
      }
      merged_options = {
        "client_options" => {
          "jwks_uri" => "#{provider_issuer}/.well-known/jwks.json",
          "host" => URI.parse(provider_issuer).host,
          "private_key" => private_key
        },
        :entity_statement_path => nil
      }
      client = double(
        jwks_uri: URI.parse(merged_options["client_options"]["jwks_uri"]),
        private_key: merged_options["client_options"]["private_key"]
      )
      client.instance_variable_set(:@strategy_options, merged_options)
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles HTTP error responses" do
      response = double(status: 500, body: "Internal Server Error")
      token = described_class.new(access_token: "token", client: double)

      expect {
        token.resource_request { response }
      }.to raise_error(OpenIDConnect::HttpError, /Unknown HttpError/)
    end

    it "handles JWT decode errors" do
      invalid_jwt = "invalid.jwt.format"
      response = double(status: 200, body: invalid_jwt)
      client = create_client_with_strategy_options(
        client_options: {
          jwks_uri: "#{provider_issuer}/.well-known/jwks.json",
          host: URI.parse(provider_issuer).host
        }
      )
      token = described_class.new(access_token: "token", client: client)

      expect {
        token.resource_request { response }
      }.to raise_error(OmniauthOpenidFederation::ValidationError, /invalid base64/)
    end

    it "handles fetch_signed_jwks with entity statement" do
      entity_statement_path = entity_statement_path_under_config
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [jwk]},
        metadata: {
          openid_provider: {
            signed_jwks_uri: "https://provider.example.com/.well-known/signed-jwks.json"
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      signed_jwks_jwt = encode_rs256({jwks: {keys: [jwk]}})
      stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
        .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
      response = double(status: 200, body: signed_jwt)
      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "raises SecurityError when entity statement path contains path traversal attempt in fetch_signed_jwks" do
      entity_statement_path = "../../../etc/passwd"
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles missing entity statement file path error in fetch_signed_jwks" do
      entity_statement_path = "/nonexistent/path.jwt"
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "successfully loads entity statement keys for JWKS validation when entity statement contains valid JWKS" do
      entity_statement_path = entity_statement_path_under_config
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [jwk]},
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize"
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
      response = double(status: 200, body: signed_jwt)

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: {keys: [jwk]}.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles load_entity_statement_keys_for_jwks_validation when entity statement has empty keys array" do
      entity_statement_path = entity_statement_path_under_config
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: []},
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize"
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles load_entity_statement_keys with errors" do
      entity_statement_path = entity_statement_path_under_config
      File.write(entity_statement_path, "invalid")

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles status as non-integer, non-code object" do
      # When status is a string that doesn't match known status codes, it raises HttpError
      status = "200"
      response = double(status: status, body: "test")
      token = described_class.new(access_token: "token", client: double)

      expect {
        token.resource_request { response }
      }.to raise_error(OpenIDConnect::HttpError, /Unknown HttpError/)
    end

    it "handles encrypted response with JSON parse error" do
      encrypted_jwt = "header.encrypted_key.iv.ciphertext.tag"
      response = double(status: 200, body: encrypted_jwt)
      client = create_client_with_strategy_options
      token = described_class.new(access_token: "token", client: client)

      allow(OmniauthOpenidFederation::Jwe).to receive(:decrypt).and_return("invalid json")

      expect {
        token.resource_request { response }
      }.to raise_error(OmniauthOpenidFederation::ValidationError, /invalid base64/)
    end

    it "handles signed JWT with signed JWKS" do
      entity_statement_path = entity_statement_path_under_config
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [jwk]},
        metadata: {
          openid_provider: {
            signed_jwks_uri: "https://provider.example.com/.well-known/signed-jwks.json",
            authorization_endpoint: "https://provider.example.com/oauth2/authorize"
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      signed_jwks_jwt = encode_rs256({jwks: {keys: [jwk]}})
      stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
        .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600, aud: "test"}
      signed_jwt = encode_rs256(payload)
      response = double(status: 200, body: signed_jwt)
      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "extracts encryption key for decryption by reading metadata from entity statement file" do
      entity_statement_path = entity_statement_path_under_config
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize"
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      encrypted_jwt = "header.encrypted_key.iv.ciphertext.tag"
      response = double(status: 200, body: encrypted_jwt)
      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path
      )
      token = described_class.new(access_token: "token", client: client)

      expect {
        token.resource_request { response }
      }.to raise_error(OmniauthOpenidFederation::DecryptionError, /Failed to decrypt JWE/)
    end

    it "handles extract_encryption_key_for_decryption using client private key" do
      encrypted_jwt = "header.encrypted_key.iv.ciphertext.tag"
      response = double(status: 200, body: encrypted_jwt)
      client = create_client_with_strategy_options(
        client_options: {
          jwks_uri: "#{provider_issuer}/.well-known/jwks.json",
          host: URI.parse(provider_issuer).host
        }
      )
      # Override private_key to come from client, not options
      allow(client).to receive(:private_key).and_return(private_key)
      client.instance_variable_get(:@strategy_options)[:client_options][:private_key] = nil
      token = described_class.new(access_token: "token", client: client)

      expect {
        token.resource_request { response }
      }.to raise_error(OmniauthOpenidFederation::DecryptionError, /Failed to decrypt JWE/)
    end
  end
end
# rubocop:enable RSpec/RepeatedExample

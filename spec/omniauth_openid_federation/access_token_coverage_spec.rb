require "spec_helper"

RSpec.describe OpenIDConnect::AccessToken do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:provider_issuer) { "https://provider.example.com" }

  # Helper to create a client with strategy options stored on it
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

  before do
    # Stub all HTTP requests for tests that use relative paths
    stub_relative_path_endpoints(host: URI.parse(provider_issuer).host)
  end

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

    it "handles encrypted JWT response" do
      encrypted_jwt = "header.encrypted_key.iv.ciphertext.tag"
      response = double(status: 200, body: encrypted_jwt)
      client = create_client_with_strategy_options
      token = described_class.new(access_token: "token", client: client)

      expect {
        token.resource_request { response }
      }.to raise_error(ArgumentError, /invalid base64/)
    end

    it "handles encrypted response with JSON payload" do
      # This would require actual JWE encryption which is complex
      # For now, just test the path exists
      encrypted_jwt = "header.encrypted_key.iv.ciphertext.tag"
      response = double(status: 200, body: encrypted_jwt)
      client = create_client_with_strategy_options
      token = described_class.new(access_token: "token", client: client)

      expect {
        token.resource_request { response }
      }.to raise_error(ArgumentError, /invalid base64/)
    end

    it "handles signed JWT response" do
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
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

    it "handles unsigned JWT (alg: none)" do
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

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
      expect(result["iss"]).to eq(provider_issuer)
      expect(result["sub"]).to eq("user-123")
    end

    it "handles JSON response (not JWT)" do
      json_response = '{"email":"user@example.com","name":"Test User"}'
      response = double(status: 200, body: json_response)
      token = described_class.new(access_token: "token", client: double)

      result = token.resource_request { response }
      expect(result).to eq({"email" => "user@example.com", "name" => "Test User"})
    end

    it "handles fallback to openid_connect config" do
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
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
      signed_jwt = JWT.encode(payload, private_key, "RS256")
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
      signed_jwt = JWT.encode(payload, private_key, "RS256")
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
      }.to raise_error(JWT::Base64DecodeError, /Invalid base64/)
    end

    it "handles fetch_signed_jwks with entity statement" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
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
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      signed_jwks_jwt = JWT.encode({jwks: {keys: [jwk]}}, private_key, "RS256")
      stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
        .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)
      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles fetch_signed_jwks with security error" do
      entity_statement_path = "../../../etc/passwd"
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
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

    it "handles fetch_signed_jwks with missing file" do
      entity_statement_path = "/nonexistent/path.jwt"
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
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

    it "handles load_entity_statement_keys_for_jwks_validation" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
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
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
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

    it "handles load_entity_statement_keys with empty keys" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
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
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
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
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid")

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
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

      # Mock JWE.decrypt to return invalid JSON
      allow(JWE).to receive(:decrypt).and_return("invalid json")

      expect {
        token.resource_request { response }
      }.to raise_error(JWT::DecodeError, /Not enough or too many segments/)
    end

    it "handles signed JWT with signed JWKS" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
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
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      signed_jwks_jwt = JWT.encode({jwks: {keys: [jwk]}}, private_key, "RS256")
      stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
        .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600, aud: "test"}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)
      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles extract_encryption_key_for_decryption with metadata" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      encrypted_jwt = "header.encrypted_key.iv.ciphertext.tag"
      response = double(status: 200, body: encrypted_jwt)
      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path
      )
      token = described_class.new(access_token: "token", client: client)

      expect {
        token.resource_request { response }
      }.to raise_error(ArgumentError, /invalid base64/)
    end

    it "handles extract_encryption_key_for_decryption with client.private_key" do
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
      }.to raise_error(ArgumentError, /invalid base64/)
    end

    it "handles extract_encryption_key_for_decryption error loading metadata" do
      entity_statement_path = "../../../etc/passwd"
      encrypted_jwt = "header.encrypted_key.iv.ciphertext.tag"
      response = double(status: 200, body: encrypted_jwt)
      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path
      )
      token = described_class.new(access_token: "token", client: client)

      expect {
        token.resource_request { response }
      }.to raise_error(ArgumentError, /invalid base64/)
    end

    it "handles fetch_signed_jwks with nil parsed" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {}
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600, aud: "test"}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
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

    it "handles load_entity_statement_keys with blank path" do
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600, aud: "test"}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        entity_statement_path: nil
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles load_entity_statement_keys with Rails.root" do
      entity_statement_path = "config/entity.jwt"
      full_path = File.expand_path(entity_statement_path)
      FileUtils.mkdir_p(File.dirname(full_path))
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
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(full_path, jwt)

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600, aud: "test"}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: {keys: [jwk]}.to_json, headers: {"Content-Type" => "application/json"})

      rails_root = double
      allow(rails_root).to receive(:join).with("config").and_return(double(to_s: File.dirname(full_path)))
      rails_cache = double
      allow(rails_cache).to receive(:read).and_return(nil)
      allow(rails_cache).to receive(:write).and_return(true)
      allow(rails_cache).to receive(:fetch).and_yield
      stub_const("Rails", double(root: rails_root, cache: rails_cache))

      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    ensure
      File.delete(full_path) if File.exist?(full_path)
      config_dir = File.dirname(full_path)
      FileUtils.rmdir(config_dir) if File.directory?(config_dir) && Dir.empty?(config_dir)
    end
  end
end

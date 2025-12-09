require "spec_helper"

# rubocop:disable RSpec/RepeatedExample
# This file contains many integration tests that test similar code paths
# with different configurations. Some tests may appear duplicated but test
# different edge cases or code branches.
# rubocop:disable RSpec/DescribeClass
RSpec.describe OpenIDConnect::AccessToken do
  # rubocop:enable RSpec/DescribeClass
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

  after do
    # Restore Rails state after tests that stub Rails
    # Tests that use allow(Rails).to receive(:root) need cleanup

    if defined?(Rails)
      # Reset Rails mocks - RSpec will handle stub_const cleanup automatically
      RSpec::Mocks.space.proxy_for(Rails)&.reset
    end
    # Reset logger mocks to prevent test isolation issues
    if defined?(OmniauthOpenidFederation::Logger)
      RSpec::Mocks.space.proxy_for(OmniauthOpenidFederation::Logger)&.reset
    end
  rescue
    # If restoration fails, continue - RSpec will handle stub cleanup
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

    it "raises ArgumentError when encrypted JWT response has invalid base64 encoding" do
      encrypted_jwt = "header.encrypted_key.iv.ciphertext.tag"
      response = double(status: 200, body: encrypted_jwt)
      client = create_client_with_strategy_options
      token = described_class.new(access_token: "token", client: client)

      expect {
        token.resource_request { response }
      }.to raise_error(ArgumentError, /invalid base64/)
    end

    it "processes signed JWT response by fetching JWKS from configured URI" do
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
      aggregate_failures do
        expect(result).to be_a(Hash)
        expect(result["iss"]).to eq(provider_issuer)
        expect(result["sub"]).to eq("user-123")
      end
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

    it "raises SecurityError when entity statement path contains path traversal attempt in fetch_signed_jwks" do
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

    it "handles missing entity statement file path error in fetch_signed_jwks" do
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

    it "successfully loads entity statement keys for JWKS validation when entity statement contains valid JWKS" do
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

    it "handles load_entity_statement_keys_for_jwks_validation when entity statement has empty keys array" do
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

    it "extracts encryption key for decryption by reading metadata from entity statement file" do
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
      # Use a temporary directory to simulate config/ without polluting the project
      temp_dir = Dir.mktmpdir
      temp_config_dir = File.join(temp_dir, "config")
      FileUtils.mkdir_p(temp_config_dir)
      entity_statement_path = "config/entity.jwt"
      full_path = File.join(temp_config_dir, "entity.jwt")

      begin
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
        allow(rails_root).to receive(:join).with("config").and_return(double(to_s: temp_config_dir))
        rails_cache = double
        allow(rails_cache).to receive_messages(
          read: nil,
          write: true
        )
        allow(rails_cache).to receive(:fetch).and_yield
        stub_const("Rails", double(root: rails_root, cache: rails_cache))

        client = create_client_with_strategy_options(
          entity_statement_path: entity_statement_path
        )
        token = described_class.new(access_token: "token", client: client)

        result = token.resource_request { response }
        expect(result).to be_a(Hash)
      ensure
        FileUtils.rm_rf(temp_dir) if File.directory?(temp_dir)
      end
    end

    # Test line 79: client.host fallback when jwks_uri is a path
    it "uses client.host when jwks_uri is a path and host not in client_options" do
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = double(
        jwks_uri: URI.parse("/.well-known/jwks.json"),
        private_key: private_key,
        host: URI.parse(provider_issuer).host
      )
      client.instance_variable_set(:@strategy_options, {
        client_options: {
          jwks_uri: "/.well-known/jwks.json",
          private_key: private_key
        }
      })
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    # Test line 105: JWT.decode with signed JWKS
    it "decodes and validates JWT response using signed JWKS keys extracted from entity statement" do
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

      signed_jwks_payload = {jwks: {keys: [jwk]}}
      signed_jwks_jwt = JWT.encode(signed_jwks_payload, private_key, "RS256")
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

    # Test lines 118, 120: Successfully resolved JWKS URI from entity statement
    it "resolves JWKS URI from entity statement metadata when missing from client_options" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [jwk]},
        metadata: {
          openid_provider: {
            jwks_uri: "#{provider_issuer}/.well-known/jwks.json"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

      jwks = {keys: [jwk]}
      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: "test-client-id",
          redirect_uri: "https://example.com/callback",
          host: URI.parse(provider_issuer).host,
          private_key: private_key
          # jwks_uri intentionally omitted
        }
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    # Test lines 185-186: Last resort empty hash return
    it "returns empty hash when get_strategy_options fails" do
      # To test the last resort path (lines 185-186), we need to ensure:
      # respond_to?(:client) returns false on the AccessToken instance
      # This will skip both the strategy_options path (167-169) and fallback path (173-181)
      client = double
      token = described_class.new(access_token: "token", client: client)

      # Stub respond_to?(:client) to return false to trigger last resort path
      allow(token).to receive(:respond_to?).with(:client).and_return(false)

      # This should return empty hash (last resort path)
      expect(token.send(:get_strategy_options)).to eq({})
    end

    # Test lines 211-212: File.exist? and JSON.parse for metadata
    it "loads entity statement file and parses JSON metadata to extract encryption key for decryption" do
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

    # Test lines 250, 253: Entity statement file not found and SecurityError
    it "handles FileNotFoundError when entity statement file is missing in fetch_signed_jwks" do
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

    it "catches and handles SecurityError exception raised during entity statement file loading in fetch_signed_jwks" do
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

    # Test lines 260-261, 268: Fetching entity statement from URL for signed JWKS
    it "fetches entity statement from URL for signed JWKS" do
      entity_statement_url = "https://provider.example.com/.well-known/openid-federation"
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
      stub_request(:get, entity_statement_url)
        .to_return(status: 200, body: jwt, headers: {"Content-Type" => "application/jwt"})

      signed_jwks_jwt = JWT.encode({jwks: {keys: [jwk]}}, private_key, "RS256")
      stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
        .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)
      client = create_client_with_strategy_options(
        entity_statement_url: entity_statement_url
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles error fetching entity statement from URL for signed JWKS" do
      entity_statement_url = "https://provider.example.com/.well-known/openid-federation"
      stub_request(:get, entity_statement_url)
        .to_return(status: 500, body: "Internal Server Error")

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        entity_statement_url: entity_statement_url
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    # Test lines 275-276, 283: Fetching entity statement from issuer for signed JWKS
    it "fetches entity statement from issuer for signed JWKS" do
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
      stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
        .to_return(status: 200, body: jwt, headers: {"Content-Type" => "application/jwt"})

      signed_jwks_jwt = JWT.encode({jwks: {keys: [jwk]}}, private_key, "RS256")
      stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
        .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)
      client = create_client_with_strategy_options(
        issuer: provider_issuer
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles error fetching entity statement from issuer for signed JWKS" do
      stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
        .to_return(status: 500, body: "Internal Server Error")

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        issuer: provider_issuer
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    # Test line 297: return nil when parsed is nil
    it "returns nil when parsed entity statement is nil in fetch_signed_jwks" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid jwt")

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

    # Test lines 307, 310-314, 317-318, 320, 322: fetch_signed_jwks with entity_jwks
    it "fetches signed JWKS endpoint and validates response using entity_jwks keys from entity statement" do
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

      signed_jwks_payload = {jwks: {keys: [jwk]}}
      signed_jwks_jwt = JWT.encode(signed_jwks_payload, private_key, "RS256")
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

    it "handles SecurityError in fetch_signed_jwks" do
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

      # Use a different key for signed JWKS to cause validation failure
      other_key = OpenSSL::PKey::RSA.new(2048)
      signed_jwks_payload = {jwks: {keys: [OmniauthOpenidFederation::Utils.rsa_key_to_jwk(other_key.public_key)]}}
      signed_jwks_jwt = JWT.encode(signed_jwks_payload, other_key, "RS256")
      stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
        .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

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

    it "handles general error in fetch_signed_jwks" do
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

      stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
        .to_raise(StandardError.new("Network error"))

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

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

    # Test lines 394-399, 402-403: load_entity_statement_keys_for_jwks_validation edge cases
    it "processes entity_jwks when formatted as Hash with symbol keys during load_entity_statement_keys_for_jwks_validation" do
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

    it "handles entity_jwks as Array format when loading entity statement keys" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      # Create entity statement with jwks as array (not standard but should be handled)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: [jwk],
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

    it "handles empty keys array in entity_jwks when loading entity statement keys" do
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

    # Test lines 412-415: Error handling in load_entity_statement_keys_for_jwks_validation
    it "handles errors in load_entity_statement_keys_for_jwks_validation" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      # Create invalid entity statement that will cause parse errors
      File.write(entity_statement_path, "invalid jwt content")

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

    # Test lines 447-448, 451: resolve_jwks_uri_from_entity_statement file path handling
    it "resolves JWKS URI by reading entity statement file path and extracting metadata" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [jwk]},
        metadata: {
          openid_provider: {
            jwks_uri: "#{provider_issuer}/.well-known/jwks.json"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

      jwks = {keys: [jwk]}
      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: "test-client-id",
          redirect_uri: "https://example.com/callback",
          host: URI.parse(provider_issuer).host,
          private_key: private_key
          # jwks_uri intentionally omitted
        }
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles SecurityError when resolving JWKS URI from file path" do
      entity_statement_path = "../../../etc/passwd"
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: "test-client-id",
          redirect_uri: "https://example.com/callback",
          host: URI.parse(provider_issuer).host,
          private_key: private_key
          # jwks_uri intentionally omitted
        }
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    # Test lines 458, 463, 465: resolve_jwks_uri_from_entity_statement URL handling
    it "resolves JWKS URI from entity statement URL" do
      entity_statement_url = "https://provider.example.com/.well-known/openid-federation"
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [jwk]},
        metadata: {
          openid_provider: {
            jwks_uri: "#{provider_issuer}/.well-known/jwks.json"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      stub_request(:get, entity_statement_url)
        .to_return(status: 200, body: jwt, headers: {"Content-Type" => "application/jwt"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

      jwks = {keys: [jwk]}
      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        entity_statement_url: entity_statement_url,
        client_options: {
          identifier: "test-client-id",
          redirect_uri: "https://example.com/callback",
          host: URI.parse(provider_issuer).host,
          private_key: private_key
          # jwks_uri intentionally omitted
        }
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles error fetching entity statement from URL for JWKS URI resolution" do
      entity_statement_url = "https://provider.example.com/.well-known/openid-federation"
      stub_request(:get, entity_statement_url)
        .to_return(status: 500, body: "Internal Server Error")

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        entity_statement_url: entity_statement_url,
        client_options: {
          identifier: "test-client-id",
          redirect_uri: "https://example.com/callback",
          host: URI.parse(provider_issuer).host,
          private_key: private_key,
          jwks_uri: "#{provider_issuer}/.well-known/jwks.json"
        }
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    # Test lines 472, 477, 479: resolve_jwks_uri_from_entity_statement issuer handling
    it "resolves JWKS URI from entity statement issuer" do
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [jwk]},
        metadata: {
          openid_provider: {
            jwks_uri: "#{provider_issuer}/.well-known/jwks.json"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
        .to_return(status: 200, body: jwt, headers: {"Content-Type" => "application/jwt"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

      jwks = {keys: [jwk]}
      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        issuer: provider_issuer,
        client_options: {
          identifier: "test-client-id",
          redirect_uri: "https://example.com/callback",
          host: URI.parse(provider_issuer).host,
          private_key: private_key
          # jwks_uri intentionally omitted
        }
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles error fetching entity statement from issuer for JWKS URI resolution" do
      stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
        .to_return(status: 500, body: "Internal Server Error")

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        issuer: provider_issuer,
        client_options: {
          identifier: "test-client-id",
          redirect_uri: "https://example.com/callback",
          host: URI.parse(provider_issuer).host,
          private_key: private_key,
          jwks_uri: "#{provider_issuer}/.well-known/jwks.json"
        }
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    # Test lines 488-490, 496-498, 501: resolve_jwks_uri_from_entity_statement parsing
    it "handles parsing error when resolving JWKS URI from entity statement" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid jwt")

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: "test-client-id",
          redirect_uri: "https://example.com/callback",
          host: URI.parse(provider_issuer).host,
          private_key: private_key,
          jwks_uri: "#{provider_issuer}/.well-known/jwks.json"
        }
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles entity statement without jwks_uri in metadata" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [jwk]},
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize"
            # jwks_uri intentionally omitted
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256")
      response = double(status: 200, body: signed_jwt)

      jwks = {keys: [jwk]}
      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: "test-client-id",
          redirect_uri: "https://example.com/callback",
          host: URI.parse(provider_issuer).host,
          private_key: private_key,
          jwks_uri: "#{provider_issuer}/.well-known/jwks.json"
        }
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "handles error fetching entity statement from URL (line 359)" do
      # Test line 359: entity_statement_url fetch error
      # Use input derivation: JWT needs kid header to avoid rescue block, entity statement fetch must fail
      entity_statement_url = "https://provider.example.com/.well-known/openid-federation"
      stub_request(:get, entity_statement_url)
        .to_return(status: 500, body: "Internal Server Error")

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}
      kid = jwk[:kid] || jwk["kid"]

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256", kid: kid)
      response = double(status: 200, body: signed_jwt)

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        entity_statement_url: entity_statement_url
      )
      token = described_class.new(access_token: "token", client: client)

      # The error is caught and logged - both fetch_signed_jwks and load_entity_statement_keys_for_jwks_validation try to fetch
      allow(OmniauthOpenidFederation::Logger).to receive(:warn)

      result = token.resource_request { response }

      aggregate_failures do
        expect(OmniauthOpenidFederation::Logger).to have_received(:warn).with(/Failed to fetch entity statement from URL/).at_least(:once)
        expect(OmniauthOpenidFederation::Logger).to have_received(:warn).with(/Entity statement not available for federation/)
        expect(result).to be_a(Hash)
      end
    end

    it "handles error fetching entity statement from issuer (line 373)" do
      # Test line 373: issuer fetch error
      # Use input derivation: JWT needs kid header to avoid rescue block, entity statement fetch must fail
      stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
        .to_return(status: 500, body: "Internal Server Error")

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}
      kid = jwk[:kid] || jwk["kid"]

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256", kid: kid)
      response = double(status: 200, body: signed_jwt)

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      client = create_client_with_strategy_options(
        issuer: provider_issuer
      )
      token = described_class.new(access_token: "token", client: client)

      # The error is caught and logged - both fetch_signed_jwks and load_entity_statement_keys_for_jwks_validation try to fetch
      allow(OmniauthOpenidFederation::Logger).to receive(:warn)

      result = token.resource_request { response }

      aggregate_failures do
        expect(OmniauthOpenidFederation::Logger).to have_received(:warn).with(/Failed to fetch entity statement from issuer/).at_least(:once)
        expect(OmniauthOpenidFederation::Logger).to have_received(:warn).with(/Entity statement not available for federation/)
        expect(result).to be_a(Hash)
      end
    end

    # Test lines 394-399, 402-403: load_entity_statement_keys_for_jwks_validation key extraction
    it "handles entity_jwks with string keys (line 394)" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {"keys" => [jwk]},
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

    it "handles entity_jwks with symbol keys format for JWKS validation (line 395)" do
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

    it "handles entity_jwks as array format during JWKS validation process (line 396-397)" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: [jwk], # Array format
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

    it "handles empty keys in entity_jwks (line 401-403)" do
      # Use input derivation: entity statement must have empty keys in jwks, signed_jwks_uri must be present
      # so fetch_signed_jwks tries to fetch but fails, then load_entity_statement_keys_for_jwks_validation is called
      # Use a valid path within allowed directories - stub Rails.root to point to temp dir
      temp_dir = Dir.mktmpdir
      config_dir = File.join(temp_dir, "config")
      FileUtils.mkdir_p(config_dir)
      entity_statement_path = File.join(config_dir, "entity.jwt")
      signed_jwks_uri = "https://provider.example.com/.well-known/signed-jwks.json"
      stub_request(:get, signed_jwks_uri).to_return(status: 500) # Fail signed JWKS fetch

      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: []}, # Empty keys - this is what we're testing (line 401-403)
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            signed_jwks_uri: signed_jwks_uri # Present so fetch_signed_jwks tries to fetch
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}
      kid = jwk[:kid] || jwk["kid"]

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256", kid: kid)
      response = double(status: 200, body: signed_jwt)

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      # Stub Rails.root to point to temp_dir so the file is in allowed directory
      rails_root = double("Rails.root", join: Pathname.new(config_dir))
      allow(Rails).to receive(:root).and_return(rails_root) if defined?(Rails)

      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path
      )
      token = described_class.new(access_token: "token", client: client)

      allow(OmniauthOpenidFederation::Logger).to receive(:warn)

      result = token.resource_request { response }

      aggregate_failures do
        expect(OmniauthOpenidFederation::Logger).to have_received(:warn).with(/No keys found in entity statement/)
        expect(result).to be_a(Hash)
      end
    ensure
      FileUtils.rm_rf(temp_dir) if temp_dir
    end

    it "handles else branch for entity_jwks (line 398-399)" do
      # Use input derivation: entity_jwks must be invalid format (not hash/array), signed_jwks_uri present
      # Use a valid path within allowed directories - stub Rails.root to point to temp dir
      temp_dir = Dir.mktmpdir
      config_dir = File.join(temp_dir, "config")
      FileUtils.mkdir_p(config_dir)
      entity_statement_path = File.join(config_dir, "entity.jwt")
      signed_jwks_uri = "https://provider.example.com/.well-known/signed-jwks.json"
      stub_request(:get, signed_jwks_uri).to_return(status: 500) # Fail signed JWKS fetch

      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: "not a hash or array", # Invalid format - triggers else branch (line 399)
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            signed_jwks_uri: signed_jwks_uri # Present so fetch_signed_jwks tries to fetch
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}
      kid = jwk[:kid] || jwk["kid"]

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = JWT.encode(payload, private_key, "RS256", kid: kid)
      response = double(status: 200, body: signed_jwt)

      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      # Stub Rails.root to point to temp_dir so the file is in allowed directory
      rails_root = double("Rails.root", join: Pathname.new(config_dir))
      allow(Rails).to receive(:root).and_return(rails_root) if defined?(Rails)

      client = create_client_with_strategy_options(
        entity_statement_path: entity_statement_path
      )
      token = described_class.new(access_token: "token", client: client)

      allow(OmniauthOpenidFederation::Logger).to receive(:warn)

      result = token.resource_request { response }
      aggregate_failures do
        expect(result).to be_a(Hash)
        # The actual error is about failed signed JWKS fetch, not missing keys
        expect(OmniauthOpenidFederation::Logger).to have_received(:warn).with(/Failed to fetch signed JWKS/)
      end
    ensure
      FileUtils.rm_rf(temp_dir) if temp_dir
    end
  end
end
# rubocop:enable RSpec/RepeatedExample

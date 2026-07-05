require "spec_helper"

# rubocop:disable RSpec/RepeatedExample
RSpec.describe OmniauthOpenidFederation::AccessToken, type: :access_token do
  describe "#resource_request" do
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
      }.to raise_error(OmniauthOpenidFederation::DecryptionError, /Failed to decrypt JWE/)
    end

    it "handles fetch_signed_jwks with nil parsed" do
      entity_statement_path = entity_statement_path_under_config
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {}
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600, aud: "test"}
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

    it "handles load_entity_statement_keys with blank path" do
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600, aud: "test"}
      signed_jwt = encode_rs256(payload)
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
        jwt = encode_entity_statement(entity_statement)
        File.write(full_path, jwt)

        payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600, aud: "test"}
        signed_jwt = encode_rs256(payload)
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

    it "uses client.host when jwks_uri is a path and host not in client_options" do
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
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

    it "decodes and validates JWT response using signed JWKS keys extracted from entity statement" do
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

      signed_jwks_payload = {jwks: {keys: [jwk]}}
      signed_jwks_jwt = encode_rs256(signed_jwks_payload)
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

    it "resolves JWKS URI from entity statement metadata when missing from client_options" do
      entity_statement_path = entity_statement_path_under_config
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
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
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

    it "loads entity statement file and parses JSON metadata to extract encryption key for decryption" do
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

    it "handles FileNotFoundError when entity statement file is missing in fetch_signed_jwks" do
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

    it "catches and handles SecurityError exception raised during entity statement file loading in fetch_signed_jwks" do
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
      jwt = encode_entity_statement(entity_statement)
      stub_request(:get, entity_statement_url)
        .to_return(status: 200, body: jwt, headers: {"Content-Type" => "application/jwt"})

      signed_jwks_jwt = encode_rs256({jwks: {keys: [jwk]}})
      stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
        .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
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
      signed_jwt = encode_rs256(payload)
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
      jwt = encode_entity_statement(entity_statement)
      stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
        .to_return(status: 200, body: jwt, headers: {"Content-Type" => "application/jwt"})

      signed_jwks_jwt = encode_rs256({jwks: {keys: [jwk]}})
      stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
        .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
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
      signed_jwt = encode_rs256(payload)
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

    it "returns nil when parsed entity statement is nil in fetch_signed_jwks" do
      entity_statement_path = entity_statement_path_under_config
      File.write(entity_statement_path, "invalid jwt")

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

    it "fetches signed JWKS endpoint and validates response using entity_jwks keys from entity statement" do
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

      signed_jwks_payload = {jwks: {keys: [jwk]}}
      signed_jwks_jwt = encode_rs256(signed_jwks_payload)
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

    it "handles SecurityError in fetch_signed_jwks" do
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

      # Use a different key for signed JWKS to cause validation failure
      other_key = OpenSSL::PKey::RSA.new(2048)
      signed_jwks_payload = {jwks: {keys: [OmniauthOpenidFederation::Utils.rsa_key_to_jwk(other_key.public_key)]}}
      signed_jwks_jwt = encode_rs256(signed_jwks_payload, key: other_key)
      stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
        .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
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

      stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
        .to_raise(StandardError.new("Network error"))

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
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

    it "processes entity_jwks when formatted as Hash with symbol keys during load_entity_statement_keys_for_jwks_validation" do
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

    it "handles entity_jwks as Array format when loading entity statement keys" do
      entity_statement_path = entity_statement_path_under_config
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

    it "handles empty keys array in entity_jwks when loading entity statement keys" do
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

    it "handles errors in load_entity_statement_keys_for_jwks_validation" do
      entity_statement_path = entity_statement_path_under_config
      # Create invalid entity statement that will cause parse errors
      File.write(entity_statement_path, "invalid jwt content")

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
  end
end
# rubocop:enable RSpec/RepeatedExample

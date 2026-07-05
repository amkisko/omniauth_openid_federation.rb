require "spec_helper"

# rubocop:disable RSpec/RepeatedExample
RSpec.describe OpenIDConnect::AccessToken, type: :access_token do
  describe "#resource_request" do
    it "resolves JWKS URI by reading entity statement file path and extracting metadata" do
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

    it "handles SecurityError when resolving JWKS URI from file path" do
      entity_statement_path = "../../../etc/passwd"
      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
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
      jwt = encode_entity_statement(entity_statement)
      stub_request(:get, entity_statement_url)
        .to_return(status: 200, body: jwt, headers: {"Content-Type" => "application/jwt"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
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
      signed_jwt = encode_rs256(payload)
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
      jwt = encode_entity_statement(entity_statement)
      stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
        .to_return(status: 200, body: jwt, headers: {"Content-Type" => "application/jwt"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
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
      signed_jwt = encode_rs256(payload)
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

    it "handles parsing error when resolving JWKS URI from entity statement" do
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
      entity_statement_path = entity_statement_path_under_config
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
          private_key: private_key,
          jwks_uri: "#{provider_issuer}/.well-known/jwks.json"
        }
      )
      token = described_class.new(access_token: "token", client: client)

      result = token.resource_request { response }
      expect(result).to be_a(Hash)
    end

    it "logs warning when entity statement URL fetch fails during JWKS validation" do
      # Use input derivation: JWT needs kid header to avoid rescue block, entity statement fetch must fail
      entity_statement_url = "https://provider.example.com/.well-known/openid-federation"
      stub_request(:get, entity_statement_url)
        .to_return(status: 500, body: "Internal Server Error")

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}
      kid = jwk[:kid] || jwk["kid"]

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
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

    it "logs warning when entity statement issuer fetch fails during JWKS validation" do
      # Use input derivation: JWT needs kid header to avoid rescue block, entity statement fetch must fail
      stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
        .to_return(status: 500, body: "Internal Server Error")

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}
      kid = jwk[:kid] || jwk["kid"]

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
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

    it "validates JWT using entity_jwks with string keys" do
      entity_statement_path = entity_statement_path_under_config
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

    it "validates JWT using entity_jwks with symbol keys" do
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

    it "validates JWT using entity_jwks as an array" do
      entity_statement_path = entity_statement_path_under_config
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

    it "warns when entity_jwks contains an empty keys array" do
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
        jwks: {keys: []},
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            signed_jwks_uri: signed_jwks_uri # Present so fetch_signed_jwks tries to fetch
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}
      kid = jwk[:kid] || jwk["kid"]

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
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

    it "warns when entity_jwks has an unsupported format" do
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
        jwks: "not a hash or array",
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            signed_jwks_uri: signed_jwks_uri # Present so fetch_signed_jwks tries to fetch
          }
        }
      }
      jwt = encode_entity_statement(entity_statement)
      File.write(entity_statement_path, jwt)

      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}
      kid = jwk[:kid] || jwk["kid"]

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600}
      signed_jwt = encode_rs256(payload)
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

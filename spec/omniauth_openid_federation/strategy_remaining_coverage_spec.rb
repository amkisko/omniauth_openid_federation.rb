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

    # Generate a valid entity statement JWT for tests that fetch from URL
    jwk = JWT::JWK.new(public_key)
    jwk_export = jwk.export
    entity_statement_payload = {
      iss: provider_issuer,
      sub: provider_issuer,
      iat: Time.now.to_i,
      exp: Time.now.to_i + 3600,
      jwks: {
        keys: [jwk_export]
      },
      metadata: {
        openid_provider: {
          issuer: provider_issuer,
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token",
          jwks_uri: "https://provider.example.com/.well-known/jwks.json"
        }
      }
    }
    entity_statement_header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
    entity_statement_jwt = JWT.encode(entity_statement_payload, private_key, "RS256", entity_statement_header)

    # Stub entity statement endpoint
    WebMock.stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
      .to_return(
        status: 200,
        body: entity_statement_jwt,
        headers: {"Content-Type" => "application/jwt"}
      )
  end

  describe "client_jwk_signing_key method" do
    it "returns configured value when present" do
      jwks_json = '{"keys":[]}'
      strategy = described_class.new(
        nil,
        client_jwk_signing_key: jwks_json,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: options accessor
      result = strategy.options[:client_jwk_signing_key]
      expect(result).to eq(jwks_json)
    end

    it "extracts from client entity statement when configured value is nil" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: "https://client.example.com",
        sub: "https://client.example.com",
        iat: Time.now.to_i,
        exp: Time.now.to_i + 3600,
        jwks: {keys: [jwk]}
      }
      header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk[:kid]}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        client_entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: options accessor
      result = strategy.options[:client_jwk_signing_key]
      expect(result).to be_a(String)
      parsed = JSON.parse(result)
      expect(parsed).to have_key("keys")
    end

    it "returns nil when not available" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: options accessor
      result = strategy.options[:client_jwk_signing_key]
      expect(result).to be_nil
    end
  end

  describe "options accessor override" do
    it "dynamically sets client_jwk_signing_key from entity statement" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: "https://client.example.com",
        sub: "https://client.example.com",
        jwks: {keys: [jwk]}
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        client_entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      opts = strategy.options
      expect(opts[:client_jwk_signing_key]).to be_a(String)
    end

    it "does not override if already set" do
      jwks_json = '{"keys":[]}'
      strategy = described_class.new(
        nil,
        client_jwk_signing_key: jwks_json,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      opts = strategy.options
      expect(opts[:client_jwk_signing_key]).to eq(jwks_json)
    end
  end

  describe "resolve_endpoints_from_metadata - all branches" do
    it "returns empty hash when entity_statement_path is nil" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      # Test through public API: client method uses resolve_endpoints_from_metadata
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: When no entity statement, client should still work with configured endpoints
      client = strategy.client
      expect(client).to be_present
    end

    it "handles entity statement with issuer in metadata" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: client method uses resolve_endpoints_from_metadata
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Client should resolve endpoints from entity statement
      client = strategy.client
      expect(client).to be_present
    end

    it "handles entity statement with entity_issuer fallback" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
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
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: client method uses resolve_endpoints_from_metadata
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Client should resolve endpoints using entity_issuer fallback
      client = strategy.client
      expect(client).to be_present
    end

    it "handles errors in resolve_endpoints_from_metadata" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid")

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      # Test through public API: client method uses resolve_endpoints_from_metadata
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: When entity statement parsing fails, should fall back to configured endpoints
      client = strategy.client
      expect(client).to be_present
    end
  end

  describe "resolve_issuer_from_metadata - all branches" do
    it "returns nil when entity_statement_path is nil" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses resolve_issuer_from_metadata via resolve_audience
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: When no entity statement, should use configured issuer or fail gracefully
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "uses entity issuer when metadata is nil" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer
        # No metadata section - this will cause parse_metadata to return metadata with entity_issuer
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses resolve_issuer_from_metadata via resolve_audience
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Should use entity issuer (iss claim) when metadata doesn't have issuer
      uri = strategy.authorize_uri
      expect(uri).to be_present
      # Verify the JWT payload contains the issuer as audience
      uri_obj = URI.parse(uri)
      query_params = URI.decode_www_form(uri_obj.query || "").to_h
      request_jwt = query_params["request"]
      parts = request_jwt.split(".")
      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      expect(payload["aud"]).to eq(provider_issuer)
    end

    it "handles errors in resolve_issuer_from_metadata" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid")

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses resolve_issuer_from_metadata via resolve_audience
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: When entity statement parsing fails, should fall back to configured issuer or fail
      # Since we have configured endpoints, it should use those
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end
  end

  describe "resolve_audience - all branches" do
    it "handles entity issuer (iss claim) as audience fallback" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = JWT::JWK.new(public_key)
      jwk_export = jwk.export
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        iat: Time.now.to_i,
        exp: Time.now.to_i + 3600,
        jwks: {
          keys: [jwk_export]
        },
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize"
          }
        }
      }
      header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles non-URL entity issuer gracefully" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: "not-a-url",
        sub: "not-a-url",
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token",
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles token endpoint from resolved endpoints" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
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
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles token endpoint from client" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles authorization endpoint as audience fallback" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles authorization endpoint from client" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles no audience found scenario" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      expect { strategy.authorize_uri }.to raise_error(OmniauthOpenidFederation::ConfigurationError)
    end
  end

  describe "load_client_entity_statement - all branches" do
    it "loads from cache when Rails.cache is available" do
      # Provide provider entity statement for audience resolution
      provider_entity_statement_path = Tempfile.new(["provider_entity", ".jwt"]).path
      provider_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      provider_entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [provider_jwk]},
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      provider_jwt = JWT.encode(provider_entity_statement, private_key, "RS256")
      File.write(provider_entity_statement_path, provider_jwt)

      entity_statement = {
        iss: "https://client.example.com",
        sub: "https://client.example.com",
        jwks: {keys: []}
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")

      # Mock Rails.cache
      rails_cache = double(fetch: jwt, read: nil, write: true)
      stub_const("Rails", double(cache: rails_cache, root: nil))

      # Configure FederationEndpoint with JWKS and metadata
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.issuer = "https://client.example.com"
        config.private_key = private_key
        config.jwks = {keys: [jwk]}
        config.metadata = {
          openid_client: {
            redirect_uris: ["https://example.com/callback"]
          }
        }
      end

      strategy = described_class.new(
        nil,
        entity_statement_path: provider_entity_statement_path,
        client_registration_type: :automatic,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_client_entity_statement for automatic registration
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Should load client entity statement from cache for automatic registration
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles cache fetch errors" do
      # Provide provider entity statement for audience resolution
      provider_entity_statement_path = Tempfile.new(["provider_entity", ".jwt"]).path
      provider_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      provider_entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [provider_jwk]},
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      provider_jwt = JWT.encode(provider_entity_statement, private_key, "RS256")
      File.write(provider_entity_statement_path, provider_jwt)

      # Mock Rails.cache with error
      rails_cache = double(read: nil, write: true)
      allow(rails_cache).to receive(:fetch).and_raise(StandardError.new("Cache error"))
      stub_const("Rails", double(cache: rails_cache, root: nil))

      # Configure FederationEndpoint with JWKS and metadata
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.issuer = "https://client.example.com"
        config.private_key = private_key
        config.jwks = {keys: [jwk]}
        config.metadata = {
          openid_client: {
            redirect_uris: ["https://example.com/callback"]
          }
        }
      end

      strategy = described_class.new(
        nil,
        entity_statement_path: provider_entity_statement_path,
        client_registration_type: :automatic,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_client_entity_statement
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Should handle cache errors and generate dynamically
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "generates dynamically when cache is empty" do
      # Provide provider entity statement for audience resolution
      provider_entity_statement_path = Tempfile.new(["provider_entity", ".jwt"]).path
      provider_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      provider_entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [provider_jwk]},
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      provider_jwt = JWT.encode(provider_entity_statement, private_key, "RS256")
      File.write(provider_entity_statement_path, provider_jwt)

      # Mock Rails.cache returning nil
      rails_cache = double(fetch: nil, read: nil, write: true)
      stub_const("Rails", double(cache: rails_cache, root: nil))

      # Configure FederationEndpoint with JWKS and metadata
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.issuer = "https://client.example.com"
        config.private_key = private_key
        config.jwks = {keys: [jwk]}
        config.metadata = {
          openid_client: {
            redirect_uris: ["https://example.com/callback"]
          }
        }
      end

      strategy = described_class.new(
        nil,
        entity_statement_path: provider_entity_statement_path,
        client_registration_type: :automatic,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_client_entity_statement
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Should generate entity statement dynamically when cache is empty
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles FederationEndpoint configuration errors" do
      # Reset configuration
      OmniauthOpenidFederation::FederationEndpoint.instance_variable_set(:@configuration, nil)

      # Mock Rails.cache returning nil
      rails_cache = double(fetch: nil)
      stub_const("Rails", double(cache: rails_cache, root: nil))

      strategy = described_class.new(
        nil,
        client_registration_type: :automatic,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_client_entity_statement
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Should raise error when FederationEndpoint is not configured
      expect {
        strategy.authorize_uri
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError)
    end

    it "handles other errors in dynamic generation" do
      # Mock Rails.cache returning nil
      rails_cache = double(fetch: nil)
      stub_const("Rails", double(cache: rails_cache, root: nil))

      # Configure FederationEndpoint
      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.issuer = "https://client.example.com"
        config.private_key = private_key
      end

      # Mock generate_entity_statement to raise error
      allow(OmniauthOpenidFederation::FederationEndpoint).to receive(:generate_entity_statement).and_raise(StandardError.new("Generation error"))

      strategy = described_class.new(
        nil,
        client_registration_type: :automatic,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_client_entity_statement
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Should raise error when generation fails
      expect {
        strategy.authorize_uri
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError)
    end
  end

  describe "load_client_entity_statement_from_file - all branches" do
    it "handles absolute path" do
      # Provide provider entity statement for audience resolution
      provider_entity_statement_path = Tempfile.new(["provider_entity", ".jwt"]).path
      provider_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      provider_entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [provider_jwk]},
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      provider_jwt = JWT.encode(provider_entity_statement, private_key, "RS256")
      File.write(provider_entity_statement_path, provider_jwt)

      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: "https://client.example.com",
        sub: "https://client.example.com",
        jwks: {keys: []}
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: entity_statement_path,
        client_registration_type: :automatic,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_client_entity_statement_from_file
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Should load client entity statement from file for automatic registration
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles relative path with Rails.root" do
      # Provide provider entity statement for audience resolution
      provider_entity_statement_path = Tempfile.new(["provider_entity", ".jwt"]).path
      provider_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      provider_entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [provider_jwk]},
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      provider_jwt = JWT.encode(provider_entity_statement, private_key, "RS256")
      File.write(provider_entity_statement_path, provider_jwt)

      entity_statement_path = "tmp/test_entity.jwt"
      entity_statement = {
        iss: "https://client.example.com",
        sub: "https://client.example.com",
        jwks: {keys: []}
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")

      full_path = if defined?(Rails)
        Rails.root.join(entity_statement_path).to_s
      else
        File.expand_path(entity_statement_path)
      end
      FileUtils.mkdir_p(File.dirname(full_path))
      File.write(full_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: entity_statement_path,
        client_registration_type: :automatic,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_client_entity_statement_from_file
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Should load client entity statement from relative path
      uri = strategy.authorize_uri
      expect(uri).to be_present
    ensure
      File.delete(full_path) if File.exist?(full_path)
    end

    it "handles relative path without Rails.root" do
      hide_const("Rails") if defined?(Rails)

      # Provide provider entity statement for audience resolution
      provider_entity_statement_path = Tempfile.new(["provider_entity", ".jwt"]).path
      provider_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      provider_entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [provider_jwk]},
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      provider_jwt = JWT.encode(provider_entity_statement, private_key, "RS256")
      File.write(provider_entity_statement_path, provider_jwt)

      entity_statement_path = "tmp/test_entity.jwt"
      entity_statement = {
        iss: "https://client.example.com",
        sub: "https://client.example.com",
        jwks: {keys: []}
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      full_path = File.expand_path(entity_statement_path)
      FileUtils.mkdir_p(File.dirname(full_path))
      File.write(full_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: entity_statement_path,
        client_registration_type: :automatic,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_client_entity_statement_from_file
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Should load client entity statement from relative path using File.expand_path
      uri = strategy.authorize_uri
      expect(uri).to be_present
    ensure
      File.delete(full_path) if File.exist?(full_path)
    end
  end

  describe "extract_entity_identifier_from_statement - all branches" do
    it "uses configured identifier when provided" do
      # Provide provider entity statement for audience resolution
      provider_entity_statement_path = Tempfile.new(["provider_entity", ".jwt"]).path
      provider_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      provider_entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [provider_jwk]},
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      provider_jwt = JWT.encode(provider_entity_statement, private_key, "RS256")
      File.write(provider_entity_statement_path, provider_jwt)

      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: "https://client.example.com",
        sub: "https://client.example.com"
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: entity_statement_path,
        client_entity_identifier: "configured-id",
        client_registration_type: :automatic,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses extract_entity_identifier_from_statement
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Should use configured entity identifier when provided
      uri = strategy.authorize_uri
      expect(uri).to be_present
      # Verify the JWT payload contains configured identifier
      uri_obj = URI.parse(uri)
      query_params = URI.decode_www_form(uri_obj.query || "").to_h
      request_jwt = query_params["request"]
      parts = request_jwt.split(".")
      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      expect(payload["iss"]).to eq("configured-id")
    end

    it "extracts from sub claim" do
      # Provide provider entity statement for audience resolution
      provider_entity_statement_path = Tempfile.new(["provider_entity", ".jwt"]).path
      provider_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      provider_entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [provider_jwk]},
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      provider_jwt = JWT.encode(provider_entity_statement, private_key, "RS256")
      File.write(provider_entity_statement_path, provider_jwt)

      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: "https://client.example.com",
        sub: "https://client.example.com"
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: entity_statement_path,
        client_registration_type: :automatic,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses extract_entity_identifier_from_statement
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Should extract entity identifier from sub claim
      uri = strategy.authorize_uri
      expect(uri).to be_present
      # Verify the JWT payload contains sub claim as issuer
      uri_obj = URI.parse(uri)
      query_params = URI.decode_www_form(uri_obj.query || "").to_h
      request_jwt = query_params["request"]
      parts = request_jwt.split(".")
      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      expect(payload["iss"]).to eq("https://client.example.com")
    end

    it "falls back to iss claim when sub is missing" do
      # Provide provider entity statement for audience resolution
      provider_entity_statement_path = Tempfile.new(["provider_entity", ".jwt"]).path
      provider_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      provider_entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [provider_jwk]},
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      provider_jwt = JWT.encode(provider_entity_statement, private_key, "RS256")
      File.write(provider_entity_statement_path, provider_jwt)

      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: "https://client.example.com"
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: entity_statement_path,
        client_registration_type: :automatic,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses extract_entity_identifier_from_statement
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Should fall back to iss claim when sub is missing
      uri = strategy.authorize_uri
      expect(uri).to be_present
      # Verify the JWT payload contains iss claim as issuer
      uri_obj = URI.parse(uri)
      query_params = URI.decode_www_form(uri_obj.query || "").to_h
      request_jwt = query_params["request"]
      parts = request_jwt.split(".")
      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      expect(payload["iss"]).to eq("https://client.example.com")
    end

    it "handles missing both sub and iss" do
      # Provide provider entity statement for audience resolution
      provider_entity_statement_path = Tempfile.new(["provider_entity", ".jwt"]).path
      provider_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      provider_entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [provider_jwk]},
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      provider_jwt = JWT.encode(provider_entity_statement, private_key, "RS256")
      File.write(provider_entity_statement_path, provider_jwt)

      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {}
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: entity_statement_path,
        client_entity_identifier: "fallback-identifier",
        client_registration_type: :automatic,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses extract_entity_identifier_from_statement
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Should handle missing sub and iss gracefully
      # When both are missing, it should fall back to configured identifier
      uri = strategy.authorize_uri
      expect(uri).to be_present
      # Verify the JWT payload contains fallback identifier
      uri_obj = URI.parse(uri)
      query_params = URI.decode_www_form(uri_obj.query || "").to_h
      request_jwt = query_params["request"]
      parts = request_jwt.split(".")
      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      expect(payload["iss"]).to eq("fallback-identifier")
    end

    it "handles errors in extraction" do
      # Provide provider entity statement for audience resolution
      provider_entity_statement_path = Tempfile.new(["provider_entity", ".jwt"]).path
      provider_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      provider_entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [provider_jwk]},
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      provider_jwt = JWT.encode(provider_entity_statement, private_key, "RS256")
      File.write(provider_entity_statement_path, provider_jwt)

      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid.jwt")

      strategy = described_class.new(
        nil,
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: entity_statement_path,
        client_entity_identifier: "fallback-identifier",
        client_registration_type: :automatic,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses extract_entity_identifier_from_statement
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Should raise error when client entity statement is invalid
      # Invalid JWT format is caught during loading, before extraction
      expect {
        strategy.authorize_uri
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /not a valid JWT/)
    end
  end

  describe "load_provider_metadata_for_encryption" do
    it "returns nil when entity_statement_path is nil" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_provider_metadata_for_encryption
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: When no entity statement, request object should not be encrypted
      uri = strategy.authorize_uri
      expect(uri).to be_present
      # Verify request object is not encrypted (3 parts for JWT, 5 for JWE)
      uri_obj = URI.parse(uri)
      query_params = URI.decode_www_form(uri_obj.query || "").to_h
      request_jwt = query_params["request"]
      parts = request_jwt.split(".")
      expect(parts.length).to eq(3) # Not encrypted
    end

    it "returns nil when file does not exist" do
      strategy = described_class.new(
        nil,
        entity_statement_path: "/nonexistent/path.jwt",
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_provider_metadata_for_encryption
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: When file doesn't exist, request object should not be encrypted
      uri = strategy.authorize_uri
      expect(uri).to be_present
      uri_obj = URI.parse(uri)
      query_params = URI.decode_www_form(uri_obj.query || "").to_h
      request_jwt = query_params["request"]
      parts = request_jwt.split(".")
      expect(parts.length).to eq(3) # Not encrypted
    end

    it "loads metadata with encryption parameters" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      provider_encryption_key = OpenSSL::PKey::RSA.new(2048)
      provider_encryption_jwk = JWT::JWK.new(provider_encryption_key.public_key).export
      provider_encryption_jwk[:use] = "enc"

      # Entity statement needs proper header with typ: "entity-statement+jwt" and kid
      # The kid must match a key in the JWKS
      signing_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      signing_jwk[:use] = "sig"

      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        iat: Time.now.to_i,
        exp: Time.now.to_i + 3600,
        jwks: {keys: [signing_jwk, provider_encryption_jwk]},
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token",
            request_object_encryption_alg: "RSA-OAEP",
            request_object_encryption_enc: "A128CBC-HS256"
          }
        }
      }
      header = {alg: "RS256", typ: "entity-statement+jwt", kid: signing_jwk[:kid]}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      # Stub HTTP request for entity statement (in case file isn't found)
      WebMock.stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
        .to_return(status: 200, body: jwt, headers: {"Content-Type" => "application/jwt"})

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_provider_metadata_for_encryption
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: When provider requires encryption, request object should be encrypted
      uri = strategy.authorize_uri
      expect(uri).to be_present
      # Verify request object is encrypted (5 parts for JWE)
      uri_obj = URI.parse(uri)
      query_params = URI.decode_www_form(uri_obj.query || "").to_h
      request_jwt = query_params["request"]
      parts = request_jwt.split(".")
      expect(parts.length).to eq(5) # Encrypted (JWE)
    end

    it "handles errors in loading metadata" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid")

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_provider_metadata_for_encryption
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: When metadata loading fails, request object should not be encrypted
      uri = strategy.authorize_uri
      expect(uri).to be_present
      uri_obj = URI.parse(uri)
      query_params = URI.decode_www_form(uri_obj.query || "").to_h
      request_jwt = query_params["request"]
      parts = request_jwt.split(".")
      expect(parts.length).to eq(3) # Not encrypted
    end
  end

  describe "load_metadata_for_key_extraction" do
    it "returns nil when entity_statement_path is nil" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_metadata_for_key_extraction
      # This is used when extracting signing keys from entity statement
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: When no entity statement, should work with configured private key
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "returns nil when file does not exist" do
      strategy = described_class.new(
        nil,
        entity_statement_path: "/nonexistent/path.jwt",
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_metadata_for_key_extraction
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: When file doesn't exist, should work with configured private key
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "loads metadata with JWKS" do
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

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_metadata_for_key_extraction
      # This is used when extracting signing keys from entity statement for federation
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: Should load metadata with JWKS from entity statement
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles errors in loading metadata" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid")

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      # Test through public API: authorize_uri uses load_metadata_for_key_extraction
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Behavior: When metadata loading fails, should work with configured private key
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end
  end
end

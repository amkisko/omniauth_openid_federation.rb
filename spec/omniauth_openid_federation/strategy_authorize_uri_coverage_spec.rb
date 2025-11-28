require "spec_helper"

RSpec.describe OmniAuth::Strategies::OpenIDFederation, type: :strategy do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:provider_issuer) { "https://provider.example.com" }
  let(:client_id) { "test-client-id" }
  let(:redirect_uri) { "https://example.com/users/auth/openid_federation/callback" }

  # Stub all HTTP requests for tests that use relative paths
  # When tests use relative paths like "/oauth2/token" with host, the strategy builds full URLs
  before do
    stub_relative_path_endpoints(host: URI.parse(provider_issuer).host)
  end

  describe "#authorize_uri - all branches" do
    it "handles automatic client registration" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: "https://client.example.com",
        sub: "https://client.example.com",
        jwks: {keys: []}
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.issuer = "https://client.example.com"
        config.private_key = private_key
      end

      strategy = described_class.new(
        nil,
        client_registration_type: :automatic,
        client_entity_statement_path: entity_statement_path,
        audience: provider_issuer,
        client_options: {
          identifier: "temp-client-id", # Temporary ID, will be replaced by entity identifier in automatic registration
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

    it "handles automatic registration with client_entity_identifier" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: "https://client.example.com",
        sub: "https://client.example.com",
        jwks: {keys: []}
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.issuer = "https://client.example.com"
        config.private_key = private_key
      end

      strategy = described_class.new(
        nil,
        client_registration_type: :automatic,
        client_entity_statement_path: entity_statement_path,
        client_entity_identifier: "configured-entity-id",
        audience: provider_issuer,
        client_options: {
          identifier: "temp-client-id", # Temporary ID, will be replaced by entity identifier in automatic registration
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

    it "handles automatic registration with client.identifier=" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: "https://client.example.com",
        sub: "https://client.example.com",
        jwks: {keys: []}
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.issuer = "https://client.example.com"
        config.private_key = private_key
      end

      strategy = described_class.new(
        nil,
        client_registration_type: :automatic,
        client_entity_statement_path: entity_statement_path,
        audience: provider_issuer,
        client_options: {
          identifier: "temp-client-id", # Temporary ID, will be replaced by entity identifier in automatic registration
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      client = strategy.client
      allow(client).to receive(:identifier=)
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles automatic registration with client.client_id=" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: "https://client.example.com",
        sub: "https://client.example.com",
        jwks: {keys: []}
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.issuer = "https://client.example.com"
        config.private_key = private_key
      end

      strategy = described_class.new(
        nil,
        client_registration_type: :automatic,
        client_entity_statement_path: entity_statement_path,
        audience: provider_issuer,
        client_options: {
          identifier: "temp-client-id", # Temporary ID, will be replaced by entity identifier in automatic registration
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      # Get client before authorize_uri so we can stub it
      client = strategy.client
      # Make respond_to?(:identifier=) return false so it falls back to client_id=
      allow(client).to receive(:respond_to?).and_call_original
      allow(client).to receive(:respond_to?).with(:identifier=).and_return(false)
      allow(client).to receive(:respond_to?).with(:client_id=).and_return(true)
      allow(client).to receive(:client_id=)
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
      # Verify client_id= was called as fallback
      expect(client).to have_received(:client_id=)
    end

    # Note: ftn_spname was removed as it was provider-specific
    # acr_values should be passed via request parameters instead

    it "handles request_object_params" do
      strategy = described_class.new(
        nil,
        request_object_params: ["custom_param"],
        audience: provider_issuer,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {"custom_param" => "value"}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles request_object_params with empty value" do
      strategy = described_class.new(
        nil,
        request_object_params: ["custom_param"],
        audience: provider_issuer,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {"custom_param" => ""}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles request_params with login_hint, ui_locales, claims_locales" do
      strategy = described_class.new(
        nil,
        audience: provider_issuer,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(
        params: {
          "login_hint" => "user@example.com",
          "ui_locales" => "en",
          "claims_locales" => "en"
        }
      ))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles provider metadata for encryption" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [jwk]},
        metadata: {
          openid_provider: {
            request_object_encryption_alg: "RSA-OAEP",
            request_object_encryption_enc: "A128CBC-HS256",
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
        audience: provider_issuer,
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

    it "handles failed signed request object generation" do
      strategy = described_class.new(
        nil,
        audience: provider_issuer,
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

      # Mock Jws to return nil
      jws_builder = double
      allow(OmniauthOpenidFederation::Jws).to receive(:new).and_return(jws_builder)
      allow(jws_builder).to receive(:sign).and_return(nil)

      expect {
        strategy.authorize_uri
      }.to raise_error(OmniauthOpenidFederation::SecurityError, /Failed to generate signed request object/)
    end

    it "handles missing authorization endpoint in authorize_uri" do
      strategy = described_class.new(
        nil,
        audience: provider_issuer,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      client = strategy.client
      allow(client).to receive(:authorization_endpoint).and_return(nil)
      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      expect {
        strategy.authorize_uri
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Authorization endpoint not configured/)
    end

    it "handles issuer resolution from entity statement" do
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
        audience: provider_issuer,
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

    it "handles signing_key_source configuration" do
      strategy = described_class.new(
        nil,
        signing_key_source: :federation,
        audience: provider_issuer,
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

    it "handles key_source as alias for signing_key_source" do
      strategy = described_class.new(
        nil,
        key_source: :federation,
        audience: provider_issuer,
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

    it "handles extra_authorize_params" do
      strategy = described_class.new(
        nil,
        extra_authorize_params: {custom: "value"},
        audience: provider_issuer,
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

    it "handles prompt, hd, acr_values options" do
      strategy = described_class.new(
        nil,
        prompt: "login",
        hd: "example.com",
        acr_values: "level1",
        audience: provider_issuer,
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

    it "handles response_type and response_mode options" do
      strategy = described_class.new(
        nil,
        response_type: "code id_token",
        response_mode: "form_post",
        audience: provider_issuer,
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

    it "handles scope as array" do
      strategy = described_class.new(
        nil,
        scope: ["openid", "email", "profile"],
        audience: provider_issuer,
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

    it "handles callback_url fallback for redirect_uri" do
      strategy = described_class.new(
        nil,
        audience: provider_issuer,
        client_options: {
          identifier: client_id,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})
      allow(strategy).to receive(:callback_url).and_return(redirect_uri)

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end
  end
end

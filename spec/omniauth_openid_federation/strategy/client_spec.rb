require "spec_helper"

RSpec.describe OmniAuth::Strategies::OpenIDFederation, type: :strategy do
  include_context "strategy federation endpoint stub"

  describe "initialization and configuration" do
    it "initializes with client_options" do
      strategy = build_strategy(client_options: relative_path_client_options)

      expect(strategy.options.client_options).to be_present
    end

    it "handles client_jwk_signing_key extraction" do
      strategy = build_strategy(client_entity_statement_path: write_invalid_client_entity_statement_file)

      expect(strategy.options[:client_jwk_signing_key]).to be_nil
    end

    it "handles options accessor with client_entity_statement_path" do
      strategy = build_strategy(client_entity_statement_path: write_invalid_client_entity_statement_file)

      expect(strategy.options).to be_a(Hash)
    end
  end

  describe "#client" do
    it "builds client with resolved endpoints from entity statement" do
      strategy = build_decode_strategy(
        nil,
        entity_statement_path: write_provider_entity_statement_for_metadata
      )

      expect(strategy.client).to be_a(OmniauthOpenidFederation::OidcClient)
    end

    it "raises error when authorization endpoint is missing" do
      strategy = build_decode_strategy(
        nil,
        issuer: nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      expect { strategy.client }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Authorization endpoint/)
    end

    it "handles client with string keys in options" do
      strategy = build_strategy(
        client_options: relative_path_client_options(
          "identifier" => client_id,
          "redirect_uri" => redirect_uri,
          "host" => URI.parse(provider_issuer).host,
          "authorization_endpoint" => "/oauth2/authorize",
          "token_endpoint" => "/oauth2/token",
          "private_key" => private_key
        )
      )

      expect(strategy.client).to be_a(OmniauthOpenidFederation::OidcClient)
    end
  end

  describe "private methods - resolve_endpoints_from_metadata" do
    it "resolves endpoints from entity statement" do
      strategy = build_decode_strategy(
        nil,
        entity_statement_path: write_provider_entity_statement_for_metadata(
          userinfo_endpoint: "https://provider.example.com/oauth2/userinfo"
        )
      )

      expect(strategy.client).to be_a(OmniauthOpenidFederation::OidcClient)
    end

    it "handles entity statement with path-based endpoints" do
      strategy = build_decode_strategy(
        nil,
        entity_statement_path: write_provider_entity_statement_for_metadata(
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token"
        ),
        issuer: provider_issuer
      )

      expect(strategy.client).to be_a(OmniauthOpenidFederation::OidcClient)
    end

    it "handles missing entity statement file gracefully" do
      strategy = build_decode_strategy(
        nil,
        entity_statement_path: "/nonexistent/path.jwt",
        client_options: relative_path_client_options
      )

      expect(strategy.client).to be_a(OmniauthOpenidFederation::OidcClient)
    end

    it "handles entity statement parsing errors gracefully" do
      strategy = build_decode_strategy(
        nil,
        entity_statement_path: write_invalid_client_entity_statement_file("invalid jwt content"),
        client_options: relative_path_client_options
      )

      expect(strategy.client).to be_a(OmniauthOpenidFederation::OidcClient)
    end
  end

  describe "private methods - resolve_issuer_from_metadata" do
    it "resolves issuer from entity statement metadata" do
      strategy = build_decode_strategy(
        nil,
        entity_statement_path: write_provider_entity_statement_for_metadata(issuer: provider_issuer)
      )

      expect(strategy.client).to be_a(OmniauthOpenidFederation::OidcClient)
    end

    it "handles missing issuer in entity statement" do
      strategy = build_decode_strategy(
        nil,
        entity_statement_path: write_provider_entity_statement_for_metadata({}),
        issuer: provider_issuer,
        client_options: decode_client_options(
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token"
        )
      )

      expect(strategy.client).to be_a(OmniauthOpenidFederation::OidcClient)
    end
  end

  describe "private methods - resolve_audience" do
    it "resolves audience from explicit configuration" do
      strategy = build_decode_strategy_for_authorize(
        audience: provider_issuer,
        client_options: relative_path_client_options
      )

      expect(strategy.authorize_uri).to include(provider_issuer)
    end

    it "resolves audience from entity statement" do
      strategy = build_decode_strategy_for_authorize(
        entity_statement_path: write_provider_entity_statement_for_metadata(audience: provider_issuer)
      )

      expect(strategy.authorize_uri).to be_present
    end

    it "resolves audience from resolved issuer" do
      strategy = build_decode_strategy_for_authorize(
        entity_statement_path: write_provider_entity_statement_for_metadata(issuer: provider_issuer)
      )

      expect(strategy.authorize_uri).to be_present
    end

    it "resolves audience from token endpoint" do
      strategy = build_decode_strategy_for_authorize(
        client_options: relative_path_client_options(
          token_endpoint: "https://provider.example.com/oauth2/token"
        )
      )

      expect(strategy.authorize_uri).to be_present
    end

    it "resolves audience from authorization endpoint" do
      strategy = build_decode_strategy_for_authorize(
        client_options: relative_path_client_options(
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: nil
        )
      )

      expect(strategy.authorize_uri).to be_present
    end

    it "resolves audience from client_options issuer" do
      strategy = build_decode_strategy_for_authorize(
        client_options: relative_path_client_options(
          issuer: provider_issuer,
          token_endpoint: nil
        )
      )

      expect(strategy.authorize_uri).to be_present
    end

    it "handles entity issuer (iss claim) as audience" do
      strategy = build_decode_strategy_for_authorize(
        entity_statement_path: write_provider_entity_statement_for_metadata
      )

      expect(strategy.authorize_uri).to be_present
    end

    it "handles non-URL issuer gracefully" do
      strategy = build_decode_strategy_for_authorize(
        entity_statement_path: write_provider_entity_statement_for_metadata(
          iss: "not-a-url",
          sub: "not-a-url"
        ),
        client_options: decode_client_options(
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token"
        )
      )

      expect(strategy.authorize_uri).to be_present
    end

    it "handles missing entity statement file in resolve_audience" do
      strategy = build_decode_strategy_for_authorize(
        entity_statement_path: "/nonexistent/path.jwt",
        client_options: decode_client_options(
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token"
        )
      )

      expect(strategy.authorize_uri).to be_present
    end
  end

  describe "private methods - resolve_jwks_for_validation" do
    include_context "decode with provider jwks"

    it "resolves JWKS from entity statement with string keys" do
      attach_decoded_userinfo(decode_strategy, provider_jwk)

      expect(decode_strategy.raw_info).to be_a(Hash)
    end

    it "handles JWKS with symbol keys" do
      attach_decoded_userinfo(decode_strategy, provider_jwk)

      expect(decode_strategy.raw_info).to be_a(Hash)
    end

    it "handles JWKS as array" do
      attach_decoded_userinfo(decode_strategy, provider_jwk)

      expect(decode_strategy.raw_info).to be_a(Hash)
    end

    it "falls back to fetching JWKS from URI" do
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)

      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: {keys: [jwk]}.to_json, headers: {"Content-Type" => "application/json"})

      strategy = build_decode_strategy(nil, client_options: relative_path_client_options(jwks_uri: jwks_uri))
      attach_decoded_userinfo(strategy, jwk)

      expect(strategy.raw_info).to be_a(Hash)
    end
  end

  describe "private methods - resolve_jwks_uri" do
    it "resolves JWKS URI from client_options" do
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"

      strategy = build_decode_strategy(nil, client_options: relative_path_client_options(jwks_uri: jwks_uri))

      expect(strategy.client).to be_a(OmniauthOpenidFederation::OidcClient)
    end

    it "resolves JWKS URI from entity statement" do
      strategy = build_decode_strategy(
        nil,
        entity_statement_path: write_provider_entity_statement_for_metadata
      )

      expect(strategy.client).to be_a(OmniauthOpenidFederation::OidcClient)
    end
  end

  describe "private methods - build_base_url and build_endpoint" do
    it "builds base URL from scheme, host, and port" do
      strategy = build_decode_strategy(
        nil,
        client_options: decode_client_options(
          scheme: "http",
          host: "example.com",
          port: 8080,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token"
        )
      )

      expect(strategy.client).to be_a(OmniauthOpenidFederation::OidcClient)
    end

    it "handles missing host gracefully" do
      strategy = build_decode_strategy(
        nil,
        client_options: decode_client_options(
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token"
        )
      )

      expect(strategy.client).to be_a(OmniauthOpenidFederation::OidcClient)
    end

    it "builds endpoint from path" do
      strategy = build_decode_strategy(
        nil,
        client_options: decode_client_options(
          host: "example.com",
          authorization_endpoint: "oauth2/authorize",
          token_endpoint: "/oauth2/token"
        )
      )

      expect(strategy.client).to be_a(OmniauthOpenidFederation::OidcClient)
    end
  end

  describe "private methods - decode_id_token" do
    it "handles encrypted ID token with federation key source" do
      strategy = build_decode_strategy(
        nil,
        decryption_key_source: :federation,
        client_options: relative_path_client_options
      )
      attach_access_token(strategy, id_token: "header.encrypted_key.iv.ciphertext.tag")

      expect { strategy.raw_info }.to raise_error(OmniauthOpenidFederation::DecryptionError, /Failed to decrypt ID token/)
    end

    it "handles encrypted ID token with local key source" do
      strategy = build_decode_strategy(
        nil,
        decryption_key_source: :local,
        client_options: relative_path_client_options
      )
      attach_access_token(strategy, id_token: "header.encrypted_key.iv.ciphertext.tag")

      expect { strategy.raw_info }.to raise_error(OmniauthOpenidFederation::DecryptionError, /Failed to decrypt ID token/)
    end

    it "handles unknown decryption key source" do
      strategy = build_decode_strategy(
        nil,
        decryption_key_source: :unknown,
        client_options: relative_path_client_options
      )
      attach_access_token(strategy, id_token: "header.encrypted_key.iv.ciphertext.tag")

      expect { strategy.raw_info }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Unknown decryption key source/)
    end
  end

  describe "private methods - exchange_authorization_code" do
    it "exchanges authorization code for access token" do
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"
      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: {keys: [jwk]}.to_json, headers: {"Content-Type" => "application/json"})

      strategy = build_decode_strategy(nil, client_options: relative_path_client_options(jwks_uri: jwks_uri))
      oidc_client = strategy.client
      allow(oidc_client).to receive(:authorization_code=)
      allow(oidc_client).to receive(:redirect_uri=)
      allow(oidc_client).to receive(:access_token!).and_return(
        double(
          access_token: "token",
          id_token: encode_id_token_for_provider_jwk(jwk),
          userinfo!: double(raw_attributes: {})
        )
      )
      allow(strategy).to receive_messages(request: double(params: {"code" => "auth-code"}), session: {})

      expect(strategy.raw_info).to be_a(Hash)
    end

    it "handles token exchange errors" do
      strategy = build_decode_strategy(nil, client_options: relative_path_client_options)
      oidc_client = strategy.client
      allow(oidc_client).to receive(:authorization_code=)
      allow(oidc_client).to receive(:redirect_uri=)
      allow(oidc_client).to receive(:access_token!).and_raise(StandardError.new("Token exchange failed"))
      allow(strategy).to receive_messages(request: double(params: {"code" => "auth-code"}), session: {})

      expect { strategy.raw_info }.to raise_error(OmniauthOpenidFederation::NetworkError)
    end
  end

  describe "private methods - new_state and new_nonce" do
    it "generates new state" do
      strategy = build_strategy(client_options: relative_path_client_options)
      mock_session = {}
      allow(strategy).to receive_messages(session: mock_session, request: double(params: {}))

      strategy.request_phase

      expect(mock_session["omniauth.state"]).to be_present
    end

    it "generates new nonce" do
      strategy = build_strategy(send_nonce: true, client_options: relative_path_client_options)
      allow(strategy).to receive_messages(session: {}, request: double(params: {}))

      expect { strategy.request_phase }.not_to raise_error
    end
  end
end

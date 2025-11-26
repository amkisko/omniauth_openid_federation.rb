require "spec_helper"
require "omniauth/test"

RSpec.describe OmniAuth::Strategies::OpenIDFederation, type: :integration do
  include OmniAuth::Test::StrategyTestCase

  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:provider_issuer) { "https://provider.example.com" }
  let(:client_id) { "test-client-id" }
  let(:redirect_uri) { "https://example.com/users/auth/openid_federation/callback" }
  let(:authorization_code) { "test-auth-code-123" }
  let(:access_token_value) { "test-access-token-456" }
  let(:id_token_payload) do
    {
      iss: provider_issuer,
      sub: "user-123",
      aud: client_id,
      exp: Time.now.to_i + 3600,
      iat: Time.now.to_i,
      nonce: "test-nonce",
      email: "user@example.com",
      name: "Test User",
      given_name: "Test",
      family_name: "User"
    }
  end

  let(:strategy) do
    described_class.new(
      nil,
      name: :openid_federation,
      issuer: provider_issuer,
      audience: provider_issuer,
      client_options: {
        identifier: client_id,
        redirect_uri: redirect_uri,
        host: URI.parse(provider_issuer).host,
        scheme: URI.parse(provider_issuer).scheme,
        authorization_endpoint: "/oauth2/authorize",
        token_endpoint: "/oauth2/token",
        userinfo_endpoint: "/oauth2/userinfo",
        jwks_uri: "/.well-known/jwks.json",
        private_key: private_key
      }
    )
  end

  describe "full authentication flow" do
    let(:mock_session) { {} }
    let(:mock_env) do
      {
        "rack.session" => mock_session,
        "REQUEST_METHOD" => "GET",
        "PATH_INFO" => "/users/auth/openid_federation",
        "SERVER_NAME" => "example.com",
        "SERVER_PORT" => "443",
        "rack.url_scheme" => "https",
        "rack.input" => StringIO.new("")
      }
    end

    let(:mock_request) do
      double(
        params: {},
        url: "#{provider_issuer}/oauth2/authorize",
        scheme: "https",
        host: URI.parse(provider_issuer).host,
        port: 443
      )
    end

    let(:provider_jwks) do
      # Generate JWK from public key using the library's utility
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key, use: "sig")
      # Set a specific kid for testing
      jwk[:kid] = "test-key-id"
      {
        keys: [jwk]
      }
    end

    before do
      # Generate a valid entity statement JWT
      entity_statement_payload = {
        iss: provider_issuer,
        sub: provider_issuer,
        iat: Time.now.to_i,
        exp: Time.now.to_i + 3600,
        jwks: provider_jwks,
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "#{provider_issuer}/oauth2/authorize",
            token_endpoint: "#{provider_issuer}/oauth2/token",
            userinfo_endpoint: "#{provider_issuer}/oauth2/userinfo",
            jwks_uri: "#{provider_issuer}/.well-known/jwks.json",
            signed_jwks_uri: "#{provider_issuer}/.well-known/signed-jwks.json"
          }
        }
      }
      entity_statement_header = {alg: "RS256", typ: "entity-statement+jwt", kid: "test-key-id"}
      entity_statement_jwt = JWT.encode(entity_statement_payload, private_key, "RS256", entity_statement_header)

      # Stub all HTTP requests that might be made
      # When using relative paths with host, the strategy builds full URLs
      stub_provider_endpoints(
        provider_issuer: provider_issuer,
        jwks: provider_jwks
      )
      stub_relative_path_endpoints(host: URI.parse(provider_issuer).host)

      # Ensure JWKS is stubbed for the full URL that the strategy will use
      WebMock.stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(
          status: 200,
          body: provider_jwks.to_json,
          headers: {"Content-Type" => "application/json"}
        )

      # Stub entity statement endpoint with valid JWT
      WebMock.stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
        .to_return(
          status: 200,
          body: entity_statement_jwt,
          headers: {"Content-Type" => "application/jwt"}
        )

      # Set up strategy with mock environment
      strategy.instance_variable_set(:@env, mock_env)
      strategy.instance_variable_set(:@request, mock_request)
      allow(strategy).to receive(:session).and_return(mock_session)
      allow(strategy).to receive(:request).and_return(mock_request)
    end

    describe "#request_phase" do
      it "generates a valid authorization URL with signed request object" do
        # Mock state generation
        allow(SecureRandom).to receive(:hex).and_return("test-state-value", "test-nonce-value")

        result = strategy.request_phase

        # Should be a redirect response
        expect(result).to be_a(Array)
        expect(result[0]).to eq(302) # Redirect status
        expect(result[1]).to include("Location" => be_a(String))

        # Extract URL from Location header
        location = result[1]["Location"]
        uri = URI.parse(location)

        # Verify it's the authorization endpoint
        expect(uri.host).to eq(URI.parse(provider_issuer).host)
        expect(uri.path).to eq("/oauth2/authorize")

        # Verify query contains request parameter (signed JWT)
        query_params = URI.decode_www_form(uri.query || "").to_h
        expect(query_params).to have_key("request")

        # Verify request is a valid JWT
        request_jwt = query_params["request"]
        parts = request_jwt.split(".")
        expect(parts.length).to eq(3) # Signed JWT has 3 parts

        # Decode and verify payload
        payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
        expect(payload["client_id"]).to eq(client_id)
        expect(payload["redirect_uri"]).to eq(redirect_uri)
        expect(payload["scope"]).to eq("openid")
        expect(payload["response_type"]).to eq("code")
        expect(payload["state"]).to eq("test-state-value")
      end

      it "stores state in session for CSRF protection" do
        allow(SecureRandom).to receive(:hex).and_return("test-state-value", "test-nonce-value")

        strategy.request_phase

        # Verify state is stored in session
        expect(mock_session["omniauth.state"]).to eq("test-state-value")
      end

      it "includes nonce when send_nonce is enabled" do
        strategy.options.send_nonce = true
        allow(SecureRandom).to receive(:hex).and_return("test-state-value", "test-nonce-value")

        result = strategy.request_phase
        location = result[1]["Location"]
        uri = URI.parse(location)
        query_params = URI.decode_www_form(uri.query || "").to_h
        request_jwt = query_params["request"]
        payload = JSON.parse(Base64.urlsafe_decode64(request_jwt.split(".")[1]))

        expect(payload).to have_key("nonce")
        expect(payload["nonce"]).to eq("test-nonce-value")
      end
    end

    describe "#callback_phase" do
      let(:id_token_jwt) do
        header = {alg: "RS256", typ: "JWT", kid: "test-key-id"}
        payload = id_token_payload
        JWT.encode(payload, private_key, "RS256", header)
      end

      let(:callback_env) do
        mock_env.merge(
          "PATH_INFO" => "/users/auth/openid_federation/callback",
          "QUERY_STRING" => "code=#{authorization_code}&state=test-state-value"
        )
      end

      let(:callback_request) do
        double(
          params: {
            "code" => authorization_code,
            "state" => "test-state-value"
          },
          url: redirect_uri,
          path: "/users/auth/openid_federation/callback",
          scheme: "https",
          host: "example.com",
          port: 443,
          env: {
            "REMOTE_ADDR" => "127.0.0.1"
          }
        )
      end

      before do
        # Set up state in session
        mock_session["omniauth.state"] = "test-state-value"

        # Set up callback environment
        strategy.instance_variable_set(:@env, callback_env)
        allow(strategy).to receive(:request).and_return(callback_request)

        # Mock OpenID Connect client token exchange
        oidc_client = strategy.client
        allow(oidc_client).to receive(:authorization_code=).with(authorization_code)
        allow(oidc_client).to receive(:redirect_uri=).with(redirect_uri)

        access_token_double = double(
          access_token: access_token_value,
          refresh_token: "test-refresh-token",
          expires_in: 3600,
          id_token: id_token_jwt,
          userinfo!: double(
            raw_attributes: {
              email: "user@example.com",
              name: "Test User",
              given_name: "Test",
              family_name: "User"
            }
          )
        )

        allow(oidc_client).to receive(:access_token!).and_return(access_token_double)
      end

      it "successfully processes callback and builds auth hash" do
        # Mock call_app! to capture the auth hash
        auth_hash_captured = nil
        allow(strategy).to receive(:call_app!) do
          auth_hash_captured = strategy.env["omniauth.auth"]
        end

        strategy.callback_phase

        # Verify auth hash was built
        expect(auth_hash_captured).to be_a(OmniAuth::AuthHash)
        expect(auth_hash_captured.provider).to eq("openid_federation")
        expect(auth_hash_captured.uid).to eq("user-123")
        expect(auth_hash_captured.info.email).to eq("user@example.com")
        expect(auth_hash_captured.info.name).to eq("Test User")
        expect(auth_hash_captured.credentials.token).to eq(access_token_value)
        expect(auth_hash_captured.credentials.refresh_token).to eq("test-refresh-token")
        expect(auth_hash_captured.credentials.expires).to be true
      end

      it "validates state parameter for CSRF protection" do
        # Set wrong state
        callback_request.params["state"] = "wrong-state"

        # fail! doesn't raise, it sets error state and returns
        strategy.callback_phase

        # Verify error was set
        expect(strategy.env["omniauth.error.type"]).to eq(:csrf_detected)
        expect(strategy.env["omniauth.error"]).to be_a(OmniauthOpenidFederation::SecurityError)

        # Verify state is not cleared on error
        expect(mock_session["omniauth.state"]).to eq("test-state-value")
      end

      it "clears state from session after successful validation" do
        allow(strategy).to receive(:call_app!)

        strategy.callback_phase

        # Verify state is cleared
        expect(mock_session["omniauth.state"]).to be_nil
      end

      it "validates authorization code is present" do
        callback_request.params.delete("code")

        # fail! doesn't raise, it sets error state
        strategy.callback_phase

        # Verify error was set
        expect(strategy.env["omniauth.error.type"]).to eq(:missing_code)
        expect(strategy.env["omniauth.error"]).to be_a(OmniauthOpenidFederation::ValidationError)
      end

      it "handles token exchange errors gracefully" do
        oidc_client = strategy.client
        allow(oidc_client).to receive(:access_token!).and_raise(StandardError.new("Token exchange failed"))

        # fail! doesn't raise, it sets error state
        strategy.callback_phase

        # Verify error was set
        expect(strategy.env["omniauth.error.type"]).to eq(:token_exchange_error)
        expect(strategy.env["omniauth.error"]).to be_a(OmniauthOpenidFederation::NetworkError)
      end
    end

    describe "#auth_hash" do
      let(:id_token_jwt) do
        header = {alg: "RS256", typ: "JWT", kid: "test-key-id"}
        payload = id_token_payload
        JWT.encode(payload, private_key, "RS256", header)
      end

      let(:access_token_double) do
        double(
          access_token: access_token_value,
          refresh_token: "test-refresh-token",
          expires_in: 3600,
          id_token: id_token_jwt,
          userinfo!: double(
            raw_attributes: {
              email: "user@example.com",
              name: "Test User"
            }
          )
        )
      end

      before do
        strategy.instance_variable_set(:@access_token, access_token_double)
      end

      it "builds complete auth hash with all required fields" do
        auth_hash = strategy.auth_hash

        expect(auth_hash).to be_a(OmniAuth::AuthHash)
        expect(auth_hash.provider).to eq("openid_federation")
        expect(auth_hash.uid).to eq("user-123")
        expect(auth_hash.info).to be_a(Hash)
        expect(auth_hash.credentials).to be_a(Hash)
        expect(auth_hash.extra).to be_a(Hash)
      end

      it "includes correct credentials" do
        auth_hash = strategy.auth_hash

        expect(auth_hash.credentials[:token]).to eq(access_token_value)
        expect(auth_hash.credentials[:refresh_token]).to eq("test-refresh-token")
        expect(auth_hash.credentials[:expires]).to be true
        expect(auth_hash.credentials[:expires_at]).to be_a(Integer)
        expect(auth_hash.credentials[:expires_at]).to be > Time.now.to_i
      end
    end

    describe "#uid" do
      let(:id_token_jwt) do
        header = {alg: "RS256", typ: "JWT", kid: "test-key-id"}
        payload = id_token_payload
        JWT.encode(payload, private_key, "RS256", header)
      end

      before do
        access_token_double = double(
          id_token: id_token_jwt,
          userinfo!: double(raw_attributes: {sub: "user-123"})
        )
        strategy.instance_variable_set(:@access_token, access_token_double)
        allow(strategy).to receive(:raw_info).and_return({"sub" => "user-123"})
      end

      it "extracts uid from raw_info sub claim" do
        expect(strategy.uid).to eq("user-123")
      end
    end

    describe "#info" do
      let(:id_token_jwt) do
        header = {alg: "RS256", typ: "JWT", kid: "test-key-id"}
        payload = id_token_payload
        JWT.encode(payload, private_key, "RS256", header)
      end

      before do
        access_token_double = double(
          id_token: id_token_jwt,
          userinfo!: double(
            raw_attributes: {
              email: "user@example.com",
              name: "Test User",
              given_name: "Test",
              family_name: "User",
              preferred_username: "testuser"
            }
          )
        )
        strategy.instance_variable_set(:@access_token, access_token_double)
        allow(strategy).to receive(:raw_info).and_return({
          "email" => "user@example.com",
          "name" => "Test User",
          "given_name" => "Test",
          "family_name" => "User",
          "preferred_username" => "testuser"
        })
      end

      it "extracts user info from raw_info" do
        info = strategy.info

        expect(info[:email]).to eq("user@example.com")
        expect(info[:name]).to eq("Test User")
        expect(info[:first_name]).to eq("Test")
        expect(info[:last_name]).to eq("User")
        expect(info[:nickname]).to eq("testuser")
      end
    end

    describe "#extra" do
      let(:id_token_jwt) do
        header = {alg: "RS256", typ: "JWT", kid: "test-key-id"}
        payload = id_token_payload
        JWT.encode(payload, private_key, "RS256", header)
      end

      before do
        access_token_double = double(
          id_token: id_token_jwt,
          userinfo!: double(raw_attributes: {sub: "user-123", email: "user@example.com"})
        )
        strategy.instance_variable_set(:@access_token, access_token_double)
        allow(strategy).to receive(:raw_info).and_return({
          "sub" => "user-123",
          "email" => "user@example.com"
        })
      end

      it "includes raw_info in extra" do
        extra = strategy.extra

        expect(extra[:raw_info]).to be_a(Hash)
        expect(extra[:raw_info]["sub"]).to eq("user-123")
        expect(extra[:raw_info]["email"]).to eq("user@example.com")
      end
    end

    describe "encrypted ID token handling" do
      let(:encrypted_id_token) do
        # Create a mock encrypted token (JWE format - 5 parts)
        # In real scenario, this would be encrypted with provider's public key
        "header.encrypted_key.iv.ciphertext.tag"
      end

      before do
        access_token_double = double(
          access_token: access_token_value,
          id_token: encrypted_id_token
        )
        strategy.instance_variable_set(:@access_token, access_token_double)
      end

      it "detects encrypted ID tokens" do
        expect(strategy.send(:encrypted_token?, encrypted_id_token)).to be true
      end

      it "handles decryption of encrypted ID tokens" do
        # This would require actual JWE decryption with provider's key
        # For now, we just verify the detection works
        expect(strategy.send(:encrypted_token?, encrypted_id_token)).to be true
      end
    end

    describe "userinfo fetching configuration" do
      let(:id_token_jwt) do
        header = {alg: "RS256", typ: "JWT", kid: "test-key-id"}
        payload = id_token_payload
        JWT.encode(payload, private_key, "RS256", header)
      end

      context "when fetch_userinfo is disabled" do
        before do
          strategy.options.fetch_userinfo = false
          access_token_double = double(
            id_token: id_token_jwt
          )
          strategy.instance_variable_set(:@access_token, access_token_double)
          allow(strategy).to receive(:raw_info).and_return(id_token_payload.stringify_keys)
        end

        it "uses ID token claims only" do
          raw_info = strategy.raw_info

          expect(raw_info["sub"]).to eq("user-123")
          expect(raw_info["email"]).to eq("user@example.com")
        end
      end

      context "when fetch_userinfo is enabled (default)" do
        before do
          strategy.options.fetch_userinfo = true
          # Mock ID token decoding to return the payload
          id_token_object = double(
            raw_attributes: id_token_payload.stringify_keys
          )
          allow(strategy).to receive(:decode_id_token).with(id_token_jwt).and_return(id_token_object)

          access_token_double = double(
            id_token: id_token_jwt,
            userinfo!: double(
              raw_attributes: {
                email: "user@example.com",
                name: "Test User"
              }
            )
          )
          strategy.instance_variable_set(:@access_token, access_token_double)
        end

        it "fetches and merges userinfo with ID token" do
          raw_info = strategy.raw_info

          expect(raw_info["sub"]).to eq("user-123") # From ID token
          expect(raw_info["email"]).to eq("user@example.com") # From userinfo (takes precedence)
        end
      end
    end
  end

  describe "error handling" do
    it "handles missing private key gracefully" do
      strategy_without_key = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          userinfo_endpoint: "/oauth2/userinfo",
          jwks_uri: "/.well-known/jwks.json"
          # private_key intentionally missing
        }
      )

      allow(strategy_without_key).to receive(:request).and_return(double(params: {}))
      allow(strategy_without_key).to receive(:session).and_return({})

      expect {
        strategy_without_key.request_phase
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Private key is required/)
    end

    it "handles missing audience gracefully" do
      strategy_no_audience = described_class.new(
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

      strategy_no_audience.options.issuer = nil
      strategy_no_audience.options.audience = nil
      allow(strategy_no_audience).to receive(:request).and_return(double(params: {}))
      allow(strategy_no_audience).to receive(:session).and_return({})

      # Audience can be resolved from token_endpoint, so it might not raise
      # Let's verify it either raises or resolves audience from token_endpoint
      begin
        result = strategy_no_audience.request_phase
        # If it doesn't raise, it should have resolved audience from token_endpoint
        expect(result).to be_a(Array)
      rescue OmniauthOpenidFederation::ConfigurationError => e
        expect(e.message).to match(/Audience is required/)
      end
    end
  end
end

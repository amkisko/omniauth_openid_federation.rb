require "spec_helper"

require "sequel"
require "roda"
require "rodauth"
require "rodauth/features/omniauth"

RSpec.describe "Rodauth integration with omniauth_openid_federation", type: :integration do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:provider_issuer) { "https://provider.example.com" }
  let(:client_id) { "test-client-id" }
  let(:redirect_uri) { "https://example.com/auth/openid_federation/callback" }

  def build_rodauth_app
    # Capture let variables for use inside Class.new block
    app_provider_issuer = provider_issuer
    app_client_id = client_id
    app_redirect_uri = redirect_uri
    app_private_key = private_key

    db = Sequel.sqlite

    db.create_table :accounts do
      primary_key :id
      String :email, null: false
    end

    db.create_table :account_identities do
      primary_key :id
      foreign_key :account_id, :accounts, null: false
      String :provider, null: false
      String :uid, null: false
      index [:provider, :uid], unique: true
    end

    # Define a named class to avoid rodauth helper name conflicts with anonymous classes
    rodauth_app_class = Class.new(Roda) do
      plugin :sessions, secret: SecureRandom.hex(32) # 64 characters minimum required by Roda
      plugin :json

      plugin :rodauth, json: true, csrf: false do
        db db
        enable :omniauth

        omniauth_prefix "/auth"

        # Override CSRF check for testing
        def omniauth_request_validation_phase
          # Skip CSRF check for testing
        end

        omniauth_provider :openid_federation,
          nil,
          nil,
          strategy_class: OmniAuth::Strategies::OpenIDFederation,
          name: :openid_federation,
          issuer: app_provider_issuer,
          audience: app_provider_issuer,
          entity_statement_url: "#{app_provider_issuer}/.well-known/openid-federation",
          client_options: {
            identifier: app_client_id,
            redirect_uri: app_redirect_uri,
            host: URI.parse(app_provider_issuer).host,
            scheme: URI.parse(app_provider_issuer).scheme,
            authorization_endpoint: "/oauth2/authorize",
            token_endpoint: "/oauth2/token",
            userinfo_endpoint: "/oauth2/userinfo",
            jwks_uri: "/.well-known/jwks.json",
            private_key: app_private_key
          }
      end

      route do |r|
        # Handle rodauth routes
        # This automatically handles omniauth routes based on omniauth_prefix setting
        # The route_omniauth! method is called from route! which is invoked by r.rodauth
        # Based on rodauth-omniauth source: route_omniauth! is called automatically
        r.rodauth

        r.root do
          if rodauth.logged_in?
            {logged_in: true, account_id: rodauth.session_value}
          else
            {logged_in: false}
          end
        end
      end
    end
    
    rodauth_app_class
  end

  let(:app) { build_rodauth_app }

  let(:provider_jwks) do
    jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key, use: "sig")
    jwk[:kid] = "test-key-id"
    {keys: [jwk]}
  end

  let(:entity_statement_jwt) do
    payload = {
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

    header = {alg: "RS256", typ: "entity-statement+jwt", kid: "test-key-id"}
    JWT.encode(payload, private_key, "RS256", header)
  end

  before do
    stub_provider_endpoints(provider_issuer: provider_issuer, jwks: provider_jwks)
    stub_relative_path_endpoints(host: URI.parse(provider_issuer).host)

    WebMock.stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
      .to_return(
        status: 200,
        body: provider_jwks.to_json,
        headers: {"Content-Type" => "application/json"}
      )

    WebMock.stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
      .to_return(
        status: 200,
        body: entity_statement_jwt,
        headers: {"Content-Type" => "application/jwt"}
      )
  end

  describe "JSON omniauth flow" do
    it "returns authorize URL for request phase and successfully handles callback" do
      require "rack/mock"

      # Ensure OmniAuth test mode is disabled for this integration test
      # (some other tests may set it to true, which can affect behavior)
      original_test_mode = OmniAuth.config.test_mode if defined?(OmniAuth)
      OmniAuth.config.test_mode = false if defined?(OmniAuth)

      begin
        # Use a shared session hash to maintain state between requests
        session = {}
        
        # Create a session-aware app wrapper
        session_app = lambda do |env|
          env["rack.session"] = session
          app.call(env)
        end

        request = Rack::MockRequest.new(session_app)

        # OmniAuth request phase - use POST (standard OmniAuth flow for rodauth-omniauth)
        # rodauth-omniauth should handle this automatically
        response = request.post("/auth/openid_federation", "HTTP_ACCEPT" => "application/json")
      
      # If we get a redirect to root, try to get more info or check if it's an error redirect
      if response.status == 302 && response["Location"] == "/"
        # Try to follow the redirect and see what we get
        root_response = request.get("/")
        raise "OmniAuth redirecting to root. Root response: status=#{root_response.status}, body=#{root_response.body[0..500]}"
      end
      
      # If it's a redirect to the provider, that's expected
      # Extract the authorization URL from Location header

      # rodauth-omniauth may return JSON with authorize_url or redirect
      # Handle both cases for compatibility
      authorize_url = if response.status == 200
        body = JSON.parse(response.body)
        body.fetch("authorize_url")
      elsif response.status == 302
        # Follow redirect and extract URL from Location header
        location = response["Location"]
        # If relative URL, make it absolute using provider_issuer as base
        if location && !location.start_with?("http")
          # Handle relative paths properly - if it starts with /, it's absolute path
          if location.start_with?("/")
            "#{provider_issuer}#{location}"
          else
            URI.join(provider_issuer, location).to_s
          end
        else
          location
        end
      else
        raise "Unexpected response status: #{response.status}, body: #{response.body[0..500]}"
      end

      # Verify the authorization URL points to the provider (not callback)
      uri = URI.parse(authorize_url)
      
      # The authorization URL should point to the provider's authorization endpoint
      # If it points to callback, that's an error - log it for debugging
      if uri.path.include?("callback")
        raise "Authorization URL points to callback instead of provider: #{authorize_url}. Response status: #{response.status}, body: #{response.body[0..500]}"
      end
      
      params = URI.decode_www_form(uri.query || "").to_h
      
      # Verify the authorization URL is correct
      expect(uri.host).to eq(URI.parse(provider_issuer).host), 
        "Expected host #{URI.parse(provider_issuer).host}, got #{uri.host} from URL: #{authorize_url}"
      expect(uri.path).to eq("/oauth2/authorize"),
        "Expected path /oauth2/authorize, got #{uri.path} from URL: #{authorize_url}"
      expect(params).to include("request"),
        "Expected 'request' parameter in query string, got: #{params.keys.inspect}"

      # Extract state parameter from session (set during request phase)
      # OmniAuth stores state in session["omniauth.state"]
      state_param = session["omniauth.state"]
      expect(state_param).to be_present, "Expected 'state' in session after request phase. Session keys: #{session.keys.inspect}"

      authorization_code = "test-auth-code-123"
      id_token_payload = {
        iss: provider_issuer,
        sub: "user-123",
        aud: client_id,
        exp: Time.now.to_i + 3600,
        iat: Time.now.to_i,
        nonce: "test-nonce",
        email: "user@example.com",
        name: "Test User"
      }

      id_token_jwt = JWT.encode(
        id_token_payload,
        private_key,
        "RS256",
        {alg: "RS256", typ: "JWT", kid: "test-key-id"}
      )

      WebMock.stub_request(:post, "#{provider_issuer}/oauth2/token")
        .to_return(
          status: 200,
          body: {
            access_token: "access-token",
            token_type: "Bearer",
            expires_in: 3600,
            id_token: id_token_jwt
          }.to_json,
          headers: {"Content-Type" => "application/json"}
        )

      WebMock.stub_request(:get, "#{provider_issuer}/oauth2/userinfo")
        .to_return(
          status: 200,
          body: {
            email: "user@example.com",
            name: "Test User"
          }.to_json,
          headers: {"Content-Type" => "application/json"}
        )

      # Use the same Rack::MockRequest instance to maintain session state
      # The state parameter must match what was set in the session during request phase
      callback_response = request.get(
        "/auth/openid_federation/callback?code=#{authorization_code}&state=#{state_param}",
        "HTTP_ACCEPT" => "application/json"
      )

      # rodauth-omniauth may return 200 JSON or 302 redirect after successful login
      # For JSON mode, it should return 200 with success message
      if callback_response.status == 200
        callback_body = JSON.parse(callback_response.body)
        expect(callback_body["success"]).to be_a(String)
      elsif callback_response.status == 302
        # If redirect, follow it to verify login was successful
        redirect_location = callback_response["Location"]
        expect(redirect_location).to be_present, "Expected redirect location after successful login"
        
        # Follow redirect to verify login
        if redirect_location.start_with?("/")
          follow_response = request.get(redirect_location, "HTTP_ACCEPT" => "application/json")
          expect(follow_response.status).to eq(200)
        end
      else
        raise "Unexpected callback response status: #{callback_response.status}, body: #{callback_response.body[0..500]}"
      end

      # Verify login by checking root endpoint
      root_response = request.get("/", "HTTP_ACCEPT" => "application/json")
      expect(root_response.status).to eq(200)
      root_body = JSON.parse(root_response.body)
      expect(root_body["logged_in"]).to eq(true)
      ensure
        # Restore original OmniAuth test mode
        OmniAuth.config.test_mode = original_test_mode if defined?(OmniAuth) && defined?(original_test_mode)
      end
    end
  end
end



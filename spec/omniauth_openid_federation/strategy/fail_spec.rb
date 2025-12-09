require "spec_helper"
require "omniauth/test"
require "rack"

OmniAuth.config.test_mode = true

RSpec.describe OmniAuth::Strategies::OpenIDFederation do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:provider_issuer) { "https://provider.example.com" }
  let(:client_id) { "test-client-id" }
  let(:redirect_uri) { "http://localhost:3000/auth/openid_federation/callback" }

  def app
    strategy_class = OmniAuth::Strategies::OpenIDFederation
    app_client_id = client_id
    app_redirect_uri = redirect_uri
    app_private_key = private_key
    app_provider_issuer = provider_issuer
    Rack::Builder.new do
      use OmniAuth::Test::PhonySession
      use strategy_class, app_client_id, "client-secret-123",
        name: "openid_federation",
        client_options: {
          identifier: app_client_id,
          secret: "client-secret-123",
          redirect_uri: app_redirect_uri,
          private_key: app_private_key,
          host: URI.parse(app_provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          jwks_uri: "https://provider.example.com/.well-known/jwks.json"
        },
        issuer: app_provider_issuer,
        audience: app_provider_issuer
      run lambda { |env| [404, {"Content-Type" => "text/plain"}, [env.key?("omniauth.auth").to_s]] }
    end.to_app
  end

  describe "fail! method error paths" do
    # Test lines 206, 207, 210, 214, 221, 224, 234, 243, 252 in strategy.rb
    let(:strategy) do
      described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          jwks_uri: "https://provider.example.com/.well-known/jwks.json"
        },
        issuer: provider_issuer,
        audience: provider_issuer
      )
    end

    it "instruments authenticity_error in request_phase" do
      # Test lines 221-230: authenticity_error case
      env = Rack::MockRequest.env_for(
        "/auth/openid_federation",
        "rack.session" => {}
      )
      strategy.instance_variable_set(:@env, env)
      allow(strategy).to receive_messages(request: Rack::Request.new(env), session: {})

      # Simulate authenticity error
      exception = OmniAuth::AuthenticityError.new("CSRF token mismatch")
      allow(OmniauthOpenidFederation::Instrumentation).to receive(:notify_authenticity_error)

      strategy.fail!(:authenticity_error, exception)
      aggregate_failures do
        expect(OmniauthOpenidFederation::Instrumentation).to have_received(:notify_authenticity_error).with(
          hash_including(
            error_type: "authenticity_error",
            phase: "request_phase"
          )
        )
        expect(env["omniauth.error.type"]).to eq(:authenticity_error)
      end
    end

    it "instruments authenticity_error in callback_phase" do
      # Test lines 221-230: authenticity_error case in callback
      env = Rack::MockRequest.env_for(
        "/auth/openid_federation/callback",
        "rack.session" => {}
      )
      strategy.instance_variable_set(:@env, env)
      allow(strategy).to receive_messages(request: Rack::Request.new(env), session: {})

      exception = OmniAuth::AuthenticityError.new("CSRF token mismatch")
      allow(OmniauthOpenidFederation::Instrumentation).to receive(:notify_authenticity_error)

      strategy.fail!(:authenticity_error, exception)
      expect(OmniauthOpenidFederation::Instrumentation).to have_received(:notify_authenticity_error).with(
        hash_including(
          error_type: "authenticity_error",
          phase: "callback_phase"
        )
      )
    end

    it "instruments csrf_detected error" do
      # Test lines 231-239: csrf_detected case
      env = Rack::MockRequest.env_for(
        "/auth/openid_federation",
        "rack.session" => {}
      )
      strategy.instance_variable_set(:@env, env)
      allow(strategy).to receive_messages(request: Rack::Request.new(env), session: {})

      allow(OmniauthOpenidFederation::Instrumentation).to receive(:notify_csrf_detected)

      strategy.fail!(:csrf_detected)
      expect(OmniauthOpenidFederation::Instrumentation).to have_received(:notify_csrf_detected).with(
        hash_including(
          error_type: "csrf_detected",
          phase: "request_phase"
        )
      )
    end

    it "instruments missing_code error" do
      # Test lines 240-249: missing_code case
      env = Rack::MockRequest.env_for(
        "/auth/openid_federation/callback",
        "rack.session" => {}
      )
      strategy.instance_variable_set(:@env, env)
      allow(strategy).to receive_messages(request: Rack::Request.new(env), session: {})

      exception = OmniauthOpenidFederation::ValidationError.new("Missing authorization code")
      allow(OmniauthOpenidFederation::Instrumentation).to receive(:notify_unexpected_authentication_break)

      strategy.fail!(:missing_code, exception)
      expect(OmniauthOpenidFederation::Instrumentation).to have_received(:notify_unexpected_authentication_break).with(
        hash_including(
          stage: "callback_phase",
          error_type: "missing_code"
        )
      )
    end

    it "instruments token_exchange_error" do
      # Test lines 240-249: token_exchange_error case
      env = Rack::MockRequest.env_for(
        "/auth/openid_federation/callback",
        "rack.session" => {}
      )
      strategy.instance_variable_set(:@env, env)
      allow(strategy).to receive_messages(request: Rack::Request.new(env), session: {})

      exception = OmniauthOpenidFederation::NetworkError.new("Token exchange failed")
      allow(OmniauthOpenidFederation::Instrumentation).to receive(:notify_unexpected_authentication_break)

      strategy.fail!(:token_exchange_error, exception)
      expect(OmniauthOpenidFederation::Instrumentation).to have_received(:notify_unexpected_authentication_break).with(
        hash_including(
          stage: "callback_phase",
          error_type: "token_exchange_error"
        )
      )
    end

    it "instruments unknown error type" do
      # Test lines 250-259: else case (unknown error type)
      env = Rack::MockRequest.env_for(
        "/auth/openid_federation",
        "rack.session" => {}
      )
      strategy.instance_variable_set(:@env, env)
      allow(strategy).to receive_messages(request: Rack::Request.new(env), session: {})

      exception = StandardError.new("Unknown error")
      allow(OmniauthOpenidFederation::Instrumentation).to receive(:notify_unexpected_authentication_break)

      strategy.fail!(:unknown_error, exception)
      expect(OmniauthOpenidFederation::Instrumentation).to have_received(:notify_unexpected_authentication_break).with(
        hash_including(
          stage: "request_phase",
          error_type: "unknown_error"
        )
      )
    end

    it "handles fail! with nil exception" do
      # Test lines 206-207: exception&.message when exception is nil
      env = Rack::MockRequest.env_for(
        "/auth/openid_federation",
        "rack.session" => {}
      )
      strategy.instance_variable_set(:@env, env)
      allow(strategy).to receive_messages(request: Rack::Request.new(env), session: {})

      allow(OmniauthOpenidFederation::Instrumentation).to receive(:notify_unexpected_authentication_break)

      strategy.fail!(:unknown_error, nil)
      expect(OmniauthOpenidFederation::Instrumentation).to have_received(:notify_unexpected_authentication_break).with(
        hash_including(
          error_message: "unknown_error",
          error_class: "UnknownError"
        )
      )
    end

    it "skips instrumentation when already instrumented" do
      # Test line 202: already_instrumented check
      env = Rack::MockRequest.env_for(
        "/auth/openid_federation",
        "rack.session" => {}
      )
      env["omniauth_openid_federation.instrumented"] = true
      strategy.instance_variable_set(:@env, env)
      allow(strategy).to receive_messages(request: Rack::Request.new(env), session: {})

      # Should not call instrumentation
      allow(OmniauthOpenidFederation::Instrumentation).to receive(:notify_authenticity_error)
      allow(OmniauthOpenidFederation::Instrumentation).to receive(:notify_csrf_detected)
      allow(OmniauthOpenidFederation::Instrumentation).to receive(:notify_unexpected_authentication_break)

      strategy.fail!(:authenticity_error, OmniAuth::AuthenticityError.new("CSRF"))
      aggregate_failures do
        expect(OmniauthOpenidFederation::Instrumentation).not_to have_received(:notify_authenticity_error)
        expect(OmniauthOpenidFederation::Instrumentation).not_to have_received(:notify_csrf_detected)
        expect(OmniauthOpenidFederation::Instrumentation).not_to have_received(:notify_unexpected_authentication_break)
      end
    end

    it "includes request_info in instrumentation" do
      # Test lines 212-218: request_info building
      env = Rack::MockRequest.env_for(
        "/auth/openid_federation",
        "REMOTE_ADDR" => "192.168.1.1",
        "HTTP_USER_AGENT" => "TestAgent/1.0"
      )
      strategy.instance_variable_set(:@env, env)
      allow(strategy).to receive_messages(request: Rack::Request.new(env), session: {})

      allow(OmniauthOpenidFederation::Instrumentation).to receive(:notify_authenticity_error)

      strategy.fail!(:authenticity_error, OmniAuth::AuthenticityError.new("CSRF"))
      expect(OmniauthOpenidFederation::Instrumentation).to have_received(:notify_authenticity_error).with(
        hash_including(
          request_info: hash_including(
            remote_ip: "192.168.1.1",
            user_agent: "TestAgent/1.0",
            path: "/auth/openid_federation",
            method: "GET"
          )
        )
      )
    end
  end
end

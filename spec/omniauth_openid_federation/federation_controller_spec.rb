require "spec_helper"

# Skip controller tests if Rails/ActionController is not available
if defined?(Rails) && defined?(ActionController::Base)
  RSpec.describe OmniauthOpenidFederation::FederationController do
    include Rack::Test::Methods if defined?(Rack::Test::Methods)

    def app
      # Create a minimal Rails app for testing
      unless defined?(Rails)
        skip "Rails not available"
      end

      # Set up routes
      Rails.application.routes.draw do
        get "/.well-known/openid-federation", to: "omniauth_openid_federation/federation#show"
        get "/.well-known/jwks.json", to: "omniauth_openid_federation/federation#jwks"
        get "/.well-known/signed-jwks.json", to: "omniauth_openid_federation/federation#signed_jwks"
      end

      Rails.application
    end
    let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:public_key) { private_key.public_key }
    let(:entity_jwk) { JWT::JWK.new(public_key) }
    let(:issuer) { "https://provider.example.com" }
    let(:subject) { "https://provider.example.com" }
    let(:jwks) do
      {
        "keys" => [entity_jwk.export.stringify_keys]
      }
    end
    let(:metadata) do
      {
        openid_provider: {
          issuer: issuer,
          authorization_endpoint: "#{issuer}/oauth2/authorize",
          token_endpoint: "#{issuer}/oauth2/token",
          userinfo_endpoint: "#{issuer}/oauth2/userinfo",
          jwks_uri: "#{issuer}/.well-known/jwks.json",
          signed_jwks_uri: "#{issuer}/.well-known/signed-jwks.json"
        }
      }
    end

    before do
      # Configure federation endpoint
      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.issuer = issuer
        config.subject = subject
        config.private_key = private_key
        config.jwks = jwks
        config.metadata = metadata
      end

      # Clear Rails cache if available
      if defined?(Rails) && Rails.cache
        Rails.cache.clear
      end
    end

    describe "GET #show" do
      it "returns entity statement JWT" do
        get "/.well-known/openid-federation"

        expect(response).to have_http_status(:ok)
        expect(response.content_type).to include("application/jwt")
        expect(response.body).to be_a(String)
        expect(response.body.split(".").length).to eq(3) # JWT has 3 parts
      end

      it "sets Cache-Control header" do
        get "/.well-known/openid-federation"

        expect(response.headers["Cache-Control"]).to eq("public, max-age=3600")
      end

      it "returns service unavailable when not configured" do
        OmniauthOpenidFederation::FederationEndpoint.configure do |config|
          config.issuer = nil
        end

        get "/.well-known/openid-federation"

        expect(response).to have_http_status(:service_unavailable)
        expect(response.body).to include("not configured")
      end
    end

    describe "GET #jwks" do
      it "returns JWKS in JSON format" do
        get "/.well-known/jwks.json"

        expect(response).to have_http_status(:ok)
        expect(response.content_type).to include("application/json")

        json_response = JSON.parse(response.body)
        expect(json_response).to have_key("keys")
        expect(json_response["keys"]).to be_an(Array)
      end

      it "uses current_jwks when configured" do
        custom_jwks = {
          "keys" => [
            {
              "kty" => "RSA",
              "kid" => "custom-key",
              "use" => "sig"
            }
          ]
        }
        OmniauthOpenidFederation::FederationEndpoint.configure do |config|
          config.current_jwks = custom_jwks
        end

        get "/.well-known/jwks.json"

        json_response = JSON.parse(response.body)
        expect(json_response["keys"].first["kid"]).to eq("custom-key")
      end

      it "caches JWKS when Rails.cache is available" do
        skip "Rails.cache not available" unless defined?(Rails) && Rails.cache

        get "/.well-known/jwks.json"
        first_response = JSON.parse(response.body)

        # Second request should use cache
        get "/.well-known/jwks.json"
        second_response = JSON.parse(response.body)

        expect(first_response).to eq(second_response)
      end

      it "sets Cache-Control header" do
        get "/.well-known/jwks.json"

        expect(response.headers["Cache-Control"]).to eq("public, max-age=3600")
      end

      it "returns service unavailable when not configured" do
        OmniauthOpenidFederation::FederationEndpoint.configure do |config|
          config.issuer = nil
        end

        get "/.well-known/jwks.json"

        expect(response).to have_http_status(:service_unavailable)
        json_response = JSON.parse(response.body)
        expect(json_response).to have_key("error")
      end
    end

    describe "GET #signed_jwks" do
      it "returns signed JWKS JWT" do
        get "/.well-known/signed-jwks.json"

        expect(response).to have_http_status(:ok)
        expect(response.content_type).to include("application/jwt")
        expect(response.body).to be_a(String)
        expect(response.body.split(".").length).to eq(3) # JWT has 3 parts
      end

      it "returns valid JWT that can be decoded" do
        get "/.well-known/signed-jwks.json"

        decoded = JWT.decode(response.body, public_key, true, {algorithm: "RS256"})
        payload = decoded.first

        expect(payload).to have_key("jwks")
        expect(payload["jwks"]).to have_key("keys")
      end

      it "uses signed_jwks_payload when configured" do
        custom_jwks = {
          "keys" => [
            {
              "kty" => "RSA",
              "kid" => "custom-signed-key",
              "use" => "sig"
            }
          ]
        }
        OmniauthOpenidFederation::FederationEndpoint.configure do |config|
          config.signed_jwks_payload = custom_jwks
        end

        get "/.well-known/signed-jwks.json"

        decoded = JWT.decode(response.body, public_key, true, {algorithm: "RS256"})
        payload = decoded.first

        expect(payload["jwks"]["keys"].first["kid"]).to eq("custom-signed-key")
      end

      it "caches signed JWKS when Rails.cache is available" do
        skip "Rails.cache not available" unless defined?(Rails) && Rails.cache

        get "/.well-known/signed-jwks.json"
        first_response = response.body

        # Second request should use cache
        get "/.well-known/signed-jwks.json"
        second_response = response.body

        expect(first_response).to eq(second_response)
      end

      it "sets Cache-Control header" do
        get "/.well-known/signed-jwks.json"

        expect(response.headers["Cache-Control"]).to eq("public, max-age=3600")
      end

      it "returns service unavailable when not configured" do
        OmniauthOpenidFederation::FederationEndpoint.configure do |config|
          config.issuer = nil
        end

        get "/.well-known/signed-jwks.json"

        expect(response).to have_http_status(:service_unavailable)
        expect(response.body).to include("not configured")
      end
    end
  end
  # Controller tests require Rails - if Rails is not available, these tests are skipped
  # by the outer conditional check
end

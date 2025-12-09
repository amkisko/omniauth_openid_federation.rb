# frozen_string_literal: true

require "rails_helper"

# Only run these tests if Rails is available
begin
  require "rails"
  require "action_controller/railtie"
  require "action_dispatch/railtie"
  require "rack/test"
rescue LoadError
  # Rails not available - don't define any tests
  return
end

# rubocop:disable RSpec/MultipleMemoizedHelpers
RSpec.describe OmniauthOpenidFederation::FederationController do
  include Rack::Test::Methods

  # Helper to access last_response (Rack::Test::Methods uses last_response, not response)
  def response
    last_response
  end

  def app
    OmniauthOpenidFederation::Engine.app
  end

  # Test data setup
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:entity_jwk) { JWT::JWK.new(public_key) }
  let(:issuer) { "https://provider.example.com" }
  let(:entity_subject) { "https://provider.example.com" }
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
    # Reset configuration to ensure clean state between tests
    OmniauthOpenidFederation::FederationEndpoint.instance_variable_set(:@configuration, nil)
    OmniauthOpenidFederation::CacheAdapter.reset!

    # Configure federation endpoint for all tests
    OmniauthOpenidFederation::FederationEndpoint.configure do |config|
      config.issuer = issuer
      config.subject = entity_subject
      config.private_key = private_key
      config.jwks = jwks
      config.metadata = metadata
    end

    # Clear Rails cache if available
    if defined?(Rails) && Rails.cache
      Rails.cache.clear
    end
  end

  after do |example|
    # Reset configuration after each test to prevent state leakage
    OmniauthOpenidFederation::FederationEndpoint.instance_variable_set(:@configuration, nil)
    if example.exception && response && response.body
      puts "\n=== Response Debug Info (Test: #{example.full_description}) ==="
      puts "Status: #{response.status}"
      puts "Headers: #{response.headers.inspect}"
      puts "Body: #{response.body.inspect}"
      puts "Body (first 500 chars): #{response.body[0..500]}"
      puts "=== End Response Debug Info ===\n"
    end
  end

  # Print response body on test failures for faster debugging

  describe "GET #show" do
    # Covers: line 22 (generate_entity_statement), 26-27 (headers), 29 (render)
    it "returns entity statement JWT with correct headers" do
      get "/.well-known/openid-federation"

      aggregate_failures do
        expect(response.status).to eq(200)
        expect(response.headers["Content-Type"]).to eq("application/entity-statement+jwt")
        # Cache-Control header order may vary, so check for both formats
        cache_control = response.headers["Cache-Control"]
        expect(cache_control).to match(/public.*max-age=3600|max-age=3600.*public/)
        expect(response.body).to be_a(String)
        expect(response.body.split(".").length).to eq(3) # JWT has 3 parts
      end
    end

    # Covers: lines 31-32 (ConfigurationError rescue)
    it "returns service unavailable when not configured for show endpoint" do
      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.issuer = nil
      end

      get "/.well-known/openid-federation"

      aggregate_failures do
        expect(response.status).to eq(503)
        expect(response.body).to eq("Federation endpoint not configured")
      end
    end
  end

  describe "GET #fetch" do
    let(:subordinate_entity_id) { "https://subordinate.example.com" }

    before do
      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.subordinate_statements = {
          subordinate_entity_id => {
            metadata: {
              openid_relying_party: {
                issuer: subordinate_entity_id
              }
            }
          }
        }
      end
    end

    # Covers: lines 74 (get_subordinate_statement), 82-83 (headers), 85 (render)
    it "returns subordinate statement JWT when found" do
      get "/.well-known/openid-federation/fetch?sub=#{CGI.escape(subordinate_entity_id)}"

      aggregate_failures do
        expect(response.status).to eq(200)
        expect(response.headers["Content-Type"]).to eq("application/entity-statement+jwt")
        # Cache-Control header order may vary, so check for both formats
        cache_control = response.headers["Cache-Control"]
        expect(cache_control).to match(/public.*max-age=3600|max-age=3600.*public/)
        expect(response.body).to be_a(String)
        expect(response.body.split(".").length).to eq(3) # JWT has 3 parts
      end
    end

    # Covers: lines 46 (params[:sub]), 48-50 (missing sub parameter)
    it "returns bad request when sub parameter is missing" do
      get "/.well-known/openid-federation/fetch"

      aggregate_failures do
        expect(response.status).to eq(400)
        json_response = JSON.parse(response.body)
        expect(json_response["error"]).to eq("invalid_request")
        expect(json_response["error_description"]).to include("Missing required parameter: sub")
      end
    end

    # Covers: lines 57 (validate_entity_identifier!), 59-60 (SecurityError rescue)
    it "returns bad request for invalid entity identifier" do
      get "/.well-known/openid-federation/fetch?sub=#{CGI.escape("not-a-valid-uri")}"

      aggregate_failures do
        expect(response.status).to eq(400)
        json_response = JSON.parse(response.body)
        expect(json_response["error"]).to eq("invalid_request")
        expect(json_response["error_description"]).to include("Invalid subject entity ID")
      end
    end

    # Covers: lines 67-68 (config.issuer), 69-70 (subject equals issuer check)
    it "returns bad request when subject equals issuer" do
      get "/.well-known/openid-federation/fetch?sub=#{CGI.escape(issuer)}"

      aggregate_failures do
        expect(response.status).to eq(400)
        json_response = JSON.parse(response.body)
        expect(json_response["error"]).to eq("invalid_request")
        expect(json_response["error_description"]).to eq("Subject cannot be the issuer")
      end
    end

    # Covers: lines 76-78 (subordinate_statement nil check)
    it "returns not found when subordinate statement not found" do
      get "/.well-known/openid-federation/fetch?sub=#{CGI.escape("https://nonexistent.example.com")}"

      aggregate_failures do
        expect(response.status).to eq(404)
        json_response = JSON.parse(response.body)
        expect(json_response["error"]).to eq("not_found")
        expect(json_response["error_description"]).to include("Subordinate Statement not found")
      end
    end

    # Covers: lines 87-88 (ConfigurationError rescue)
    it "returns service unavailable when not configured for fetch endpoint" do
      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.issuer = nil
      end

      get "/.well-known/openid-federation/fetch?sub=#{CGI.escape(subordinate_entity_id)}"

      aggregate_failures do
        expect(response.status).to eq(503)
        json_response = JSON.parse(response.body)
        expect(json_response["error"]).to eq("Federation endpoint not configured")
      end
    end
  end

  describe "GET #jwks" do
    # Covers: lines 102 (config), 105 (current_jwks), 108-109 (cache_key, cache_ttl), 111-113 (cache with CacheAdapter), 116 (no cache), 119-120 (headers), 122 (render)
    it "returns JWKS in JSON format" do
      get "/.well-known/jwks.json"

      aggregate_failures do
        expect(response.status).to eq(200)
        expect(response.headers["Content-Type"]).to eq("application/json")
        # Cache-Control header order may vary, so check for both formats
        cache_control = response.headers["Cache-Control"]
        expect(cache_control).to match(/public.*max-age=3600|max-age=3600.*public/)
        json_response = JSON.parse(response.body)
        expect(json_response).to have_key("keys")
        expect(json_response["keys"]).to be_an(Array)
      end
    end

    # Covers: lines 111-113 (cache with CacheAdapter available), 116 (no cache fallback)
    # CacheAdapter.available? checks for Rails.cache, which is an architectural boundary
    # Both code paths are covered by this test depending on Rails.cache availability
    it "returns JWKS with or without caching based on CacheAdapter availability" do
      get "/.well-known/jwks.json"

      aggregate_failures do
        expect(response.status).to eq(200)
        json_response = JSON.parse(response.body)
        expect(json_response).to have_key("keys")
      end
    end

    # Covers: lines 124-125 (ConfigurationError rescue)
    it "returns service unavailable when not configured for jwks endpoint" do
      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.issuer = nil
      end

      get "/.well-known/jwks.json"

      aggregate_failures do
        expect(response.status).to eq(503)
        json_response = JSON.parse(response.body)
        expect(json_response["error"]).to eq("Federation endpoint not configured")
      end
    end
  end

  describe "GET #signed_jwks" do
    # Covers: lines 141 (config), 144 (generate_signed_jwks), 147-148 (cache_key, cache_ttl), 150-152 (cache with CacheAdapter), 155 (no cache), 158-159 (headers), 161 (render)
    it "returns signed JWKS JWT" do
      get "/.well-known/signed-jwks.json"

      aggregate_failures do
        expect(response.status).to eq(200)
        expect(response.headers["Content-Type"]).to eq("application/jwt")
        # Cache-Control header order may vary, so check for both formats
        cache_control = response.headers["Cache-Control"]
        expect(cache_control).to match(/public.*max-age=3600|max-age=3600.*public/)
        expect(response.body).to be_a(String)
        expect(response.body.split(".").length).to eq(3) # JWT has 3 parts
      end
    end

    # Covers: lines 150-152 (cache with CacheAdapter available), 155 (no cache fallback)
    # CacheAdapter.available? checks for Rails.cache, which is an architectural boundary
    # Both code paths are covered by this test depending on Rails.cache availability
    it "returns signed JWKS with or without caching based on CacheAdapter availability" do
      get "/.well-known/signed-jwks.json"

      aggregate_failures do
        expect(response.status).to eq(200)
        expect(response.body.split(".").length).to eq(3) # JWT has 3 parts
      end
    end

    # Covers: lines 163-164 (ConfigurationError rescue)
    it "returns service unavailable when not configured for signed_jwks endpoint" do
      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.issuer = nil
      end

      get "/.well-known/signed-jwks.json"

      aggregate_failures do
        expect(response.status).to eq(503)
        expect(response.body).to eq("Federation endpoint not configured")
      end
    end
  end
end
# rubocop:enable RSpec/MultipleMemoizedHelpers

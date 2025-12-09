require "spec_helper"
require "rack"

RSpec.describe OmniauthOpenidFederation::RackEndpoint do
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

  let(:endpoint) { described_class.new }

  before do
    # Reset configuration
    OmniauthOpenidFederation::FederationEndpoint.instance_variable_set(:@configuration, nil)
    OmniauthOpenidFederation::CacheAdapter.reset!

    # Configure federation endpoint
    OmniauthOpenidFederation::FederationEndpoint.configure do |config|
      config.issuer = issuer
      config.subject = entity_subject
      config.private_key = private_key
      config.jwks = jwks
      config.metadata = metadata
    end
  end

  describe "#call" do
    context "with /openid-federation path" do
      it "returns entity statement" do
        env = Rack::MockRequest.env_for("/openid-federation")
        status, headers, body = endpoint.call(env)

        aggregate_failures do
          expect(status).to eq(200)
          expect(headers["Content-Type"]).to eq("application/jwt")
          expect(headers["Cache-Control"]).to eq("public, max-age=3600")
          expect(body.first).to be_a(String)
          expect(body.first.split(".").length).to eq(3) # JWT format
        end
      end
    end

    context "with /jwks.json path" do
      it "returns JWKS JSON" do
        env = Rack::MockRequest.env_for("/jwks.json")
        status, headers, body = endpoint.call(env)

        json_body = JSON.parse(body.first)
        aggregate_failures do
          expect(status).to eq(200)
          expect(headers["Content-Type"]).to eq("application/json")
          expect(headers["Cache-Control"]).to eq("public, max-age=3600")
          expect(json_body).to have_key("keys")
          expect(json_body["keys"]).to be_an(Array)
        end
      end

      context "with cache available" do
        let(:cache_store) { {} }
        let(:cache_adapter) do
          double("CacheAdapter").tap do |adapter|
            allow(adapter).to receive(:fetch) do |key, options = {}, &block|
              if cache_store.key?(key)
                cache_store[key]
              else
                value = block.call
                cache_store[key] = value
                value
              end
            end
          end
        end

        before do
          OmniauthOpenidFederation::CacheAdapter.adapter = cache_adapter
        end

        it "caches the JWKS JSON" do
          env = Rack::MockRequest.env_for("/jwks.json")

          # First call should fetch and cache
          endpoint.call(env)
          # Second call should use cache (no new fetch call)
          call_count = 0
          allow(cache_adapter).to receive(:fetch) do |*args, &block|
            call_count += 1
            cache_store[args[0]] ||= block.call
          end

          endpoint.call(env)
          aggregate_failures do
            expect(cache_store).not_to be_empty
            expect(call_count).to eq(1) # Should only be called once (for cache lookup)
          end
        end
      end

      context "without cache" do
        before do
          OmniauthOpenidFederation::CacheAdapter.adapter = nil
        end

        it "returns JWKS JSON without caching" do
          env = Rack::MockRequest.env_for("/jwks.json")
          status, _, body = endpoint.call(env)

          json_body = JSON.parse(body.first)
          aggregate_failures do
            expect(status).to eq(200)
            expect(json_body).to have_key("keys")
          end
        end
      end
    end

    context "with /openid-federation/fetch path" do
      let(:subordinate_entity_id) { "https://subordinate.example.com" }
      let(:subordinate_statement) { "subordinate.statement.jwt" }

      before do
        allow(OmniauthOpenidFederation::FederationEndpoint).to receive(:get_subordinate_statement)
          .with(subordinate_entity_id)
          .and_return(subordinate_statement)
      end

      it "returns subordinate statement when found" do
        env = Rack::MockRequest.env_for("/openid-federation/fetch?sub=#{CGI.escape(subordinate_entity_id)}")
        status, headers, body = endpoint.call(env)

        aggregate_failures do
          expect(status).to eq(200)
          expect(headers["Content-Type"]).to eq("application/entity-statement+jwt")
          expect(headers["Cache-Control"]).to eq("public, max-age=3600")
          expect(body.first).to eq(subordinate_statement)
        end
      end

      it "returns 400 when sub parameter is missing" do
        env = Rack::MockRequest.env_for("/openid-federation/fetch")
        status, headers, body = endpoint.call(env)

        json_body = JSON.parse(body.first)
        aggregate_failures do
          expect(status).to eq(400)
          expect(headers["Content-Type"]).to eq("application/json")
          expect(json_body["error"]).to eq("invalid_request")
          expect(json_body["error_description"]).to include("Missing required parameter: sub")
        end
      end

      it "returns 400 for invalid entity identifier" do
        env = Rack::MockRequest.env_for("/openid-federation/fetch?sub=not-a-valid-uri")
        status, headers, body = endpoint.call(env)

        json_body = JSON.parse(body.first)
        aggregate_failures do
          expect(status).to eq(400)
          expect(json_body["error"]).to eq("invalid_request")
          expect(json_body["error_description"]).to include("Invalid subject entity ID")
        end
      end

      it "returns 400 when subject equals issuer" do
        env = Rack::MockRequest.env_for("/openid-federation/fetch?sub=#{CGI.escape(issuer)}")
        status, headers, body = endpoint.call(env)

        json_body = JSON.parse(body.first)
        aggregate_failures do
          expect(status).to eq(400)
          expect(json_body["error"]).to eq("invalid_request")
          expect(json_body["error_description"]).to include("Subject cannot be the issuer")
        end
      end

      it "returns 404 when subordinate statement not found" do
        allow(OmniauthOpenidFederation::FederationEndpoint).to receive(:get_subordinate_statement)
          .with(subordinate_entity_id)
          .and_return(nil)

        env = Rack::MockRequest.env_for("/openid-federation/fetch?sub=#{CGI.escape(subordinate_entity_id)}")
        status, headers, body = endpoint.call(env)

        json_body = JSON.parse(body.first)
        aggregate_failures do
          expect(status).to eq(404)
          expect(json_body["error"]).to eq("not_found")
          expect(json_body["error_description"]).to include("Subordinate Statement not found")
        end
      end
    end

    context "with /signed-jwks.json path" do
      it "returns signed JWKS JWT" do
        env = Rack::MockRequest.env_for("/signed-jwks.json")
        status, headers, body = endpoint.call(env)

        aggregate_failures do
          expect(status).to eq(200)
          expect(headers["Content-Type"]).to eq("application/jwt")
          expect(headers["Cache-Control"]).to eq("public, max-age=3600")
          expect(body.first).to be_a(String)
          expect(body.first.split(".").length).to eq(3) # JWT format
        end
      end

      context "with cache available" do
        let(:cache_store) { {} }
        let(:cache_adapter) do
          double("CacheAdapter").tap do |adapter|
            allow(adapter).to receive(:fetch) do |key, options = {}, &block|
              if cache_store.key?(key)
                cache_store[key]
              else
                value = block.call
                cache_store[key] = value
                value
              end
            end
          end
        end

        before do
          OmniauthOpenidFederation::CacheAdapter.adapter = cache_adapter
        end

        it "caches the signed JWKS" do
          env = Rack::MockRequest.env_for("/signed-jwks.json")

          # First call should fetch and cache
          endpoint.call(env)
          # Second call should use cache (no new fetch call)
          call_count = 0
          allow(cache_adapter).to receive(:fetch) do |*args, &block|
            call_count += 1
            cache_store[args[0]] ||= block.call
          end

          endpoint.call(env)
          aggregate_failures do
            expect(cache_store).not_to be_empty
            expect(call_count).to eq(1) # Should only be called once (for cache lookup)
          end
        end
      end

      context "without cache" do
        before do
          OmniauthOpenidFederation::CacheAdapter.adapter = nil
        end

        it "returns signed JWKS without caching" do
          env = Rack::MockRequest.env_for("/signed-jwks.json")
          status, _, body = endpoint.call(env)

          aggregate_failures do
            expect(status).to eq(200)
            expect(body.first.split(".").length).to eq(3)
          end
        end
      end
    end

    context "with unknown path" do
      it "returns 404 Not Found" do
        env = Rack::MockRequest.env_for("/unknown")
        status, headers, body = endpoint.call(env)

        aggregate_failures do
          expect(status).to eq(404)
          expect(headers["Content-Type"]).to eq("text/plain")
          expect(body.first).to eq("Not Found")
        end
      end
    end

    context "with configuration error" do
      before do
        OmniauthOpenidFederation::FederationEndpoint.instance_variable_set(:@configuration, nil)
        allow(OmniauthOpenidFederation::FederationEndpoint).to receive(:generate_entity_statement)
          .and_raise(OmniauthOpenidFederation::ConfigurationError.new("Not configured"))
      end

      it "returns 503 Service Unavailable" do
        env = Rack::MockRequest.env_for("/openid-federation")
        status, headers, body = endpoint.call(env)

        aggregate_failures do
          expect(status).to eq(503)
          expect(headers["Content-Type"]).to eq("text/plain")
          expect(body.first).to eq("Federation endpoint not configured")
        end
      end
    end

    context "with signature error" do
      before do
        allow(OmniauthOpenidFederation::FederationEndpoint).to receive(:generate_signed_jwks)
          .and_raise(OmniauthOpenidFederation::SignatureError.new("Signature failed"))
      end

      it "returns 500 Internal Server Error for signed-jwks endpoint" do
        env = Rack::MockRequest.env_for("/signed-jwks.json")
        status, headers, body = endpoint.call(env)

        json_body = JSON.parse(body.first)
        aggregate_failures do
          expect(status).to eq(500)
          expect(headers["Content-Type"]).to eq("application/json")
          expect(json_body).to have_key("error")
          expect(json_body["error"]).to eq("Internal server error")
        end
      end
    end

    context "with general error" do
      before do
        allow(OmniauthOpenidFederation::FederationEndpoint).to receive(:generate_entity_statement)
          .and_raise(StandardError.new("Unexpected error"))
      end

      it "returns 500 Internal Server Error for openid-federation endpoint" do
        env = Rack::MockRequest.env_for("/openid-federation")
        status, headers, body = endpoint.call(env)

        json_body = JSON.parse(body.first)
        aggregate_failures do
          expect(status).to eq(500)
          expect(headers["Content-Type"]).to eq("application/json")
          expect(json_body).to have_key("error")
          expect(json_body["error"]).to eq("Internal server error")
        end
      end
    end
  end

  describe "#rack_app" do
    it "returns a RackEndpoint instance" do
      app = OmniauthOpenidFederation::FederationEndpoint.rack_app
      expect(app).to be_a(described_class)
    end
  end
end

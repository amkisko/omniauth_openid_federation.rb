require "spec_helper"
require "rack"

RSpec.describe OmniauthOpenidFederation::RackEndpoint do
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

  let(:endpoint) { described_class.new }

  before do
    # Reset configuration
    OmniauthOpenidFederation::FederationEndpoint.instance_variable_set(:@configuration, nil)
    OmniauthOpenidFederation::CacheAdapter.reset!

    # Configure federation endpoint
    OmniauthOpenidFederation::FederationEndpoint.configure do |config|
      config.issuer = issuer
      config.subject = subject
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

        expect(status).to eq(200)
        expect(headers["Content-Type"]).to eq("application/jwt")
        expect(headers["Cache-Control"]).to eq("public, max-age=3600")
        expect(body.first).to be_a(String)
        expect(body.first.split(".").length).to eq(3) # JWT format
      end
    end

    context "with /jwks.json path" do
      it "returns JWKS JSON" do
        env = Rack::MockRequest.env_for("/jwks.json")
        status, headers, body = endpoint.call(env)

        expect(status).to eq(200)
        expect(headers["Content-Type"]).to eq("application/json")
        expect(headers["Cache-Control"]).to eq("public, max-age=3600")

        json_body = JSON.parse(body.first)
        expect(json_body).to have_key("keys")
        expect(json_body["keys"]).to be_an(Array)
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
          expect(cache_store).not_to be_empty

          # Second call should use cache (no new fetch call)
          call_count = 0
          allow(cache_adapter).to receive(:fetch) do |*args, &block|
            call_count += 1
            cache_store[args[0]] ||= block.call
          end

          endpoint.call(env)
          expect(call_count).to eq(1) # Should only be called once (for cache lookup)
        end
      end

      context "without cache" do
        before do
          OmniauthOpenidFederation::CacheAdapter.adapter = nil
        end

        it "returns JWKS JSON without caching" do
          env = Rack::MockRequest.env_for("/jwks.json")
          status, _, body = endpoint.call(env)

          expect(status).to eq(200)
          json_body = JSON.parse(body.first)
          expect(json_body).to have_key("keys")
        end
      end
    end

    context "with /signed-jwks.json path" do
      it "returns signed JWKS JWT" do
        env = Rack::MockRequest.env_for("/signed-jwks.json")
        status, headers, body = endpoint.call(env)

        expect(status).to eq(200)
        expect(headers["Content-Type"]).to eq("application/jwt")
        expect(headers["Cache-Control"]).to eq("public, max-age=3600")
        expect(body.first).to be_a(String)
        expect(body.first.split(".").length).to eq(3) # JWT format
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
          expect(cache_store).not_to be_empty

          # Second call should use cache (no new fetch call)
          call_count = 0
          allow(cache_adapter).to receive(:fetch) do |*args, &block|
            call_count += 1
            cache_store[args[0]] ||= block.call
          end

          endpoint.call(env)
          expect(call_count).to eq(1) # Should only be called once (for cache lookup)
        end
      end

      context "without cache" do
        before do
          OmniauthOpenidFederation::CacheAdapter.adapter = nil
        end

        it "returns signed JWKS without caching" do
          env = Rack::MockRequest.env_for("/signed-jwks.json")
          status, _, body = endpoint.call(env)

          expect(status).to eq(200)
          expect(body.first.split(".").length).to eq(3)
        end
      end
    end

    context "with unknown path" do
      it "returns 404 Not Found" do
        env = Rack::MockRequest.env_for("/unknown")
        status, headers, body = endpoint.call(env)

        expect(status).to eq(404)
        expect(headers["Content-Type"]).to eq("text/plain")
        expect(body.first).to eq("Not Found")
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

        expect(status).to eq(503)
        expect(headers["Content-Type"]).to eq("text/plain")
        expect(body.first).to eq("Federation endpoint not configured")
      end
    end

    context "with signature error" do
      before do
        allow(OmniauthOpenidFederation::FederationEndpoint).to receive(:generate_signed_jwks)
          .and_raise(OmniauthOpenidFederation::SignatureError.new("Signature failed"))
      end

      it "returns 500 Internal Server Error" do
        env = Rack::MockRequest.env_for("/signed-jwks.json")
        status, headers, body = endpoint.call(env)

        expect(status).to eq(500)
        expect(headers["Content-Type"]).to eq("application/json")
        json_body = JSON.parse(body.first)
        expect(json_body).to have_key("error")
        expect(json_body["error"]).to eq("Internal server error")
      end
    end

    context "with general error" do
      before do
        allow(OmniauthOpenidFederation::FederationEndpoint).to receive(:generate_entity_statement)
          .and_raise(StandardError.new("Unexpected error"))
      end

      it "returns 500 Internal Server Error" do
        env = Rack::MockRequest.env_for("/openid-federation")
        status, headers, body = endpoint.call(env)

        expect(status).to eq(500)
        expect(headers["Content-Type"]).to eq("application/json")
        json_body = JSON.parse(body.first)
        expect(json_body).to have_key("error")
        expect(json_body["error"]).to eq("Internal server error")
      end
    end
  end

  describe "#rack_app" do
    it "returns a RackEndpoint instance" do
      app = OmniauthOpenidFederation::FederationEndpoint.rack_app
      expect(app).to be_a(OmniauthOpenidFederation::RackEndpoint)
    end
  end
end

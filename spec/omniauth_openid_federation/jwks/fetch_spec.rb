require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Jwks::Fetch do
  let(:jwks_uri) { "https://example.com/.well-known/jwks.json" }
  let(:jwks_response) do
    {
      keys: [
        {
          kty: "RSA",
          kid: "key-1",
          use: "sig",
          n: "test-n",
          e: "AQAB"
        }
      ]
    }
  end

  describe ".run" do
    context "with standard JWKS" do
      it "fetches and returns JWKS" do
        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: jwks_response.to_json, headers: {"Content-Type" => "application/json"})

        result = described_class.run(jwks_uri)

        expect(result).to be_a(Hash)
        expect(result["keys"]).to be_present
      end
    end

    context "with signed JWKS" do
      let(:entity_jwks) { {keys: [{kty: "RSA", kid: "entity-key", use: "sig", n: "test", e: "AQAB"}]} }
      let(:signed_jwks_jwt) { "eyJhbGciOiJSUzI1NiJ9.eyJrZXlzIjpbXX0.signature" }

      it "validates signed JWKS when entity keys provided" do
        # This is a simplified test - actual signed JWKS validation requires proper JWT signing
        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: jwks_response.to_json, headers: {"Content-Type" => "application/json"})

        result = described_class.run(jwks_uri, entity_statement_keys: entity_jwks)

        expect(result).to be_a(Hash)
      end
    end

    context "with HTTP errors" do
      before do
        # Clear cache to ensure fresh fetch
        cache_key = OmniauthOpenidFederation::Cache.key_for_jwks(jwks_uri)
        OmniauthOpenidFederation::CacheAdapter.delete(cache_key) if OmniauthOpenidFederation::CacheAdapter.available?
      end

      it "raises error on HTTP failure" do
        stub_request(:get, jwks_uri)
          .to_return(status: 500)

        expect { described_class.run(jwks_uri) }.to raise_error(OmniauthOpenidFederation::FetchError, /Failed to fetch JWKS/)
      end

      it "raises error on network failure" do
        stub_request(:get, jwks_uri)
          .to_raise(HTTP::Error.new("Network error"))

        expect { described_class.run(jwks_uri) }.to raise_error(OmniauthOpenidFederation::FetchError, /Failed to fetch JWKS/)
      end

      it "raises KeyRelatedError on 401 status" do
        stub_request(:get, jwks_uri)
          .to_return(status: 401)

        expect { described_class.run(jwks_uri) }.to raise_error(OmniauthOpenidFederation::KeyRelatedError)
      end

      it "raises KeyRelatedError on 403 status" do
        stub_request(:get, jwks_uri)
          .to_return(status: 403)

        expect { described_class.run(jwks_uri) }.to raise_error(OmniauthOpenidFederation::KeyRelatedError)
      end

      it "raises KeyRelatedError on 404 status" do
        stub_request(:get, jwks_uri)
          .to_return(status: 404)

        expect { described_class.run(jwks_uri) }.to raise_error(OmniauthOpenidFederation::KeyRelatedError)
      end
    end

    context "with cache and rotate_on_errors" do
      before do
        require "active_support/cache" unless defined?(ActiveSupport::Cache)
        memory_store = ActiveSupport::Cache::MemoryStore.new
        stub_const("Rails", double(cache: memory_store))
        OmniauthOpenidFederation::CacheAdapter.reset!
      end

      it "rotates cache on key-related error when rotate_on_errors is true" do
        OmniauthOpenidFederation.configure do |config|
          config.rotate_on_errors = true
        end

        stub_request(:get, jwks_uri)
          .to_return(status: 401)
          .then.to_return(status: 200, body: jwks_response.to_json, headers: {"Content-Type" => "application/json"})

        result = described_class.run(jwks_uri)
        expect(result).to be_a(Hash)
        expect(WebMock).to have_requested(:get, jwks_uri).twice
      end

      it "raises error when rotate_on_errors is false" do
        OmniauthOpenidFederation.configure do |config|
          config.rotate_on_errors = false
        end

        stub_request(:get, jwks_uri)
          .to_return(status: 401)

        expect { described_class.run(jwks_uri) }.to raise_error(OmniauthOpenidFederation::KeyRelatedError)
      end

      it "rotates cache on key-related error with TTL-based cache when rotate_on_errors is true" do
        OmniauthOpenidFederation.configure do |config|
          config.rotate_on_errors = true
          config.cache_ttl = 3600
        end

        stub_request(:get, jwks_uri)
          .to_return(status: 401)
          .then.to_return(status: 200, body: jwks_response.to_json, headers: {"Content-Type" => "application/json"})

        result = described_class.run(jwks_uri, cache_ttl: 3600)
        expect(result).to be_a(Hash)
        expect(WebMock).to have_requested(:get, jwks_uri).twice
      end

      it "raises error with TTL-based cache when rotate_on_errors is false" do
        OmniauthOpenidFederation.configure do |config|
          config.rotate_on_errors = false
          config.cache_ttl = 3600
        end

        stub_request(:get, jwks_uri)
          .to_return(status: 401)

        expect { described_class.run(jwks_uri, cache_ttl: 3600) }.to raise_error(OmniauthOpenidFederation::KeyRelatedError)
      end
    end

    context "without cache" do
      before do
        OmniauthOpenidFederation::CacheAdapter.reset!
        hide_const("Rails")
        # Ensure CacheAdapter is not available
        allow(OmniauthOpenidFederation::CacheAdapter).to receive(:available?).and_return(false)
      end

      it "fetches directly when cache is not available" do
        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: jwks_response.to_json, headers: {"Content-Type" => "application/json"})

        result = described_class.run(jwks_uri)
        expect(result).to be_a(Hash)
        expect(result["keys"]).to be_present
      end

      it "fetches directly when cache adapter is not available (line 89)" do
        # This specifically tests the else branch at line 89
        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: jwks_response.to_json, headers: {"Content-Type" => "application/json"})

        # Ensure we're in the else branch (CacheAdapter.available? returns false)
        allow(OmniauthOpenidFederation::CacheAdapter).to receive(:available?).and_return(false)

        result = described_class.run(jwks_uri)
        expect(result).to be_a(Hash)
        expect(result["keys"]).to be_present
        expect(WebMock).to have_requested(:get, jwks_uri).once
      end

      it "raises error when rate limit is exceeded" do
        # Mock rate limiter to deny
        allow(OmniauthOpenidFederation::RateLimiter).to receive(:allow?).and_return(false)

        expect { described_class.run(jwks_uri) }.to raise_error(
          OmniauthOpenidFederation::FetchError,
          /Rate limit exceeded/
        )
      end
    end

    context "with signed JWKS" do
      let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
      let(:public_key) { private_key.public_key }
      let(:entity_jwk) { JWT::JWK.new(public_key) }
      let(:entity_statement_keys) { [entity_jwk.export.stringify_keys] }

      let(:signed_jwks_payload) do
        {
          keys: [
            {
              kty: "RSA",
              kid: "provider-key-1",
              use: "sig",
              n: "test-n",
              e: "AQAB"
            }
          ]
        }
      end

      let(:signed_jwks_jwt) do
        header = {alg: "RS256", typ: "JWT", kid: entity_jwk.export[:kid]}
        JWT.encode(signed_jwks_payload, private_key, "RS256", header)
      end

      it "validates and decodes signed JWKS" do
        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

        result = described_class.run(jwks_uri, entity_statement_keys: entity_statement_keys)

        expect(result).to be_a(Hash)
        expect(result["keys"]).to be_present
      end
    end
  end

  describe "hash conversion" do
    it "uses Utils.to_indifferent_hash for conversion" do
      hash = {"key" => "value"}
      result = OmniauthOpenidFederation::Utils.to_indifferent_hash(hash)

      if defined?(ActiveSupport::HashWithIndifferentAccess)
        expect(result).to be_a(ActiveSupport::HashWithIndifferentAccess)
      else
        expect(result).to be_a(Hash)
      end
    end
  end
end

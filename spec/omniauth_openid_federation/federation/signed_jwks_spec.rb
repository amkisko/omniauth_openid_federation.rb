require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Federation::SignedJWKS do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:entity_jwk) { JWT::JWK.new(public_key) }
  let(:signed_jwks_uri) { "https://example.com/.well-known/signed-jwks" }

  let(:entity_jwks) do
    {
      "keys" => [entity_jwk.export.stringify_keys]
    }
  end

  let(:jwks_payload) do
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
    # OpenID Federation format: JWT payload contains iss, sub, iat, exp, jwks
    # The jwks field contains the actual JWKS
    now = Time.now.to_i
    payload = {
      iss: "https://example.com",
      sub: "https://example.com",
      iat: now,
      exp: now + 3600,
      jwks: jwks_payload
    }
    header = {
      alg: "RS256",
      typ: "JWT",
      kid: entity_jwk.export[:kid]
    }
    JWT.encode(payload, private_key, "RS256", header)
  end

  before do
    # Reset configuration before each test
    OmniauthOpenidFederation::Configuration.reset!
    # Reset rate limiter
    OmniauthOpenidFederation::RateLimiter.reset!(signed_jwks_uri) if OmniauthOpenidFederation::CacheAdapter.available?
    # Reset cache adapter to force re-detection
    OmniauthOpenidFederation::CacheAdapter.reset!
    # Clear cache store before each test to prevent test pollution
    # Always create a fresh cache store for each test
    @cache_store = {}
  end

  describe ".fetch!" do
    context "without Rails cache" do
      before do
        # Reset cache adapter to ensure no cache is available
        OmniauthOpenidFederation::CacheAdapter.reset!
        # Ensure Rails is not defined or Rails.cache is nil
        if defined?(Rails)
          allow(Rails).to receive(:cache).and_return(nil)
        end
        # Ensure CacheAdapter.available? returns false to hit line 111
        allow(OmniauthOpenidFederation::CacheAdapter).to receive(:available?).and_return(false)
      end

      it "fetches and validates signed JWKS directly" do
        stub_request(:get, signed_jwks_uri)
          .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

        result = described_class.fetch!(signed_jwks_uri, entity_jwks)

        expect(result).to be_a(Hash)
        expect(result["keys"]).to be_present
      end

      it "fetches directly when cache adapter is not available (line 111)" do
        # This specifically tests the else branch at line 111
        stub_request(:get, signed_jwks_uri)
          .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

        # Ensure CacheAdapter.available? returns false
        allow(OmniauthOpenidFederation::CacheAdapter).to receive(:available?).and_return(false)

        result = described_class.fetch!(signed_jwks_uri, entity_jwks)
        expect(result).to be_a(Hash)
        expect(result["keys"]).to be_present
        expect(WebMock).to have_requested(:get, signed_jwks_uri).once
      end
    end

    context "with Rails cache" do
      before do
        # Use ActiveSupport::Cache::MemoryStore for reliable cache behavior
        # This is what Rails uses in tests and behaves correctly
        require "active_support/cache" unless defined?(ActiveSupport::Cache)
        memory_store = ActiveSupport::Cache::MemoryStore.new

        logger_double = double("Rails.logger")
        allow(logger_double).to receive(:debug)
        allow(logger_double).to receive(:info)
        allow(logger_double).to receive(:warn)
        allow(logger_double).to receive(:error)

        # Create or update Rails module
        if defined?(Rails)
          # If Rails is already defined, stub the cache method
          allow(Rails).to receive(:cache).and_return(memory_store)
          allow(Rails).to receive(:logger).and_return(logger_double)
        else
          rails_module = Class.new do
            class << self
              attr_accessor :cache, :logger
            end
          end

          rails_module.cache = memory_store
          rails_module.logger = logger_double

          stub_const("Rails", rails_module)
        end

        # Ensure Rails.cache is set
        Rails.cache = memory_store if defined?(Rails)

        # Reset cache adapter to force re-detection of Rails.cache
        OmniauthOpenidFederation::CacheAdapter.reset!
      end

      context "with manual rotation (cache_ttl: nil)" do
        before do
          # Clear cache before each test
          if OmniauthOpenidFederation::CacheAdapter.available?
            OmniauthOpenidFederation::CacheAdapter.clear
            # Also clear via the cache module
            OmniauthOpenidFederation::Cache.delete_signed_jwks(signed_jwks_uri)
          end
          OmniauthOpenidFederation.configure do |config|
            config.cache_ttl = nil
            config.rotate_on_errors = false
          end
        end

        it "caches forever and fetches once" do
          # Clear cache before test to ensure fresh fetch
          cache_key = OmniauthOpenidFederation::Cache.key_for_signed_jwks(signed_jwks_uri)
          if OmniauthOpenidFederation::CacheAdapter.available?
            OmniauthOpenidFederation::CacheAdapter.delete(cache_key)
            # Verify cache is empty
            expect(OmniauthOpenidFederation::CacheAdapter.read(cache_key)).to be_nil
          end

          stub_request(:get, signed_jwks_uri)
            .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

          # First fetch should make HTTP request
          result1 = described_class.fetch!(signed_jwks_uri, entity_jwks)
          expect(WebMock).to have_requested(:get, signed_jwks_uri).once

          # Second fetch should use cache (no additional HTTP request)
          result2 = described_class.fetch!(signed_jwks_uri, entity_jwks)
          expect(result1).to eq(result2)
          expect(WebMock).to have_requested(:get, signed_jwks_uri).once
        end

        it "does not rotate on key-related errors when rotate_on_errors is false" do
          stub_request(:get, signed_jwks_uri)
            .to_return(status: 401)

          expect { described_class.fetch!(signed_jwks_uri, entity_jwks) }.to raise_error(
            OmniauthOpenidFederation::KeyRelatedError
          )
        end

        it "rotates cache on key-related errors when rotate_on_errors is true" do
          OmniauthOpenidFederation.configure do |config|
            config.rotate_on_errors = true
          end

          stub_request(:get, signed_jwks_uri)
            .to_return(status: 401)
            .then.to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

          # When rotate_on_errors is true, error is caught, cache is rotated, and retry happens immediately
          # First request fails with 401, cache is rotated, second request succeeds
          result = described_class.fetch!(signed_jwks_uri, entity_jwks)
          expect(result).to be_a(Hash)
          expect(WebMock).to have_requested(:get, signed_jwks_uri).twice
        end

        it "rotates cache on key-related validation errors when rotate_on_errors is true" do
          OmniauthOpenidFederation.configure do |config|
            config.rotate_on_errors = true
          end

          # First call: invalid signature (key-related validation error)
          other_key = OpenSSL::PKey::RSA.new(2048)
          header = {alg: "RS256", typ: "JWT", kid: entity_jwk.export[:kid]}
          invalid_jwt = JWT.encode(jwks_payload, other_key, "RS256", header)

          stub_request(:get, signed_jwks_uri)
            .to_return(status: 200, body: invalid_jwt, headers: {"Content-Type" => "application/jwt"})
            .then.to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

          # When rotate_on_errors is true, error is caught, cache is rotated, and retry happens immediately
          # First request fails with validation error, cache is rotated, second request succeeds
          result = described_class.fetch!(signed_jwks_uri, entity_jwks)
          expect(result).to be_a(Hash)
          expect(WebMock).to have_requested(:get, signed_jwks_uri).twice
        end
      end

      context "with TTL-based cache" do
        before do
          # Clear cache before each test
          if defined?(Rails) && Rails.cache
            Rails.cache.clear
            cache_key = OmniauthOpenidFederation::Cache.key_for_signed_jwks(signed_jwks_uri)
            Rails.cache.delete(cache_key)
          end
          OmniauthOpenidFederation.configure do |config|
            config.cache_ttl = 3600
            config.rotate_on_errors = false
          end
        end

        it "caches with TTL and fetches once within TTL" do
          stub_request(:get, signed_jwks_uri)
            .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

          result1 = described_class.fetch!(signed_jwks_uri, entity_jwks)
          result2 = described_class.fetch!(signed_jwks_uri, entity_jwks)

          expect(result1).to eq(result2)
          expect(WebMock).to have_requested(:get, signed_jwks_uri).once
        end

        it "rotates cache on key-related errors when rotate_on_errors is true" do
          OmniauthOpenidFederation.configure do |config|
            config.rotate_on_errors = true
          end

          stub_request(:get, signed_jwks_uri)
            .to_return(status: 401)
            .then.to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

          # When rotate_on_errors is true, error is caught, cache is rotated, and retry happens immediately
          # First request fails with 401, cache is rotated, second request succeeds
          result = described_class.fetch!(signed_jwks_uri, entity_jwks)
          expect(result).to be_a(Hash)
          expect(WebMock).to have_requested(:get, signed_jwks_uri).twice
        end

        it "raises error when rotate_on_errors is false and key-related error occurs" do
          OmniauthOpenidFederation.configure do |config|
            config.rotate_on_errors = false
          end

          stub_request(:get, signed_jwks_uri)
            .to_return(status: 401)

          expect {
            described_class.fetch!(signed_jwks_uri, entity_jwks)
          }.to raise_error(OmniauthOpenidFederation::KeyRelatedError)
        end
      end

      context "with force_refresh" do
        before do
          # Clear cache before test
          if OmniauthOpenidFederation::CacheAdapter.available?
            OmniauthOpenidFederation::CacheAdapter.clear
            cache_key = OmniauthOpenidFederation::Cache.key_for_signed_jwks(signed_jwks_uri)
            OmniauthOpenidFederation::CacheAdapter.delete(cache_key)
          end
        end

        it "forces refresh even if cached" do
          stub_request(:get, signed_jwks_uri)
            .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})
            .then.to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

          described_class.fetch!(signed_jwks_uri, entity_jwks)
          described_class.fetch!(signed_jwks_uri, entity_jwks, force_refresh: true)

          expect(WebMock).to have_requested(:get, signed_jwks_uri).twice
        end
      end

      context "with custom cache_key and cache_ttl" do
        before do
          # Clear cache before each test
          if OmniauthOpenidFederation::CacheAdapter.available?
            OmniauthOpenidFederation::CacheAdapter.clear
          end
        end

        it "uses custom cache key" do
          stub_request(:get, signed_jwks_uri)
            .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

          custom_key = "custom:cache:key"
          result1 = described_class.fetch!(signed_jwks_uri, entity_jwks, cache_key: custom_key)
          result2 = described_class.fetch!(signed_jwks_uri, entity_jwks, cache_key: custom_key)

          expect(result1).to eq(result2)
          expect(OmniauthOpenidFederation::CacheAdapter.read(custom_key)).to be_present
        end

        it "uses custom cache TTL" do
          stub_request(:get, signed_jwks_uri)
            .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

          custom_ttl = 1800
          result = described_class.fetch!(signed_jwks_uri, entity_jwks, cache_ttl: custom_ttl)

          # Verify cache was written with custom TTL (we can't directly check TTL, but we can verify it was cached)
          OmniauthOpenidFederation::Cache.key_for_signed_jwks(signed_jwks_uri)
          # Second call should use cache (verify by checking only one HTTP request was made)
          result2 = described_class.fetch!(signed_jwks_uri, entity_jwks, cache_ttl: custom_ttl)
          expect(result).to eq(result2)
          expect(WebMock).to have_requested(:get, signed_jwks_uri).once
        end
      end
    end

    it "raises error on HTTP failure" do
      stub_request(:get, signed_jwks_uri)
        .to_return(status: 500)

      expect { described_class.fetch!(signed_jwks_uri, entity_jwks) }.to raise_error(
        OmniauthOpenidFederation::FetchError
      )
    end

    it "raises KeyRelatedError on 401 status" do
      stub_request(:get, signed_jwks_uri)
        .to_return(status: 401)

      expect { described_class.fetch!(signed_jwks_uri, entity_jwks) }.to raise_error(
        OmniauthOpenidFederation::KeyRelatedError
      )
    end

    it "raises KeyRelatedError on 403 status" do
      stub_request(:get, signed_jwks_uri)
        .to_return(status: 403)

      expect { described_class.fetch!(signed_jwks_uri, entity_jwks) }.to raise_error(
        OmniauthOpenidFederation::KeyRelatedError
      )
    end

    it "raises KeyRelatedError on 404 status" do
      stub_request(:get, signed_jwks_uri)
        .to_return(status: 404)

      expect { described_class.fetch!(signed_jwks_uri, entity_jwks) }.to raise_error(
        OmniauthOpenidFederation::KeyRelatedError
      )
    end

    it "raises error when response is not JWT format" do
      stub_request(:get, signed_jwks_uri)
        .to_return(status: 200, body: {keys: []}.to_json, headers: {"Content-Type" => "application/json"})

      expect { described_class.fetch!(signed_jwks_uri, entity_jwks) }.to raise_error(
        OmniauthOpenidFederation::ValidationError,
        /not in JWT format/
      )
    end

    it "raises KeyRelatedValidationError on JWT::VerificationError" do
      # Create JWT signed with different key to trigger verification error
      other_key = OpenSSL::PKey::RSA.new(2048)
      header = {alg: "RS256", typ: "JWT", kid: entity_jwk.export[:kid]}
      invalid_jwt = JWT.encode(jwks_payload, other_key, "RS256", header)

      stub_request(:get, signed_jwks_uri)
        .to_return(status: 200, body: invalid_jwt, headers: {"Content-Type" => "application/jwt"})

      # Clear cache to ensure we hit the verification error path
      if OmniauthOpenidFederation::CacheAdapter.available?
        cache_key = OmniauthOpenidFederation::Cache.key_for_signed_jwks(signed_jwks_uri)
        OmniauthOpenidFederation::CacheAdapter.delete(cache_key)
      end

      # JWT::VerificationError is caught and logged, then raises KeyRelatedValidationError
      expect(OmniauthOpenidFederation::Logger).to receive(:error).with(/Signed JWKS signature validation failed/)
      expect { described_class.fetch!(signed_jwks_uri, entity_jwks, force_refresh: true) }.to raise_error(
        OmniauthOpenidFederation::KeyRelatedValidationError,
        /Signed JWKS signature validation failed/
      )
    end

    it "raises ValidationError when payload doesn't contain jwks or keys" do
      # Create JWT with payload that doesn't have jwks or keys
      now = Time.now.to_i
      payload = {
        iss: "https://example.com",
        sub: "https://example.com",
        iat: now,
        exp: now + 3600
        # No jwks or keys field
      }
      header = {
        alg: "RS256",
        typ: "JWT",
        kid: entity_jwk.export[:kid]
      }
      invalid_jwt = JWT.encode(payload, private_key, "RS256", header)

      stub_request(:get, signed_jwks_uri)
        .to_return(status: 200, body: invalid_jwt, headers: {"Content-Type" => "application/jwt"})

      expect(OmniauthOpenidFederation::Logger).to receive(:error).with(/does not contain 'jwks' or 'keys' field/)
      expect { described_class.fetch!(signed_jwks_uri, entity_jwks) }.to raise_error(
        OmniauthOpenidFederation::ValidationError,
        /does not contain 'jwks' or 'keys' field/
      )
    end

    it "raises KeyRelatedValidationError on JWT decode error" do
      stub_request(:get, signed_jwks_uri)
        .to_return(status: 200, body: "invalid.jwt.format", headers: {"Content-Type" => "application/jwt"})

      expect { described_class.fetch!(signed_jwks_uri, entity_jwks) }.to raise_error(
        OmniauthOpenidFederation::KeyRelatedValidationError
      )
    end

    it "handles network errors" do
      # Mock HttpClient to raise NetworkError
      allow(OmniauthOpenidFederation::HttpClient).to receive(:get).and_raise(
        OmniauthOpenidFederation::NetworkError.new("Network error")
      )

      expect { described_class.fetch!(signed_jwks_uri, entity_jwks) }.to raise_error(
        OmniauthOpenidFederation::FetchError
      )
    end
  end

  describe "#fetch_and_validate" do
    context "when cache is not available" do
      before do
        OmniauthOpenidFederation::CacheAdapter.reset!
        hide_const("Rails")
      end

      it "fetches and validates directly" do
        stub_request(:get, signed_jwks_uri)
          .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

        fetcher = described_class.new(signed_jwks_uri, entity_jwks)
        result = fetcher.fetch_and_validate

        expect(result).to be_a(Hash)
        expect(result["keys"]).to be_present
      end
    end

    it "validates signed JWKS" do
      stub_request(:get, signed_jwks_uri)
        .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

      instance = described_class.new(signed_jwks_uri, entity_jwks)
      result = instance.fetch_and_validate

      expect(result).to be_a(Hash)
      expect(result["keys"]).to be_present
    end

    it "raises error when rate limit is exceeded" do
      # Mock Rails.cache and Rails.logger if not available
      unless defined?(Rails) && Rails.respond_to?(:cache) && Rails.cache
        cache_store = {}
        cache_double = double("Rails.cache")
        allow(cache_double).to receive(:read) { |key| cache_store[key] }
        allow(cache_double).to receive(:write) { |key, value, options = {}|
          cache_store[key] = value
          true
        }
        allow(cache_double).to receive(:increment) { |key, amount = 1| cache_store[key] = (cache_store[key] || 0) + amount }
        allow(cache_double).to receive(:exist?) { |key| cache_store.key?(key) }

        logger_double = double("Rails.logger")
        allow(logger_double).to receive(:debug)
        allow(logger_double).to receive(:info)
        allow(logger_double).to receive(:warn)
        allow(logger_double).to receive(:error)

        rails_module = Class.new do
          def self.cache
            @cache ||= nil
          end

          def self.cache=(cache)
            @cache = cache
          end

          def self.logger
            @logger ||= nil
          end

          def self.logger=(logger)
            @logger = logger
          end
        end

        rails_module.cache = cache_double
        rails_module.logger = logger_double

        stub_const("Rails", rails_module) unless defined?(Rails)
      end

      # Exceed rate limit
      11.times do
        OmniauthOpenidFederation::RateLimiter.allow?(signed_jwks_uri, max_requests: 10, window: 60)
      end

      expect { described_class.new(signed_jwks_uri, entity_jwks).fetch_and_validate }.to raise_error(
        OmniauthOpenidFederation::FetchError,
        /Rate limit exceeded/
      )
    end

    it "handles non-success HTTP status codes" do
      stub_request(:get, signed_jwks_uri)
        .to_return(status: 500)

      expect { described_class.new(signed_jwks_uri, entity_jwks).fetch_and_validate }.to raise_error(
        OmniauthOpenidFederation::FetchError
      )
    end

    it "returns HashWithIndifferentAccess when available" do
      stub_request(:get, signed_jwks_uri)
        .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

      instance = described_class.new(signed_jwks_uri, entity_jwks)
      result = instance.fetch_and_validate

      expect(result).to be_a(Hash)
      # Should be able to access with string or symbol keys
      expect(result["keys"]).to be_present
      expect(result[:keys]).to be_present if result.respond_to?(:[])
    end

    it "handles legacy format with keys at root level (line 186)" do
      # Test the legacy format where payload is the JWKS directly (keys at root)
      # This tests line 186: jwks_payload = full_payload
      Time.now.to_i
      legacy_payload = {
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
      header = {
        alg: "RS256",
        typ: "JWT",
        kid: entity_jwk.export[:kid]
      }
      legacy_jwt = JWT.encode(legacy_payload, private_key, "RS256", header)

      stub_request(:get, signed_jwks_uri)
        .to_return(status: 200, body: legacy_jwt, headers: {"Content-Type" => "application/jwt"})

      instance = described_class.new(signed_jwks_uri, entity_jwks)
      result = instance.fetch_and_validate

      expect(result).to be_a(Hash)
      expect(result["keys"]).to be_present
      expect(result["keys"].first["kid"]).to eq("provider-key-1")
    end
  end
end

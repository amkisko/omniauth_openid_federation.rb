require "spec_helper"

RSpec.describe OmniauthOpenidFederation::RateLimiter do
  let(:cache_store) { ActiveSupport::Cache::MemoryStore.new }

  before do
    OmniauthOpenidFederation::CacheAdapter.adapter =
      OmniauthOpenidFederation::CacheAdapter::RailsCacheAdapter.new(cache_store)
    cache_store.clear
  end

  after do
    OmniauthOpenidFederation::CacheAdapter.reset!
    cache_store.clear
  end

  describe ".allow?" do
    context "when cache adapter is available" do
      it "allows requests within limit" do
        key = "https://example.com/jwks.json"
        max_requests = 3

        aggregate_failures do
          max_requests.times do
            expect(described_class.allow?(key, max_requests: max_requests, window: 60)).to be true
          end
          expect(described_class.allow?(key, max_requests: max_requests, window: 60)).to be false
        end
      end

      it "allows requests after window expires" do
        key = "https://example.com/jwks.json"
        max_requests = 2
        window = 1

        (max_requests + 1).times do
          described_class.allow?(key, max_requests: max_requests, window: window)
        end

        sleep(window + 0.1)

        expect(described_class.allow?(key, max_requests: max_requests, window: window)).to be true
      end

      it "uses different keys for different URIs" do
        key1 = "https://example.com/jwks.json"
        key2 = "https://other.com/jwks.json"
        max_requests = 1

        described_class.allow?(key1, max_requests: max_requests, window: 60)
        aggregate_failures do
          expect(described_class.allow?(key1, max_requests: max_requests, window: 60)).to be false
          expect(described_class.allow?(key2, max_requests: max_requests, window: 60)).to be true
        end
      end

      it "filters out timestamps outside the window" do
        key = "https://example.com/jwks.json"
        max_requests = 2
        window = 60

        described_class.allow?(key, max_requests: max_requests, window: window)
        described_class.allow?(key, max_requests: max_requests, window: window)

        cache_key = "omniauth_openid_federation:rate_limit:#{Digest::SHA256.hexdigest(key)}"
        old_timestamps = [Time.now.to_i - 120, Time.now.to_i - 90]
        cache_store.write(cache_key, old_timestamps, expires_in: window)

        expect(described_class.allow?(key, max_requests: max_requests, window: window)).to be true
      end

      it "logs warning when rate limit is exceeded" do
        key = "https://example.com/jwks.json"
        max_requests = 1

        described_class.allow?(key, max_requests: max_requests, window: 60)

        allow(OmniauthOpenidFederation::Logger).to receive(:warn)
        described_class.allow?(key, max_requests: max_requests, window: 60)
        expect(OmniauthOpenidFederation::Logger).to have_received(:warn).with(/Rate limit exceeded/)
      end
    end

    context "when cache adapter is not available" do
      before do
        allow(OmniauthOpenidFederation::CacheAdapter).to receive(:available?).and_return(false)
      end

      it "always allows requests" do
        key = "https://example.com/jwks.json"
        expect(described_class.allow?(key)).to be true
      end
    end
  end

  describe ".reset!" do
    it "clears rate limit for a key" do
      key = "https://example.com/jwks.json"
      max_requests = 1

      described_class.allow?(key, max_requests: max_requests, window: 60)
      aggregate_failures do
        expect(described_class.allow?(key, max_requests: max_requests, window: 60)).to be false

        described_class.reset!(key)

        expect(described_class.allow?(key, max_requests: max_requests, window: 60)).to be true
      end
    end

    context "when cache adapter is not available" do
      before do
        allow(OmniauthOpenidFederation::CacheAdapter).to receive(:available?).and_return(false)
      end

      it "does nothing" do
        expect { described_class.reset!("https://example.com/jwks.json") }.not_to raise_error
      end
    end
  end
end

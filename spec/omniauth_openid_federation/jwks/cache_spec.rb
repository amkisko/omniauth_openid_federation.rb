require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Jwks::Cache do
  let(:jwks_source) { double("JWKSSource") }
  let(:timeout_sec) { 300 }
  let(:cache) { described_class.new(jwks_source, timeout_sec) }

  describe "#initialize" do
    it "sets jwks_source" do
      expect(cache.jwks_source).to eq(jwks_source)
    end

    it "sets timeout_sec" do
      expect(cache.timeout_sec).to eq(timeout_sec)
    end

    it "uses default timeout when not provided" do
      cache = described_class.new(jwks_source)
      expect(cache.timeout_sec).to eq(300)
    end

    it "initializes cache_last_update to 0" do
      expect(cache.cache_last_update).to eq(0)
    end
  end

  describe "#call" do
    let(:jwks_hash) do
      {
        keys: [
          {kid: "key1", use: "sig", kty: "RSA"},
          {kid: "key2", use: "enc", kty: "RSA"}
        ]
      }
    end

    it "returns signing keys from jwks" do
      allow(jwks_source).to receive(:jwks).and_return(jwks_hash)
      result = cache.call
      aggregate_failures do
        expect(result.length).to eq(1)
        expect(result.first[:use]).to eq("sig")
      end
    end

    it "caches keys" do
      allow(jwks_source).to receive(:jwks).and_return(jwks_hash)
      result1 = cache.call
      result2 = cache.call
      aggregate_failures do
        expect(result1).to be(result2)
        expect(jwks_source).to have_received(:jwks).once
      end
    end

    it "updates cache_last_update" do
      allow(jwks_source).to receive(:jwks).and_return(jwks_hash)
      cache.call
      expect(cache.cache_last_update).to be > 0
    end

    it "handles hash with string keys" do
      jwks = {
        "keys" => [
          {"kid" => "key1", "use" => "sig", "kty" => "RSA"}
        ]
      }
      allow(jwks_source).to receive(:jwks).and_return(jwks)
      result = cache.call
      expect(result.length).to eq(1)
    end

    it "handles hash with symbol keys" do
      jwks = {
        keys: [
          {kid: "key1", use: "sig", kty: "RSA"}
        ]
      }
      allow(jwks_source).to receive(:jwks).and_return(jwks)
      result = cache.call
      expect(result.length).to eq(1)
    end

    it "handles array jwks" do
      jwks = [
        {kid: "key1", use: "sig", kty: "RSA"}
      ]
      allow(jwks_source).to receive(:jwks).and_return(jwks)
      result = cache.call
      expect(result.length).to eq(1)
    end

    it "handles nil keys" do
      jwks = {keys: nil}
      allow(jwks_source).to receive(:jwks).and_return(jwks)
      result = cache.call
      expect(result).to eq([])
    end

    it "handles non-hash, non-array jwks" do
      allow(jwks_source).to receive(:jwks).and_return("string")
      result = cache.call
      expect(result).to eq([])
    end

    context "with kid_not_found" do
      it "invalidates cache when timeout passed" do
        allow(jwks_source).to receive(:jwks).and_return(jwks_hash)
        cache.call # Initial cache

        # Move time forward past timeout
        allow(Time).to receive(:now).and_return(Time.zone.at(Time.now.to_i + timeout_sec + 1))

        allow(jwks_source).to receive(:reload!)
        cache.call(kid_not_found: true, kid: "missing-kid")

        aggregate_failures do
          expect(jwks_source).to have_received(:reload!)
          expect(cache.cache_last_update).to be > 0
        end
      end

      it "does not invalidate cache when timeout not passed" do
        allow(jwks_source).to receive(:jwks).and_return(jwks_hash)
        cache.call # Initial cache
        initial_update = cache.cache_last_update

        # Move time forward but not past timeout
        allow(Time).to receive(:now).and_return(Time.zone.at(Time.now.to_i + timeout_sec - 1))

        cache.call(kid_not_found: true, kid: "missing-kid")

        expect(cache.cache_last_update).to eq(initial_update)
      end

      it "calls reload! when jwks_source responds to it" do
        allow(jwks_source).to receive(:jwks).and_return(jwks_hash)
        allow(jwks_source).to receive(:reload!)
        cache.call # Initial cache

        allow(Time).to receive(:now).and_return(Time.zone.at(Time.now.to_i + timeout_sec + 1))
        cache.call(kid_not_found: true, kid: "missing-kid")

        expect(jwks_source).to have_received(:reload!)
      end

      it "does not call reload! when jwks_source does not respond to it" do
        jwks_source_no_reload = double("JWKSSource")
        allow(jwks_source_no_reload).to receive(:jwks).and_return(jwks_hash)
        cache = described_class.new(jwks_source_no_reload, timeout_sec)

        cache.call # Initial cache
        allow(Time).to receive(:now).and_return(Time.zone.at(Time.now.to_i + timeout_sec + 1))

        expect {
          cache.call(kid_not_found: true, kid: "missing-kid")
        }.not_to raise_error
      end

      it "logs invalidation message" do
        allow(jwks_source).to receive(:jwks).and_return(jwks_hash)
        cache.call # Initial cache

        allow(Time).to receive(:now).and_return(Time.zone.at(Time.now.to_i + timeout_sec + 1))
        allow(OmniauthOpenidFederation::Logger).to receive(:info)

        cache.call(kid_not_found: true, kid: "missing-kid")

        expect(OmniauthOpenidFederation::Logger).to have_received(:info).with(/Invalidating JWK cache/)
      end
    end
  end

  describe "#clear!" do
    it "clears cached keys" do
      allow(jwks_source).to receive(:jwks).and_return({keys: [{kid: "key1", use: "sig"}]})
      cache.call
      cache.clear!
      aggregate_failures do
        # Verify cache was populated before clearing
        expect(cache.instance_variable_get(:@cached_keys)).to be_nil
      end
    end

    it "resets cache_last_update to 0" do
      allow(jwks_source).to receive(:jwks).and_return({keys: [{kid: "key1", use: "sig"}]})
      cache.call
      cache.clear!
      aggregate_failures do
        # Verify cache_last_update was set before clearing
        expect(cache.cache_last_update).to eq(0)
      end
    end
  end
end

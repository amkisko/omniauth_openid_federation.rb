require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Cache do
  describe ".key_for_jwks" do
    it "generates consistent cache key for JWKS URI" do
      uri = "https://example.com/.well-known/jwks.json"
      key1 = described_class.key_for_jwks(uri)
      key2 = described_class.key_for_jwks(uri)

      expect(key1).to eq(key2)
      expect(key1).to start_with("omniauth_openid_federation:jwks:")
    end

    it "generates different keys for different URIs" do
      uri1 = "https://example.com/.well-known/jwks.json"
      uri2 = "https://other.com/.well-known/jwks.json"
      key1 = described_class.key_for_jwks(uri1)
      key2 = described_class.key_for_jwks(uri2)

      expect(key1).not_to eq(key2)
    end
  end

  describe ".key_for_signed_jwks" do
    it "generates consistent cache key for signed JWKS URI" do
      uri = "https://example.com/.well-known/signed-jwks.json"
      key1 = described_class.key_for_signed_jwks(uri)
      key2 = described_class.key_for_signed_jwks(uri)

      expect(key1).to eq(key2)
      expect(key1).to start_with("omniauth_openid_federation:signed_jwks:")
    end
  end

  describe ".delete_jwks" do
    it "deletes JWKS cache when cache adapter is available" do
      if OmniauthOpenidFederation::CacheAdapter.available?
        uri = "https://example.com/.well-known/jwks.json"
        cache_key = described_class.key_for_jwks(uri)
        OmniauthOpenidFederation::CacheAdapter.write(cache_key, {test: "data"})

        described_class.delete_jwks(uri)

        expect(OmniauthOpenidFederation::CacheAdapter.read(cache_key)).to be_nil
      end
    end

    it "does nothing when cache adapter is not available" do
      unless OmniauthOpenidFederation::CacheAdapter.available?
        expect { described_class.delete_jwks("https://example.com/jwks.json") }.not_to raise_error
      end
    end
  end

  describe ".delete_signed_jwks" do
    it "deletes signed JWKS cache when cache adapter is available" do
      if OmniauthOpenidFederation::CacheAdapter.available?
        uri = "https://example.com/.well-known/signed-jwks.json"
        cache_key = described_class.key_for_signed_jwks(uri)
        OmniauthOpenidFederation::CacheAdapter.write(cache_key, {test: "data"})

        described_class.delete_signed_jwks(uri)

        expect(OmniauthOpenidFederation::CacheAdapter.read(cache_key)).to be_nil
      end
    end
  end
end

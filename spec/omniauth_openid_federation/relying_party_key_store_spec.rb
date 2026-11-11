# frozen_string_literal: true

require "spec_helper"
require "base64"

RSpec.describe OmniauthOpenidFederation::RelyingPartyKeyStore do
  let(:signing_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:encryption_key) { OpenSSL::PKey::RSA.new(2048) }

  describe OmniauthOpenidFederation::RelyingPartyKeyStore::FileStore do
    it "stores and loads PEM files" do
      Dir.mktmpdir do |dir|
        store = described_class.new(
          signing_path: File.join(dir, "sig.pem"),
          encryption_path: File.join(dir, "enc.pem")
        )
        store.store(signing_key: signing_key, encryption_key: encryption_key)
        loaded = store.load
        expect(loaded.signing_key.to_pem).to eq(signing_key.to_pem)
        expect(loaded.encryption_key.to_pem).to eq(encryption_key.to_pem)
      end
    end
  end

  describe OmniauthOpenidFederation::RelyingPartyKeyStore::CacheStore do
    def memory_adapter(cache)
      Class.new do
        def initialize(store)
          @store = store
        end

        def fetch(key, expires_in: nil)
          return @store[key] if @store.key?(key)
          @store[key] = yield
        end

        def read(key)
          @store[key]
        end

        def write(key, value, expires_in: nil)
          @store[key] = value
        end

        def delete(key)
          @store.delete(key)
        end
      end.new(cache)
    end

    it "stores and loads through CacheAdapter" do
      cache = {}
      OmniauthOpenidFederation::CacheAdapter.adapter = memory_adapter(cache)
      store = described_class.new(cache_key_prefix: "rp-keys-test")
      store.store(signing_key: signing_key, encryption_key: encryption_key)
      loaded = store.load
      expect(loaded.signing_key.to_pem).to eq(signing_key.to_pem)
      expect(loaded.encryption_key.to_pem).to eq(encryption_key.to_pem)
      expect(cache.fetch("rp-keys-test:signing_pem")).to include("BEGIN")
    ensure
      OmniauthOpenidFederation::CacheAdapter.reset!
    end

    it "applies encrypt before write and decrypt after read" do
      cache = {}
      OmniauthOpenidFederation::CacheAdapter.adapter = memory_adapter(cache)
      store = described_class.new(
        cache_key_prefix: "rp-keys-sealed",
        encrypt: ->(pem) { Base64.strict_encode64(pem) },
        decrypt: ->(blob) { Base64.strict_decode64(blob) }
      )
      store.store(signing_key: signing_key, encryption_key: encryption_key)

      aggregate_failures do
        expect(cache.fetch("rp-keys-sealed:signing_pem")).not_to include("BEGIN")
        expect(cache.fetch("rp-keys-sealed:encryption_pem")).not_to include("BEGIN")
        loaded = store.load
        expect(loaded.signing_key.to_pem).to eq(signing_key.to_pem)
        expect(loaded.encryption_key.to_pem).to eq(encryption_key.to_pem)
      end
    ensure
      OmniauthOpenidFederation::CacheAdapter.reset!
    end
  end
end

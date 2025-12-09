require "spec_helper"

RSpec.describe OmniauthOpenidFederation::CacheAdapter do
  before do
    # Reset before each test
    described_class.reset!
    OmniauthOpenidFederation::Configuration.reset!
  end

  describe ".reset!" do
    it "resets the adapter to nil" do
      # Set an adapter first
      custom_adapter = double("CustomAdapter")
      described_class.adapter = custom_adapter

      # Reset - this clears @adapter, so next access will re-detect
      described_class.reset!
      # After reset, adapter getter will re-detect (may return Rails.cache if available)
      # So we just verify the instance variable is nil, not the adapter getter
      expect(described_class.instance_variable_get(:@adapter)).to be_nil
    end
  end

  describe ".available?" do
    it "returns false when no adapter is available" do
      described_class.reset!
      # Ensure no adapter is detected
      allow(described_class).to receive(:detect_adapter).and_return(nil)
      expect(described_class.available?).to be false
    end

    it "returns true when adapter is available" do
      custom_adapter = double("CustomAdapter")
      described_class.adapter = custom_adapter
      expect(described_class.available?).to be true
    end
  end

  describe ".fetch" do
    context "when cache is not available" do
      before do
        described_class.adapter = nil
      end

      it "executes the block and returns the result" do
        result = described_class.fetch("test-key") { "computed-value" }
        expect(result).to eq("computed-value")
      end

      it "executes the block even with nil key" do
        # When cache is not available, fetch should just execute the block
        # even if key is nil
        result = described_class.fetch(nil) { "computed-value" }
        expect(result).to eq("computed-value")
      end
    end

    context "when cache is available" do
      let(:cache_store) { {} }
      let(:adapter) do
        double("Adapter").tap do |a|
          allow(a).to receive(:fetch) do |key, options = {}, &block|
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
        described_class.adapter = adapter
      end

      it "caches and returns the computed value" do
        result1 = described_class.fetch("test-key") { "computed-value" }

        # Second call should use cache
        result2 = described_class.fetch("test-key") { "different-value" }
        aggregate_failures do
          expect(result1).to eq("computed-value")
          expect(result2).to eq("computed-value")
        end
      end

      it "passes expires_in option to adapter" do
        allow(adapter).to receive(:fetch).with("test-key", expires_in: 3600)
        described_class.fetch("test-key", expires_in: 3600) { "value" }
        expect(adapter).to have_received(:fetch).with("test-key", expires_in: 3600)
      end

      it "passes nil expires_in when not specified" do
        allow(adapter).to receive(:fetch).with("test-key", expires_in: nil)
        described_class.fetch("test-key") { "value" }
        expect(adapter).to have_received(:fetch).with("test-key", expires_in: nil)
      end

      it "returns cached value when available" do
        allow(adapter).to receive(:fetch).and_return("cached-value")
        result = described_class.fetch("test-key") { "computed-value" }
        expect(result).to eq("cached-value")
      end
    end
  end

  describe ".read" do
    context "when cache is not available" do
      before do
        described_class.adapter = nil
      end

      it "returns nil" do
        expect(described_class.read("test-key")).to be_nil
      end
    end

    context "when cache is available" do
      let(:adapter) { double("Adapter") }

      before do
        described_class.adapter = adapter
      end

      it "delegates to adapter.read" do
        allow(adapter).to receive(:read).with("test-key").and_return("cached-value")
        aggregate_failures do
          expect(described_class.read("test-key")).to eq("cached-value")
          expect(adapter).to have_received(:read).with("test-key")
        end
      end

      it "returns nil when adapter returns nil" do
        allow(adapter).to receive(:read).with("test-key").and_return(nil)
        aggregate_failures do
          expect(described_class.read("test-key")).to be_nil
          expect(adapter).to have_received(:read).with("test-key")
        end
      end
    end
  end

  describe ".write" do
    context "when cache is not available" do
      before do
        described_class.adapter = nil
      end

      it "does nothing" do
        expect { described_class.write("test-key", "value") }.not_to raise_error
      end
    end

    context "when cache is available" do
      let(:adapter) { double("Adapter") }

      before do
        described_class.adapter = adapter
      end

      it "delegates to adapter.write" do
        allow(adapter).to receive(:write).with("test-key", "value", expires_in: nil)
        described_class.write("test-key", "value")
        expect(adapter).to have_received(:write).with("test-key", "value", expires_in: nil)
      end

      it "passes expires_in option" do
        allow(adapter).to receive(:write).with("test-key", "value", expires_in: 3600)
        described_class.write("test-key", "value", expires_in: 3600)
        expect(adapter).to have_received(:write).with("test-key", "value", expires_in: 3600)
      end
    end
  end

  describe ".delete" do
    context "when cache is not available" do
      before do
        described_class.adapter = nil
      end

      it "does nothing" do
        expect { described_class.delete("test-key") }.not_to raise_error
      end
    end

    context "when cache is available" do
      let(:adapter) { double("Adapter") }

      before do
        described_class.adapter = adapter
      end

      it "delegates to adapter.delete" do
        allow(adapter).to receive(:delete).with("test-key")
        described_class.delete("test-key")
        expect(adapter).to have_received(:delete).with("test-key")
      end
    end
  end

  describe ".clear" do
    context "when cache is not available" do
      before do
        described_class.adapter = nil
      end

      it "does nothing" do
        expect { described_class.clear }.not_to raise_error
      end
    end

    context "when cache is available" do
      context "when adapter supports clear" do
        let(:adapter) { double("Adapter", clear: true) }

        before do
          described_class.adapter = adapter
        end

        it "calls adapter.clear" do
          allow(adapter).to receive(:clear)
          described_class.clear
          expect(adapter).to have_received(:clear)
        end
      end

      context "when adapter does not support clear" do
        let(:adapter) { double("Adapter") }

        before do
          described_class.adapter = adapter
          allow(adapter).to receive(:respond_to?).with(:clear).and_return(false)
        end

        it "does not call adapter.clear" do
          allow(adapter).to receive(:clear)
          described_class.clear
          expect(adapter).not_to have_received(:clear)
        end
      end
    end
  end

  describe ".adapter" do
    context "when adapter is explicitly set" do
      let(:custom_adapter) { double("CustomAdapter") }

      it "returns the explicitly set adapter" do
        described_class.adapter = custom_adapter
        expect(described_class.adapter).to eq(custom_adapter)
      end
    end

    context "when adapter is configured via configuration" do
      let(:configured_adapter) { double("ConfiguredAdapter") }

      before do
        OmniauthOpenidFederation.configure do |config|
          config.cache_adapter = configured_adapter
        end
        described_class.reset!
      end

      it "returns the configured adapter" do
        expect(described_class.adapter).to eq(configured_adapter)
      end
    end

    context "when Rails.cache is available" do
      let(:rails_cache) do
        double("Rails.cache").tap do |cache|
          allow(cache).to receive(:fetch)
          allow(cache).to receive(:read)
          allow(cache).to receive(:write)
          allow(cache).to receive(:delete)
          allow(cache).to receive(:clear)
          allow(cache).to receive(:respond_to?).with(:cache).and_return(false)
        end
      end

      before do
        # Use stub_const which RSpec will clean up automatically
        rails_module = Class.new do
          class << self
            attr_accessor :cache

            def respond_to?(method)
              method == :cache || super
            end
          end
        end
        stub_const("Rails", rails_module)
        Rails.cache = rails_cache
        described_class.reset!
      end

      after do
        # RSpec's stub_const should automatically restore Rails
        # We just need to ensure CacheAdapter is reset
        described_class.reset!
      end

      it "returns a RailsCacheAdapter wrapping Rails.cache" do
        adapter = described_class.adapter
        expect(adapter).to be_a(OmniauthOpenidFederation::CacheAdapter::RailsCacheAdapter)
      end
    end

    context "when ActiveSupport::Cache::MemoryStore is available" do
      before do
        # Ensure Rails is not defined
        hide_const("Rails") if defined?(Rails)

        # Mock ActiveSupport::Cache::MemoryStore
        memory_store_class = Class.new do
          def initialize
          end
        end
        stub_const("ActiveSupport::Cache::MemoryStore", memory_store_class)
        stub_const("ActiveSupport::Cache::Store", Class.new)

        # Mock require to succeed
        allow(described_class).to receive(:require).with("active_support/cache/memory_store").and_return(true)

        described_class.reset!
      end

      after do
        described_class.reset!
      end

      it "returns a RailsCacheAdapter with MemoryStore" do
        adapter = described_class.adapter
        expect(adapter).to be_a(OmniauthOpenidFederation::CacheAdapter::RailsCacheAdapter)
      end
    end

    context "when ActiveSupport::Cache::MemoryStore load fails" do
      before do
        # Ensure Rails is not defined
        hide_const("Rails") if defined?(Rails)

        # Mock ActiveSupport::Cache::Store but make MemoryStore require fail
        stub_const("ActiveSupport::Cache::Store", Class.new)
        allow(described_class).to receive(:require).with("active_support/cache/memory_store")
          .and_raise(LoadError.new("cannot load such file"))

        described_class.reset!
      end

      after do
        described_class.reset!
      end

      it "returns nil" do
        expect(described_class.adapter).to be_nil
      end
    end

    context "when no cache is available" do
      before do
        # Ensure Rails is not defined
        hide_const("Rails") if defined?(Rails)

        # Ensure ActiveSupport::Cache is not available by stubbing detect_adapter
        allow(described_class).to receive(:detect_adapter).and_return(nil)

        described_class.reset!
      end

      after do
        described_class.reset!
      end

      it "returns nil" do
        expect(described_class.adapter).to be_nil
      end
    end
  end

  describe "RailsCacheAdapter" do
    let(:cache_store) { {} }
    let(:cache_store_double) do
      double("CacheStore").tap do |store|
        allow(store).to receive(:fetch) do |key, options = {}, &block|
          if cache_store.key?(key)
            cache_store[key]
          else
            value = block.call
            cache_store[key] = value
            value
          end
        end
        allow(store).to receive(:read) { |key| cache_store[key] }
        allow(store).to receive(:write) { |key, value, options = {}| cache_store[key] = value }
        allow(store).to receive(:delete) { |key| cache_store.delete(key) }
        allow(store).to receive(:clear) { cache_store.clear }
        allow(store).to receive(:respond_to?).with(:clear).and_return(true)
      end
    end
    let(:adapter) { described_class::RailsCacheAdapter.new(cache_store_double) }

    describe "#fetch" do
      it "delegates to cache store with options" do
        result = adapter.fetch("test-key", expires_in: 3600) { "value" }
        aggregate_failures do
          expect(result).to eq("value")
          expect(cache_store["test-key"]).to eq("value")
        end
      end

      it "works without expires_in" do
        result = adapter.fetch("test-key") { "value" }
        expect(result).to eq("value")
      end

      it "works with nil expires_in" do
        result = adapter.fetch("test-key", expires_in: nil) { "value" }
        expect(result).to eq("value")
      end
    end

    describe "#read" do
      it "delegates to cache store" do
        cache_store["test-key"] = "cached-value"
        expect(adapter.read("test-key")).to eq("cached-value")
      end

      it "returns nil for missing key" do
        expect(adapter.read("missing-key")).to be_nil
      end
    end

    describe "#write" do
      it "delegates to cache store with options" do
        adapter.write("test-key", "value", expires_in: 3600)
        expect(cache_store["test-key"]).to eq("value")
      end

      it "works without expires_in" do
        adapter.write("test-key", "value")
        expect(cache_store["test-key"]).to eq("value")
      end

      it "works with nil expires_in" do
        adapter.write("test-key", "value", expires_in: nil)
        expect(cache_store["test-key"]).to eq("value")
      end
    end

    describe "#delete" do
      it "delegates to cache store" do
        cache_store["test-key"] = "value"
        adapter.delete("test-key")
        expect(cache_store).not_to have_key("test-key")
      end
    end

    describe "#clear" do
      context "when cache store supports clear" do
        it "calls cache store clear" do
          cache_store["key1"] = "value1"
          cache_store["key2"] = "value2"
          adapter.clear
          expect(cache_store).to be_empty
        end
      end

      context "when cache store does not support clear" do
        let(:cache_store_double) do
          double("CacheStore").tap do |store|
            allow(store).to receive(:respond_to?).with(:clear).and_return(false)
            allow(store).to receive(:fetch)
            allow(store).to receive(:read)
            allow(store).to receive(:write)
            allow(store).to receive(:delete)
          end
        end

        it "does not raise error" do
          expect { adapter.clear }.not_to raise_error
        end
      end
    end
  end
end

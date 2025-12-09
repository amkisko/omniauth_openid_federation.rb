require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Configuration do
  after do
    # Reset configuration after each test
    described_class.instance_variable_set(:@config, nil)
  end

  describe ".config" do
    it "returns a Configuration instance" do
      expect(described_class.config).to be_a(described_class)
    end

    it "returns the same instance on subsequent calls" do
      config1 = described_class.config
      config2 = described_class.config
      expect(config1).to be(config2)
    end
  end

  describe ".configure" do
    it "yields the configuration instance" do
      expect { |b| described_class.configure(&b) }.to yield_with_args(be_a(described_class))
    end

    it "allows setting configuration values" do
      described_class.configure do |config|
        config.verify_ssl = false
        config.cache_ttl = 3600
      end

      aggregate_failures do
        expect(described_class.config.verify_ssl).to be false
        expect(described_class.config.cache_ttl).to eq(3600)
      end
    end

    it "returns the configuration instance" do
      result = described_class.configure do |config|
        config.verify_ssl = false
      end

      expect(result).to be_a(described_class)
    end
  end

  describe "#initialize" do
    it "sets default values" do
      config = described_class.new

      aggregate_failures do
        expect(config.verify_ssl).to be true
        expect(config.http_timeout).to eq(10)
        expect(config.max_retries).to eq(3)
        expect(config.retry_delay).to eq(1)
      end
    end

    it "sets cache_ttl to nil by default (manual rotation)" do
      config = described_class.new
      expect(config.cache_ttl).to be_nil
    end
  end

  describe "attribute accessors" do
    let(:config) { described_class.new }

    it "allows setting and getting verify_ssl" do
      config.verify_ssl = false
      expect(config.verify_ssl).to be false
    end

    it "allows setting and getting cache_ttl" do
      config.cache_ttl = 7200
      expect(config.cache_ttl).to eq(7200)
    end

    it "allows setting and getting http_timeout" do
      config.http_timeout = 30
      expect(config.http_timeout).to eq(30)
    end

    it "allows setting and getting max_retries" do
      config.max_retries = 5
      expect(config.max_retries).to eq(5)
    end

    it "allows setting and getting retry_delay" do
      config.retry_delay = 2
      expect(config.retry_delay).to eq(2)
    end
  end
end

require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Logger do
  let(:test_logger) { instance_double(Logger) }

  before do
    described_class.logger = test_logger
  end

  after do
    described_class.logger = nil
  end

  describe ".debug" do
    it "logs debug message" do
      expect(test_logger).to receive(:debug).with("[OpenIDFederation] test message")
      described_class.debug("test message")
    end
  end

  describe ".info" do
    it "logs info message" do
      expect(test_logger).to receive(:info).with("[OpenIDFederation] test message")
      described_class.info("test message")
    end
  end

  describe ".warn" do
    it "logs warning message" do
      expect(test_logger).to receive(:warn).with("[OpenIDFederation] test message")
      described_class.warn("test message")
    end
  end

  describe ".error" do
    it "logs error message" do
      expect(test_logger).to receive(:error).with("[OpenIDFederation] test message")
      described_class.error("test message")
    end
  end

  describe ".logger" do
    context "when logger is set" do
      it "returns the configured logger" do
        expect(described_class.logger).to eq(test_logger)
      end
    end

    context "when logger is not set" do
      before do
        described_class.logger = nil
      end

      it "returns OmniAuth.config.logger if available" do
        if defined?(OmniAuth) && OmniAuth.config.respond_to?(:logger)
          omniauth_logger = double("OmniAuthLogger")
          allow(OmniAuth.config).to receive(:logger).and_return(omniauth_logger)
          hide_const("Rails")
          hide_const("Logger")

          expect(described_class.logger).to eq(omniauth_logger)
        end
      end

      it "returns Rails.logger if available and OmniAuth logger is not" do
        rails_logger = double("RailsLogger")
        stub_const("Rails", double(logger: rails_logger))
        allow(OmniAuth).to receive(:config).and_return(double(logger: nil))
        hide_const("Logger")

        expect(described_class.logger).to eq(rails_logger)
      end

      it "returns standard Logger if Rails and OmniAuth are not available" do
        hide_const("Rails")
        hide_const("OmniAuth")

        logger = described_class.logger
        expect(logger).to respond_to(:debug)
        expect(logger).to respond_to(:info)
        expect(logger).to respond_to(:warn)
        expect(logger).to respond_to(:error)
      end

      it "returns NullLogger if no logger is available" do
        hide_const("Rails")
        hide_const("OmniAuth")
        hide_const("Logger")

        logger = described_class.logger
        expect(logger).to be_a(described_class::NullLogger)
      end
    end
  end

  describe "NullLogger" do
    let(:null_logger) { described_class::NullLogger.new }

    it "does not raise errors on debug" do
      expect { null_logger.debug("test") }.not_to raise_error
    end

    it "does not raise errors on info" do
      expect { null_logger.info("test") }.not_to raise_error
    end

    it "does not raise errors on warn" do
      expect { null_logger.warn("test") }.not_to raise_error
    end

    it "does not raise errors on error" do
      expect { null_logger.error("test") }.not_to raise_error
    end
  end
end

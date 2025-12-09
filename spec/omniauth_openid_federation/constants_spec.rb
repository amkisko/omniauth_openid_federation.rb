require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Constants do
  describe "KEY_ROTATION_HTTP_CODES" do
    it "contains expected HTTP status codes" do
      aggregate_failures do
        expect(described_class::KEY_ROTATION_HTTP_CODES).to include(401, 403, 404)
        expect(described_class::KEY_ROTATION_HTTP_CODES.length).to eq(3)
      end
    end

    it "is frozen" do
      expect(described_class::KEY_ROTATION_HTTP_CODES).to be_frozen
    end
  end

  describe "REQUEST_OBJECT_EXPIRATION_SECONDS" do
    it "is set to 600 seconds (10 minutes)" do
      expect(described_class::REQUEST_OBJECT_EXPIRATION_SECONDS).to eq(600)
    end
  end

  describe "MAX_RETRY_DELAY_SECONDS" do
    it "is set to 60 seconds" do
      expect(described_class::MAX_RETRY_DELAY_SECONDS).to eq(60)
    end
  end
end

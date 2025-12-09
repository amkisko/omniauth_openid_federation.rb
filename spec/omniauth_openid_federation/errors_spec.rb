require "spec_helper"

RSpec.describe "OmniauthOpenidFederation Error Classes" do
  describe OmniauthOpenidFederation::KeyRelatedError do
    it "returns true for key_related_error?" do
      error = described_class.new("Key error")
      expect(error.key_related_error?).to be true
    end

    it "is a subclass of FetchError" do
      expect(described_class.superclass).to eq(OmniauthOpenidFederation::FetchError)
    end
  end

  describe OmniauthOpenidFederation::KeyRelatedValidationError do
    it "returns true for key_related_error?" do
      error = described_class.new("Validation error")
      expect(error.key_related_error?).to be true
    end

    it "is a subclass of ValidationError" do
      expect(described_class.superclass).to eq(OmniauthOpenidFederation::ValidationError)
    end
  end
end

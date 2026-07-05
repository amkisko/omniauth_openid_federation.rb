require "spec_helper"

RSpec.describe OmniauthOpenidFederation::SecureCompare do
  describe ".secure_compare" do
    it "returns true for equal strings" do
      expect(described_class.secure_compare("abc", "abc")).to be(true)
    end

    it "returns false for unequal strings of equal length" do
      expect(described_class.secure_compare("abc", "abd")).to be(false)
    end

    it "returns false when lengths differ" do
      expect(described_class.secure_compare("abc", "abcd")).to be(false)
    end
  end
end

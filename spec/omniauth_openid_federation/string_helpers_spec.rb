require "spec_helper"

RSpec.describe OmniauthOpenidFederation::StringHelpers do
  describe ".present?" do
    it "returns true for non-empty string" do
      expect(described_class.present?("hello")).to be true
    end

    it "returns false for empty string" do
      expect(described_class.present?("")).to be false
    end

    it "returns false for whitespace-only string" do
      expect(described_class.present?("   ")).to be false
    end

    it "returns false for nil" do
      expect(described_class.present?(nil)).to be false
    end

    it "returns true for non-empty array" do
      expect(described_class.present?([1, 2, 3])).to be true
    end

    it "returns false for empty array" do
      expect(described_class.present?([])).to be false
    end

    it "returns true for non-empty hash" do
      expect(described_class.present?({key: "value"})).to be true
    end

    it "returns false for empty hash" do
      expect(described_class.present?({})).to be false
    end

    it "returns true for non-nil object" do
      expect(described_class.present?(Object.new)).to be true
    end
  end

  describe ".blank?" do
    it "returns false for non-empty string" do
      expect(described_class.blank?("hello")).to be false
    end

    it "returns true for empty string" do
      expect(described_class.blank?("")).to be true
    end

    it "returns true for whitespace-only string" do
      expect(described_class.blank?("   ")).to be true
    end

    it "returns true for nil" do
      expect(described_class.blank?(nil)).to be true
    end

    it "returns false for non-empty array" do
      expect(described_class.blank?([1, 2, 3])).to be false
    end

    it "returns true for empty array" do
      expect(described_class.blank?([])).to be true
    end

    it "returns false for non-empty hash" do
      expect(described_class.blank?({key: "value"})).to be false
    end

    it "returns true for empty hash" do
      expect(described_class.blank?({})).to be true
    end
  end
end

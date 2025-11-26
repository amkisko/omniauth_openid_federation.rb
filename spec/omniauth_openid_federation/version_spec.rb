require "spec_helper"

RSpec.describe OmniauthOpenidFederation do
  describe "VERSION" do
    it "is defined" do
      expect(OmniauthOpenidFederation::VERSION).to be_a(String)
    end

    it "is frozen" do
      expect(OmniauthOpenidFederation::VERSION).to be_frozen
    end

    it "has a valid version format" do
      expect(OmniauthOpenidFederation::VERSION).to match(/\d+\.\d+\.\d+/)
    end
  end
end

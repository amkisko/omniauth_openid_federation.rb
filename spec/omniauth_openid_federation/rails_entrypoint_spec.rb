# frozen_string_literal: true

require "spec_helper"

RSpec.describe OmniauthOpenidFederation do
  describe "rails entrypoint" do
    it "defines a loadable rails.rb path in the gem" do
      path = File.expand_path("../../lib/omniauth_openid_federation/rails.rb", __dir__)
      expect(File.file?(path)).to be(true)
      contents = File.read(path)
      expect(contents).to include('require "omniauth_openid_federation"')
      expect(contents).to include("federation_controller.rb")
    end
  end
end

# frozen_string_literal: true

require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Utils, ".rsa_key_to_jwk" do
  let(:key) { OpenSSL::PKey::RSA.new(2048) }

  it "exports public material by default" do
    jwk = described_class.rsa_key_to_jwk(key, use: "sig")
    expect(jwk[:d]).to be_nil
    expect(jwk[:use]).to eq("sig")
    expect(jwk[:n]).to be_a(String)
  end

  it "includes private material only when include_private is true" do
    jwk = described_class.rsa_key_to_jwk(key, use: "sig", include_private: true)
    expect(jwk[:d]).to be_a(String)
  end
end

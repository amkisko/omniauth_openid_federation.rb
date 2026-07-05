require "spec_helper"

RSpec.describe OmniauthOpenidFederation::IdToken do
  subject(:id_token) { described_class.new(claims) }

  let(:claims) do
    {
      iss: "https://provider.example.com",
      sub: "user-123",
      aud: "client-id",
      exp: Time.now.to_i + 3600,
      iat: Time.now.to_i,
      nonce: "nonce-value"
    }
  end

  it "exposes raw_attributes with symbol keys" do
    expect(id_token.raw_attributes[:sub]).to eq("user-123")
  end

  it "provides claim readers" do
    expect(id_token.iss).to eq(claims[:iss])
    expect(id_token.sub).to eq(claims[:sub])
    expect(id_token.aud).to eq(claims[:aud])
    expect(id_token.nonce).to eq(claims[:nonce])
  end
end

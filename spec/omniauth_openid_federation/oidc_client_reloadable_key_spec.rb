# frozen_string_literal: true

require "spec_helper"

RSpec.describe OmniauthOpenidFederation::OidcClient, "#private_key" do
  subject(:client) do
    described_class.new(
      identifier: "rp",
      redirect_uri: "https://rp.example.com/cb",
      authorization_endpoint: "https://op.example.com/authorize",
      token_endpoint: "https://op.example.com/token"
    )
  end

  it "picks up a new key from a callable without rebuilding the client" do
    first = OpenSSL::PKey::RSA.new(2048)
    second = OpenSSL::PKey::RSA.new(2048)
    current = first
    client.private_key = -> { current }

    expect(client.private_key.to_pem).to eq(first.to_pem)
    current = second
    expect(client.private_key.to_pem).to eq(second.to_pem)
  end
end

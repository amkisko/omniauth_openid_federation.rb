# frozen_string_literal: true

require "spec_helper"

RSpec.describe OmniauthOpenidFederation::KeyResolver do
  let(:key) { OpenSSL::PKey::RSA.new(2048) }

  it "returns RSA keys unchanged" do
    expect(described_class.resolve(key)).to equal(key)
  end

  it "parses PEM strings" do
    resolved = described_class.resolve(key.to_pem)
    expect(resolved).to be_a(OpenSSL::PKey::RSA)
    expect(resolved.to_pem).to eq(key.to_pem)
  end

  it "resolves callables on each invocation" do
    current = key
    callable = -> { current }
    expect(described_class.resolve(callable)).to equal(key)
    current = OpenSSL::PKey::RSA.new(2048)
    expect(described_class.resolve(callable)).to equal(current)
  end

  it "returns nil for nil" do
    expect(described_class.resolve(nil)).to be_nil
  end
end

require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Jwe do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:signed_jwt) do
    JWT.encode({sub: "user123", exp: Time.now.to_i + 3600}, private_key, "RS256", {kid: "test"})
  end

  describe ".encrypted?" do
    it "returns true for compact JWE tokens" do
      encrypted = described_class.encrypt(signed_jwt, public_key, alg: "RSA-OAEP", enc: "A128CBC-HS256")
      expect(described_class.encrypted?(encrypted)).to be(true)
    end

    it "returns false for signed JWTs" do
      expect(described_class.encrypted?(signed_jwt)).to be(false)
    end
  end

  describe ".encrypt and .decrypt" do
    it "round-trips nested JWT plaintext" do
      encrypted = described_class.encrypt(signed_jwt, public_key, alg: "RSA-OAEP", enc: "A128CBC-HS256")
      expect(described_class.decrypt(encrypted, private_key)).to eq(signed_jwt)
    end

    it "raises DecryptionError for malformed compact tokens" do
      expect {
        described_class.decrypt("header.encrypted_key.iv.ciphertext.tag", private_key)
      }.to raise_error(OmniauthOpenidFederation::DecryptionError, /Failed to decrypt JWE/)
    end
  end
end

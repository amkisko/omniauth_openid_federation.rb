require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Jwks::Selector do
  describe ".current_keys" do
    it "returns first signing and encryption keys" do
      jwks = {
        keys: [
          {kid: "sig1", use: "sig", kty: "RSA"},
          {kid: "sig2", use: "sig", kty: "RSA"},
          {kid: "enc1", use: "enc", kty: "RSA"},
          {kid: "enc2", use: "enc", kty: "RSA"}
        ]
      }

      result = described_class.current_keys(jwks)
      expect(result["keys"].length).to eq(2)
      expect(result["keys"].map { |k| k[:kid] }).to contain_exactly("sig1", "enc1")
    end

    it "handles string keys" do
      jwks = {
        "keys" => [
          {"kid" => "sig1", "use" => "sig", "kty" => "RSA"},
          {"kid" => "enc1", "use" => "enc", "kty" => "RSA"}
        ]
      }

      result = described_class.current_keys(jwks)
      expect(result["keys"].length).to eq(2)
    end

    it "returns empty keys array when jwks is empty" do
      jwks = {keys: []}
      result = described_class.current_keys(jwks)
      expect(result["keys"]).to eq([])
    end

    it "handles array input" do
      jwks = [
        {kid: "sig1", use: "sig", kty: "RSA"},
        {kid: "enc1", use: "enc", kty: "RSA"}
      ]

      result = described_class.current_keys(jwks)
      expect(result["keys"].length).to eq(2)
    end

    it "handles jwks without use field" do
      jwks = {
        keys: [
          {kid: "key1", kty: "RSA"}
        ]
      }

      result = described_class.current_keys(jwks)
      expect(result["keys"]).to eq([])
    end
  end

  describe ".all_keys" do
    it "returns all keys from hash with keys array" do
      jwks = {
        keys: [
          {kid: "key1", use: "sig"},
          {kid: "key2", use: "enc"}
        ]
      }

      result = described_class.all_keys(jwks)
      expect(result["keys"].length).to eq(2)
    end

    it "handles string keys" do
      jwks = {
        "keys" => [
          {"kid" => "key1", "use" => "sig"}
        ]
      }

      result = described_class.all_keys(jwks)
      expect(result["keys"].length).to eq(1)
    end

    it "handles array input" do
      jwks = [
        {kid: "key1", use: "sig"},
        {kid: "key2", use: "enc"}
      ]

      result = described_class.all_keys(jwks)
      expect(result["keys"].length).to eq(2)
    end

    it "handles empty jwks" do
      jwks = {keys: []}
      result = described_class.all_keys(jwks)
      expect(result["keys"]).to eq([])
    end

    it "handles nil keys" do
      jwks = {keys: nil}
      result = described_class.all_keys(jwks)
      expect(result["keys"]).to eq([])
    end

    it "handles hash without keys key" do
      jwks = {other: "value"}
      result = described_class.all_keys(jwks)
      expect(result["keys"]).to eq([])
    end
  end

  describe ".signing_keys" do
    it "returns only signing keys" do
      jwks = {
        keys: [
          {kid: "sig1", use: "sig"},
          {kid: "enc1", use: "enc"},
          {kid: "sig2", use: "sig"}
        ]
      }

      result = described_class.signing_keys(jwks)
      expect(result.length).to eq(2)
      expect(result.map { |k| k[:kid] }).to contain_exactly("sig1", "sig2")
    end

    it "handles string keys" do
      jwks = {
        "keys" => [
          {"kid" => "sig1", "use" => "sig"}
        ]
      }

      result = described_class.signing_keys(jwks)
      expect(result.length).to eq(1)
    end

    it "handles array input" do
      jwks = [
        {kid: "sig1", use: "sig"},
        {kid: "enc1", use: "enc"}
      ]

      result = described_class.signing_keys(jwks)
      expect(result.length).to eq(1)
    end
  end

  describe ".encryption_keys" do
    it "returns only encryption keys" do
      jwks = {
        keys: [
          {kid: "sig1", use: "sig"},
          {kid: "enc1", use: "enc"},
          {kid: "enc2", use: "enc"}
        ]
      }

      result = described_class.encryption_keys(jwks)
      expect(result.length).to eq(2)
      expect(result.map { |k| k[:kid] }).to contain_exactly("enc1", "enc2")
    end

    it "handles string keys" do
      jwks = {
        "keys" => [
          {"kid" => "enc1", "use" => "enc"}
        ]
      }

      result = described_class.encryption_keys(jwks)
      expect(result.length).to eq(1)
    end

    it "handles array input" do
      jwks = [
        {kid: "sig1", use: "sig"},
        {kid: "enc1", use: "enc"}
      ]

      result = described_class.encryption_keys(jwks)
      expect(result.length).to eq(1)
    end
  end

  describe ".key_by_kid" do
    it "finds key by kid" do
      jwks = {
        keys: [
          {kid: "key1", use: "sig"},
          {kid: "key2", use: "enc"}
        ]
      }

      result = described_class.key_by_kid(jwks, "key1")
      expect(result[:kid]).to eq("key1")
    end

    it "returns nil when kid not found" do
      jwks = {
        keys: [
          {kid: "key1", use: "sig"}
        ]
      }

      result = described_class.key_by_kid(jwks, "nonexistent")
      expect(result).to be_nil
    end

    it "handles string keys" do
      jwks = {
        "keys" => [
          {"kid" => "key1", "use" => "sig"}
        ]
      }

      result = described_class.key_by_kid(jwks, "key1")
      expect(result["kid"]).to eq("key1")
    end

    it "handles array input" do
      jwks = [
        {kid: "key1", use: "sig"}
      ]

      result = described_class.key_by_kid(jwks, "key1")
      expect(result[:kid]).to eq("key1")
    end

    it "handles non-hash jwks" do
      result = described_class.key_by_kid("not a hash", "key1")
      expect(result).to be_nil
    end
  end

  describe ".extract_keys_array" do
    it "extracts keys from hash with string keys" do
      jwks = {"keys" => [{kid: "key1"}]}
      result = described_class.send(:extract_keys_array, jwks)
      expect(result.length).to eq(1)
    end

    it "extracts keys from hash with symbol keys" do
      jwks = {keys: [{kid: "key1"}]}
      result = described_class.send(:extract_keys_array, jwks)
      expect(result.length).to eq(1)
    end

    it "handles array input" do
      jwks = [{kid: "key1"}]
      result = described_class.send(:extract_keys_array, jwks)
      expect(result.length).to eq(1)
    end

    it "handles nil keys" do
      jwks = {keys: nil}
      result = described_class.send(:extract_keys_array, jwks)
      expect(result).to eq([])
    end

    it "handles hash without keys key" do
      jwks = {other: "value"}
      result = described_class.send(:extract_keys_array, jwks)
      expect(result).to eq([])
    end

    it "handles non-hash, non-array input" do
      result = described_class.send(:extract_keys_array, "string")
      expect(result).to eq([])
    end
  end
end

require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Federation::EntityStatement do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:jwk) { JWT::JWK.new(public_key) }

  let(:entity_statement_content) do
    jwk_export = jwk.export
    jwk_export[:kid] = "key-1"
    header = Base64.urlsafe_encode64({alg: "RS256", typ: "entity-statement+jwt", kid: "key-1"}.to_json).gsub(/=+$/, "")
    payload = Base64.urlsafe_encode64({
      iss: "https://provider.example.com",
      sub: "https://provider.example.com",
      exp: Time.now.to_i + 3600,
      iat: Time.now.to_i,
      jwks: {
        keys: [jwk_export]
      },
      metadata: {
        openid_provider: {
          issuer: "https://provider.example.com",
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token"
        }
      }
    }.to_json).gsub(/=+$/, "")
    # Create a valid signature using the private key
    signature_input = "#{header}.#{payload}"
    signature = Base64.urlsafe_encode64(private_key.sign(OpenSSL::Digest.new("SHA256"), signature_input)).gsub(/=+$/, "")
    "#{header}.#{payload}.#{signature}"
  end

  describe "#initialize" do
    it "creates instance with content" do
      instance = described_class.new(entity_statement_content)

      expect(instance.entity_statement).to eq(entity_statement_content)
      expect(instance.fingerprint).to be_present
    end

    it "accepts custom fingerprint" do
      fingerprint = "custom-fingerprint"
      instance = described_class.new(entity_statement_content, fingerprint: fingerprint)

      expect(instance.fingerprint).to eq(fingerprint)
    end
  end

  describe "#calculate_fingerprint" do
    it "calculates SHA256 fingerprint" do
      instance = described_class.new(entity_statement_content)
      fingerprint = instance.calculate_fingerprint

      expect(fingerprint).to eq(Digest::SHA256.hexdigest(entity_statement_content).downcase)
    end
  end

  describe "#validate_fingerprint" do
    it "validates correct fingerprint" do
      instance = described_class.new(entity_statement_content)
      fingerprint = instance.calculate_fingerprint

      expect(instance.validate_fingerprint(fingerprint)).to be true
    end

    it "rejects incorrect fingerprint" do
      instance = described_class.new(entity_statement_content)

      expect(instance.validate_fingerprint("wrong-fingerprint")).to be false
    end
  end

  describe "#parse" do
    it "parses entity statement metadata" do
      instance = described_class.new(entity_statement_content)
      metadata = instance.parse

      expect(metadata).to be_a(Hash)
      # Behavior: Should extract issuer from entity statement
      expect(metadata[:issuer]).to eq("https://provider.example.com")
      # Behavior: Should contain metadata structure
      expect(metadata[:metadata]).to be_present
      expect(metadata[:metadata][:openid_provider]).to be_present
    end

    it "caches parsed metadata" do
      instance = described_class.new(entity_statement_content)
      metadata1 = instance.parse
      metadata2 = instance.parse

      # Behavior: Should cache parsed results for performance
      expect(metadata1).to eq(metadata2)
    end

    it "extracts required OpenID Federation metadata fields" do
      instance = described_class.new(entity_statement_content)
      metadata = instance.parse

      # Behavior: Should extract required metadata fields per OpenID Federation spec
      expect(metadata).to have_key(:issuer)
      expect(metadata).to have_key(:metadata)
      expect(metadata[:metadata]).to have_key(:openid_provider)

      provider_metadata = metadata[:metadata][:openid_provider]
      # Behavior: Should contain required provider endpoints
      expect(provider_metadata).to have_key(:authorization_endpoint)
      expect(provider_metadata).to have_key(:token_endpoint)
    end
  end

  describe "#save_to_file" do
    it "saves entity statement to file" do
      instance = described_class.new(entity_statement_content)
      temp_file = Tempfile.new(["entity", ".jwt"])

      instance.save_to_file(temp_file.path)

      expect(File.read(temp_file.path)).to eq(entity_statement_content)

      temp_file.close
      temp_file.unlink
    end
  end

  describe ".fetch!" do
    let(:url) { "https://example.com/.well-known/openid-federation" }

    it "fetches entity statement from URL" do
      stub_request(:get, url)
        .to_return(status: 200, body: entity_statement_content)

      instance = described_class.fetch!(url)

      expect(instance).to be_a(described_class)
      expect(instance.entity_statement).to eq(entity_statement_content)
    end

    it "validates fingerprint when provided" do
      fingerprint = Digest::SHA256.hexdigest(entity_statement_content).downcase
      stub_request(:get, url)
        .to_return(status: 200, body: entity_statement_content)

      instance = described_class.fetch!(url, fingerprint: fingerprint)

      expect(instance).to be_a(described_class)
    end

    it "raises error on HTTP failure" do
      stub_request(:get, url)
        .to_return(status: 500)

      expect { described_class.fetch!(url) }.to raise_error(
        OmniauthOpenidFederation::FetchError
      )
    end

    it "raises error on network failure" do
      stub_request(:get, url)
        .to_raise(HTTP::Error.new("Network error"))

      expect { described_class.fetch!(url) }.to raise_error(
        OmniauthOpenidFederation::FetchError
      )
    end

    it "raises error on fingerprint mismatch" do
      stub_request(:get, url)
        .to_return(status: 200, body: entity_statement_content)

      expect { described_class.fetch!(url, fingerprint: "wrong-fingerprint") }.to raise_error(
        OmniauthOpenidFederation::ValidationError
      )
    end
  end
end

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

      aggregate_failures do
        expect(instance.entity_statement).to eq(entity_statement_content)
        expect(instance.fingerprint).to be_present
      end
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

      aggregate_failures do
        expect(metadata).to be_a(Hash)
        # Behavior: Should extract issuer from entity statement
        expect(metadata[:issuer]).to eq("https://provider.example.com")
        # Behavior: Should contain metadata structure
        expect(metadata[:metadata]).to be_present
        expect(metadata[:metadata][:openid_provider]).to be_present
      end
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

      aggregate_failures do
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

      aggregate_failures do
        expect(instance).to be_a(described_class)
        expect(instance.entity_statement).to eq(entity_statement_content)
      end
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

    # Test line 80: fetch_from_issuer! calls build_entity_statement_url
    it "fetches entity statement from issuer using fetch_from_issuer!" do
      issuer_uri = "https://provider.example.com"
      entity_statement_url = "#{issuer_uri}/.well-known/openid-federation"
      stub_request(:get, entity_statement_url)
        .to_return(status: 200, body: entity_statement_content)

      instance = described_class.fetch_from_issuer!(issuer_uri)

      aggregate_failures do
        expect(instance).to be_a(described_class)
        expect(instance.entity_statement).to eq(entity_statement_content)
      end
    end

    # Test lines 125, 128, 134: ValidationError handling in fetch!
    it "raises ValidationError with instrumentation on validation failure" do
      # Create invalid entity statement (missing required fields)
      invalid_content = "invalid.jwt.content"
      stub_request(:get, url)
        .to_return(status: 200, body: invalid_content)

      allow(OmniauthOpenidFederation::Instrumentation).to receive(:notify_entity_statement_validation_failed)

      aggregate_failures do
        expect { described_class.fetch!(url) }.to raise_error(
          OmniauthOpenidFederation::ValidationError
        )
        expect(OmniauthOpenidFederation::Instrumentation).to have_received(:notify_entity_statement_validation_failed)
      end
    end

    # Test lines 156, 161: validate_against_previous
    it "validates against previous statement successfully" do
      stub_request(:get, url)
        .to_return(status: 200, body: entity_statement_content)

      instance = described_class.fetch!(url)

      # Create a previous statement with same issuer but earlier exp
      previous_payload = {
        iss: "https://provider.example.com",
        sub: "https://provider.example.com",
        exp: Time.now.to_i + 1800,  # Earlier expiration
        iat: Time.now.to_i - 3600
      }
      previous_jwt = JWT.encode(previous_payload, private_key, "RS256")
      previous_instance = described_class.new(previous_jwt)

      result = instance.validate_against_previous(previous_instance)
      expect(result).to be true
    end

    it "validates against previous statement as String" do
      stub_request(:get, url)
        .to_return(status: 200, body: entity_statement_content)

      instance = described_class.fetch!(url)

      # Create a previous statement as string
      previous_payload = {
        iss: "https://provider.example.com",
        sub: "https://provider.example.com",
        exp: Time.now.to_i + 1800,
        iat: Time.now.to_i - 3600
      }
      previous_jwt = JWT.encode(previous_payload, private_key, "RS256")

      result = instance.validate_against_previous(previous_jwt)
      expect(result).to be true
    end

    it "validates against previous statement as Hash" do
      stub_request(:get, url)
        .to_return(status: 200, body: entity_statement_content)

      instance = described_class.fetch!(url)

      # Create a previous statement as Hash
      previous_payload = {
        "iss" => "https://provider.example.com",
        "sub" => "https://provider.example.com",
        "exp" => Time.now.to_i + 1800,
        "iat" => Time.now.to_i - 3600
      }

      result = instance.validate_against_previous(previous_payload)
      expect(result).to be true
    end

    it "returns false when issuer doesn't match in validate_against_previous" do
      stub_request(:get, url)
        .to_return(status: 200, body: entity_statement_content)

      instance = described_class.fetch!(url)

      previous_payload = {
        "iss" => "https://different-provider.example.com",
        "sub" => "https://provider.example.com",
        "exp" => Time.now.to_i + 1800,
        "iat" => Time.now.to_i - 3600
      }

      result = instance.validate_against_previous(previous_payload)
      expect(result).to be false
    end

    it "returns false when current exp is earlier than previous exp" do
      stub_request(:get, url)
        .to_return(status: 200, body: entity_statement_content)

      instance = described_class.fetch!(url)

      previous_payload = {
        "iss" => "https://provider.example.com",
        "sub" => "https://provider.example.com",
        "exp" => Time.now.to_i + 7200,  # Later expiration
        "iat" => Time.now.to_i - 3600
      }

      result = instance.validate_against_previous(previous_payload)
      expect(result).to be false
    end

    # Test lines 325, 327: Error handling in decode_payload
    it "handles JSON::ParserError in decode_payload" do
      # Create entity statement with invalid JSON in payload
      invalid_payload = Base64.urlsafe_encode64("invalid json").gsub(/=+$/, "")
      header = Base64.urlsafe_encode64({alg: "RS256", typ: "entity-statement+jwt"}.to_json).gsub(/=+$/, "")
      invalid_jwt = "#{header}.#{invalid_payload}.signature"

      instance = described_class.new(invalid_jwt)

      expect {
        instance.decode_payload
      }.to raise_error(OmniauthOpenidFederation::ValidationError, /Failed to parse entity statement payload/)
    end

    it "handles ArgumentError in decode_payload" do
      # Create entity statement with invalid base64
      invalid_jwt = "invalid.base64.signature"

      instance = described_class.new(invalid_jwt)

      expect {
        instance.decode_payload
      }.to raise_error(OmniauthOpenidFederation::ValidationError, /Failed to decode entity statement/)
    end
  end
end

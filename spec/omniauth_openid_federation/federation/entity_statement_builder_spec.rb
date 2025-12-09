require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Federation::EntityStatementBuilder do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:entity_jwk) { JWT::JWK.new(public_key) }
  let(:issuer) { "https://provider.example.com" }
  let(:entity_subject) { "https://provider.example.com" }
  let(:jwks) do
    {
      "keys" => [entity_jwk.export.stringify_keys]
    }
  end
  let(:metadata) do
    {
      openid_provider: {
        issuer: issuer,
        authorization_endpoint: "#{issuer}/oauth2/authorize",
        token_endpoint: "#{issuer}/oauth2/token",
        userinfo_endpoint: "#{issuer}/oauth2/userinfo",
        jwks_uri: "#{issuer}/.well-known/jwks.json",
        signed_jwks_uri: "#{issuer}/.well-known/signed-jwks.json"
      }
    }
  end

  describe "#initialize" do
    it "initializes with required parameters" do
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks,
        metadata: metadata
      )

      expect(builder).to be_a(described_class)
    end

    it "extracts kid from JWKS when not provided" do
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks,
        metadata: metadata
      )

      expect(builder.instance_variable_get(:@kid)).to eq(entity_jwk.export[:kid])
    end

    it "uses provided kid when given" do
      custom_kid = "custom-key-id"
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks,
        metadata: metadata,
        kid: custom_kid
      )

      expect(builder.instance_variable_get(:@kid)).to eq(custom_kid)
    end

    it "uses custom expiration_seconds" do
      custom_expiration = 7200
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks,
        metadata: metadata,
        expiration_seconds: custom_expiration
      )

      expect(builder.instance_variable_get(:@expiration_seconds)).to eq(custom_expiration)
    end

    it "normalizes JWKS hash with :keys symbol" do
      jwks_with_symbol = {keys: [entity_jwk.export.stringify_keys]}
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks_with_symbol,
        metadata: metadata
      )

      normalized = builder.instance_variable_get(:@jwks)
      aggregate_failures do
        expect(normalized).to have_key("keys")
        expect(normalized["keys"]).to be_an(Array)
      end
    end

    it "normalizes JWKS array" do
      jwks_array = [entity_jwk.export.stringify_keys]
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks_array,
        metadata: metadata
      )

      normalized = builder.instance_variable_get(:@jwks)
      aggregate_failures do
        expect(normalized).to have_key("keys")
        expect(normalized["keys"]).to be_an(Array)
      end
    end

    it "normalizes single JWK hash" do
      single_jwk = entity_jwk.export.stringify_keys
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: single_jwk,
        metadata: metadata
      )

      normalized = builder.instance_variable_get(:@jwks)
      aggregate_failures do
        expect(normalized).to have_key("keys")
        expect(normalized["keys"]).to be_an(Array)
        expect(normalized["keys"].length).to eq(1)
      end
    end

    it "normalizes keys with symbol keys to string keys" do
      jwks_with_symbols = {
        keys: [
          {
            kty: "RSA",
            kid: "test-kid",
            use: "sig"
          }
        ]
      }
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks_with_symbols,
        metadata: metadata
      )

      normalized = builder.instance_variable_get(:@jwks)
      aggregate_failures do
        expect(normalized["keys"].first).to have_key("kty")
        expect(normalized["keys"].first).not_to have_key(:kty)
      end
    end
  end

  describe "#build" do
    it "builds and signs entity statement JWT" do
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks,
        metadata: metadata
      )

      jwt_string = builder.build

      aggregate_failures do
        expect(jwt_string).to be_a(String)
        expect(jwt_string.split(".").length).to eq(3) # JWT has 3 parts
      end
    end

    it "includes issuer, subject, iat, exp in payload" do
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks,
        metadata: metadata
      )

      jwt_string = builder.build
      decoded = JWT.decode(jwt_string, public_key, true, {algorithm: "RS256"})

      payload = decoded.first
      aggregate_failures do
        expect(payload["iss"]).to eq(issuer)
        expect(payload["sub"]).to eq(entity_subject)
        expect(payload["iat"]).to be_a(Integer)
        expect(payload["exp"]).to be_a(Integer)
        expect(payload["exp"]).to be > payload["iat"]
      end
    end

    it "includes jwks in payload" do
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks,
        metadata: metadata
      )

      jwt_string = builder.build
      decoded = JWT.decode(jwt_string, public_key, true, {algorithm: "RS256"})

      payload = decoded.first
      aggregate_failures do
        expect(payload["jwks"]).to be_a(Hash)
        expect(payload["jwks"]["keys"]).to be_an(Array)
      end
    end

    it "includes metadata in payload" do
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks,
        metadata: metadata
      )

      jwt_string = builder.build
      decoded = JWT.decode(jwt_string, public_key, true, {algorithm: "RS256"})

      payload = decoded.first
      aggregate_failures do
        expect(payload["metadata"]).to be_a(Hash)
        expect(payload["metadata"]["openid_provider"]).to be_present
      end
    end

    it "uses custom expiration_seconds" do
      custom_expiration = 7200
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks,
        metadata: metadata,
        expiration_seconds: custom_expiration
      )

      jwt_string = builder.build
      decoded = JWT.decode(jwt_string, public_key, true, {algorithm: "RS256"})

      payload = decoded.first
      expect(payload["exp"] - payload["iat"]).to eq(custom_expiration)
    end

    it "raises ConfigurationError when issuer is missing" do
      builder = described_class.new(
        issuer: "",
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks,
        metadata: metadata
      )

      expect { builder.build }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /Issuer is required/
      )
    end

    it "raises ConfigurationError when subject is missing" do
      builder = described_class.new(
        issuer: issuer,
        subject: "",
        private_key: private_key,
        jwks: jwks,
        metadata: metadata
      )

      expect { builder.build }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /Subject is required/
      )
    end

    it "raises ConfigurationError when private_key is missing" do
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: nil,
        jwks: jwks,
        metadata: metadata
      )

      expect { builder.build }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /Private key is required/
      )
    end

    it "raises ConfigurationError when jwks is missing" do
      expect {
        described_class.new(
          issuer: issuer,
          subject: entity_subject,
          private_key: private_key,
          jwks: nil,
          metadata: metadata
        )
      }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /JWKS must be a Hash or Array/
      )
    end

    it "raises ConfigurationError when jwks is empty" do
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: {},
        metadata: metadata
      )
      expect {
        builder.build
      }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /(JWKS is required|Key ID \(kid\) is required|JWKS must contain at least one key)/
      )
    end

    it "raises ConfigurationError when jwks has no keys" do
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: {"keys" => []},
        metadata: metadata
      )

      expect { builder.build }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /must contain at least one key/
      )
    end

    it "raises ConfigurationError when metadata is missing" do
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks,
        metadata: nil
      )

      expect { builder.build }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /Metadata is required/
      )
    end

    it "raises ConfigurationError when metadata is empty" do
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks,
        metadata: {}
      )

      expect { builder.build }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /Metadata is required/
      )
    end

    it "raises ConfigurationError when kid is missing" do
      jwks_without_kid = {
        "keys" => [
          {
            "kty" => "RSA",
            "use" => "sig"
          }
        ]
      }
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks_without_kid,
        metadata: metadata
      )

      expect { builder.build }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /Key ID \(kid\) is required/
      )
    end

    it "raises SignatureError when signing fails" do
      invalid_key = "not a key"
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: invalid_key,
        jwks: jwks,
        metadata: metadata,
        kid: entity_jwk.export[:kid]
      )

      expect { builder.build }.to raise_error(
        OmniauthOpenidFederation::SignatureError
      )
    end

    it "raises ConfigurationError when jwks is not Hash or Array" do
      expect {
        described_class.new(
          issuer: issuer,
          subject: entity_subject,
          private_key: private_key,
          jwks: "not a hash or array",
          metadata: metadata
        )
      }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /JWKS must be a Hash or Array/
      )
    end

    it "handles non-Hash key objects in JWKS" do
      # Create a mock object that responds to to_json but is not a Hash
      # The normalize_keys method returns non-Hash objects as-is (line 129)
      jwk_object = double("JWKObject")
      allow(jwk_object).to receive(:to_json).and_return('{"kty":"RSA","kid":"test-kid","use":"sig"}')

      jwks_with_object = {"keys" => [jwk_object]}
      builder = described_class.new(
        issuer: issuer,
        subject: entity_subject,
        private_key: private_key,
        jwks: jwks_with_object,
        metadata: metadata,
        kid: "test-kid"
      )

      normalized = builder.instance_variable_get(:@jwks)
      # When key is not a Hash, normalize_keys returns it as-is (line 129)
      aggregate_failures do
        expect(normalized["keys"]).to be_an(Array)
        expect(normalized["keys"].first).to eq(jwk_object)
      end
    end
  end
end

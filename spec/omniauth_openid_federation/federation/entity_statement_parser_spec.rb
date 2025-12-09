require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Federation::EntityStatementParser do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:jwk) { JWT::JWK.new(public_key) }

  let(:payload) do
    {
      iss: "https://provider.example.com",
      sub: "https://provider.example.com",
      exp: Time.now.to_i + 3600,
      iat: Time.now.to_i,
      jwks: {
        keys: [jwk.export]
      },
      metadata: {
        openid_provider: {
          issuer: "https://provider.example.com",
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token",
          userinfo_endpoint: "https://provider.example.com/oauth2/userinfo",
          jwks_uri: "https://provider.example.com/.well-known/jwks.json"
        }
      }
    }
  end

  let(:jwt_string) do
    header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk.export[:kid]}
    JWT.encode(payload, private_key, "RS256", header)
  end

  describe ".parse" do
    it "parses entity statement without signature validation" do
      result = described_class.parse(jwt_string, validate_signature: false, validate_full: true)

      aggregate_failures do
        expect(result).to be_a(Hash)
        expect(result[:issuer]).to eq("https://provider.example.com")
        expect(result[:metadata]).to be_present
        expect(result[:metadata][:openid_provider]).to be_present
      end
    end

    it "parses entity statement with signature validation" do
      result = described_class.parse(jwt_string, validate_signature: true)

      aggregate_failures do
        expect(result).to be_a(Hash)
        expect(result[:issuer]).to eq("https://provider.example.com")
      end
    end

    it "raises error on invalid JWT format" do
      expect { described_class.parse("invalid.jwt") }.to raise_error(
        OmniauthOpenidFederation::ValidationError
      )
    end

    it "raises ValidationError on JSON::ParserError" do
      # Create a JWT with invalid JSON in payload
      header = Base64.urlsafe_encode64({alg: "RS256"}.to_json, padding: false)
      invalid_payload = Base64.urlsafe_encode64("invalid json", padding: false)
      invalid_jwt = "#{header}.#{invalid_payload}.signature"

      expect { described_class.parse(invalid_jwt) }.to raise_error(
        OmniauthOpenidFederation::ValidationError,
        /Failed to parse entity statement/
      )
    end

    it "raises ValidationError on ArgumentError (Base64 decode error)" do
      # Create a JWT with invalid Base64
      header = Base64.urlsafe_encode64({alg: "RS256"}.to_json, padding: false)
      invalid_payload = "invalid-base64!!!"
      invalid_jwt = "#{header}.#{invalid_payload}.signature"

      expect { described_class.parse(invalid_jwt) }.to raise_error(
        OmniauthOpenidFederation::ValidationError,
        /Failed to decode entity statement/
      )
    end

    context "with signature validation" do
      it "raises ValidationError when kid is not found in JWKS" do
        # Create JWT with kid that doesn't exist in entity_jwks
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: "nonexistent-kid"}
        JWT.encode(payload, private_key, "RS256", header)

        # Create payload with JWKS that doesn't contain the kid
        payload_with_different_jwks = payload.merge(
          jwks: {
            keys: [jwk.export] # JWKS with different kid
          }
        )
        jwt_with_different_jwks = JWT.encode(payload_with_different_jwks, private_key, "RS256", header)

        parser = described_class.new(jwt_with_different_jwks, validate_signature: true)
        expect {
          parser.parse
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /Entity statement kid 'nonexistent-kid' MUST exactly match a kid value for a key in the issuer's jwks/
        )
      end

      it "raises SignatureError when signature validation fails" do
        # Create JWT signed with different key
        other_key = OpenSSL::PKey::RSA.new(2048)
        JWT::JWK.new(other_key.public_key)
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk.export[:kid]}
        # Use wrong key for signature but correct kid in header
        jwt_with_wrong_signature = JWT.encode(payload, other_key, "RS256", header)

        parser = described_class.new(jwt_with_wrong_signature, validate_signature: true)
        allow(OmniauthOpenidFederation::Logger).to receive(:error)

        aggregate_failures do
          expect {
            parser.parse
          }.to raise_error(
            OmniauthOpenidFederation::SignatureError,
            /Entity statement signature validation failed/
          )
          expect(OmniauthOpenidFederation::Logger).to have_received(:error).with(/Entity statement signature validation failed/)
        end
      end
    end
  end
end

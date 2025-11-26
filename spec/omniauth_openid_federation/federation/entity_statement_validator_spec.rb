require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Federation::EntityStatementValidator do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:jwk) { JWT::JWK.new(public_key) }
  let(:jwk_export) { jwk.export }

  let(:issuer) { "https://provider.example.com" }
  let(:subject) { "https://provider.example.com" }

  def create_valid_jwt(iss:, sub:, additional_claims: {})
    payload = {
      iss: iss,
      sub: sub,
      iat: Time.now.to_i,
      exp: Time.now.to_i + 3600,
      jwks: {
        keys: [jwk_export]
      }
    }.merge(additional_claims)

    header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
    JWT.encode(payload, private_key, "RS256", header)
  end

  describe "#initialize" do
    it "initializes with required parameters" do
      jwt_string = create_valid_jwt(iss: issuer, sub: subject)
      validator = described_class.new(jwt_string: jwt_string)

      expect(validator.instance_variable_get(:@jwt_string)).to eq(jwt_string)
      expect(validator.instance_variable_get(:@issuer_entity_configuration)).to be_nil
      expect(validator.instance_variable_get(:@clock_skew_tolerance)).to eq(OmniauthOpenidFederation.config.clock_skew_tolerance)
    end

    it "accepts custom clock_skew_tolerance" do
      jwt_string = create_valid_jwt(iss: issuer, sub: subject)
      validator = described_class.new(jwt_string: jwt_string, clock_skew_tolerance: 120)

      expect(validator.instance_variable_get(:@clock_skew_tolerance)).to eq(120)
    end

    it "accepts issuer_entity_configuration" do
      jwt_string = create_valid_jwt(iss: issuer, sub: subject)
      issuer_config = {jwks: {keys: [jwk_export]}}
      validator = described_class.new(jwt_string: jwt_string, issuer_entity_configuration: issuer_config)

      expect(validator.instance_variable_get(:@issuer_entity_configuration)).to eq(issuer_config)
    end
  end

  describe "#validate!" do
    context "with valid Entity Configuration" do
      it "validates successfully" do
        jwt_string = create_valid_jwt(iss: issuer, sub: subject)
        validator = described_class.new(jwt_string: jwt_string)

        result = validator.validate!

        expect(result).to be_a(Hash)
        expect(result[:header]).to be_a(Hash)
        expect(result[:claims]).to be_a(Hash)
        expect(result[:is_entity_configuration]).to be true
        expect(result[:is_subordinate_statement]).to be false
      end
    end

    context "with valid Subordinate Statement" do
      it "validates successfully" do
        issuer_id = "https://ta.example.com"
        subject_id = "https://rp.example.com"
        jwt_string = create_valid_jwt(iss: issuer_id, sub: subject_id)

        # issuer_entity_configuration should be the SUBJECT's Entity Configuration
        # (the RP's config) which contains authority_hints pointing to the issuer (TA)
        # The code checks :claims or "claims", and then fetches "authority_hints" (string key)
        subject_config = {
          "claims" => {
            "authority_hints" => [issuer_id],
            "jwks" => {keys: [jwk_export]}
          }
        }

        validator = described_class.new(
          jwt_string: jwt_string,
          issuer_entity_configuration: subject_config
        )

        result = validator.validate!

        expect(result[:is_entity_configuration]).to be false
        expect(result[:is_subordinate_statement]).to be true
      end
    end

    context "JWT format validation" do
      it "raises ValidationError for invalid JWT format" do
        validator = described_class.new(jwt_string: "invalid.jwt")

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /Invalid JWT format/
        )
      end

      it "raises ValidationError for malformed JWT parts" do
        validator = described_class.new(jwt_string: "header.payload")

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /Invalid JWT format/
        )
      end

      it "raises ValidationError for invalid base64 encoding" do
        validator = described_class.new(jwt_string: "invalid.base64.signature")

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /Failed to decode entity statement JWT/
        )
      end
    end

    context "typ header validation" do
      it "raises ValidationError for missing typ header" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /Invalid entity statement type/
        )
      end

      it "raises ValidationError for wrong typ header" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "JWT", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /Invalid entity statement type/
        )
      end
    end

    context "alg header validation" do
      it "raises ValidationError for missing alg header" do
        # Manually construct JWT without alg header
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {typ: "entity-statement+jwt", kid: jwk_export[:kid]}

        # Manually encode to avoid JWT.encode adding alg automatically
        header_encoded = Base64.urlsafe_encode64(header.to_json).gsub(/=+$/, "")
        payload_encoded = Base64.urlsafe_encode64(payload.to_json).gsub(/=+$/, "")
        signature = "dummy_signature"
        jwt_string = "#{header_encoded}.#{payload_encoded}.#{signature}"

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /MUST have an alg/
        )
      end

      it "raises ValidationError for alg: none" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "none", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /alg header MUST NOT be 'none'/
        )
      end

      it "logs warning for unsupported algorithm" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "HS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect(OmniauthOpenidFederation::Logger).to receive(:warn).with(/Unsupported algorithm/)

        begin
          validator.validate!
        rescue OmniauthOpenidFederation::ValidationError
          # Expected to fail on other validations
        end
      end
    end

    context "sub claim validation" do
      it "raises ValidationError for missing sub claim" do
        payload = {iss: issuer, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /MUST have a sub/
        )
      end

      it "raises ValidationError for invalid sub claim format" do
        payload = {iss: issuer, sub: "not-a-uri", iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /sub claim MUST be a valid Entity Identifier/
        )
      end
    end

    context "iss claim validation" do
      it "raises ValidationError for missing iss claim" do
        payload = {sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /MUST have an iss/
        )
      end

      it "raises ValidationError for invalid iss claim format" do
        payload = {iss: "not-a-uri", sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /iss claim MUST be a valid Entity Identifier/
        )
      end
    end

    context "iat claim validation" do
      it "raises ValidationError for missing iat claim" do
        payload = {iss: issuer, sub: subject, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /MUST have an iat/
        )
      end

      it "raises ValidationError for iat too far in the future" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i + 200, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string, clock_skew_tolerance: 60)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /iat.*is too far in the future/
        )
      end

      it "allows iat within clock skew tolerance" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i + 30, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string, clock_skew_tolerance: 60)

        result = validator.validate!
        expect(result).to be_a(Hash)
      end
    end

    context "exp claim validation" do
      it "raises ValidationError for missing exp claim" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /MUST have an exp/
        )
      end

      it "raises ValidationError for expired statement" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i - 7200, exp: Time.now.to_i - 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string, clock_skew_tolerance: 60)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /has expired/
        )
      end

      it "allows exp within clock skew tolerance" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i - 3600, exp: Time.now.to_i - 30, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string, clock_skew_tolerance: 60)

        result = validator.validate!
        expect(result).to be_a(Hash)
      end
    end

    context "jwks claim validation" do
      it "raises ValidationError for missing jwks claim" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /MUST have a jwks/
        )
      end

      it "raises ValidationError for invalid jwks format" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: "not-an-object"}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /jwks claim MUST be a JSON object/
        )
      end

      it "raises ValidationError for jwks without keys array" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /jwks claim MUST contain a 'keys' array/
        )
      end

      it "raises ValidationError for duplicate kid values" do
        duplicate_jwk = jwk_export.dup
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export, duplicate_jwk]}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /jwks keys MUST have unique kid/
        )
      end
    end

    context "kid header validation" do
      it "raises ValidationError for missing kid header" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "entity-statement+jwt"}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /MUST have a kid/
        )
      end

      it "raises ValidationError for empty kid header" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: ""}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /MUST have a kid/
        )
      end

      it "raises ValidationError for non-string kid header" do
        # Manually construct JWT with non-string kid
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: 123}

        # Manually encode to preserve non-string kid
        header_encoded = Base64.urlsafe_encode64(header.to_json).gsub(/=+$/, "")
        payload_encoded = Base64.urlsafe_encode64(payload.to_json).gsub(/=+$/, "")
        signature = "dummy_signature"
        jwt_string = "#{header_encoded}.#{payload_encoded}.#{signature}"

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /kid header parameter MUST be a string/
        )
      end
    end

    context "kid matching validation" do
      it "raises ValidationError when kid doesn't match any key in JWKS" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: "nonexistent-kid"}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /kid.*MUST exactly match a kid value for a key in the issuer's jwks/
        )
      end

      it "validates kid matching for Entity Configuration" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        result = validator.validate!
        expect(result).to be_a(Hash)
      end
    end

    context "authority_hints validation" do
      it "validates authority_hints for Subordinate Statement" do
        issuer_id = "https://ta.example.com"
        subject_id = "https://rp.example.com"
        jwt_string = create_valid_jwt(iss: issuer_id, sub: subject_id)

        # issuer_entity_configuration should be the SUBJECT's Entity Configuration
        subject_config = {
          "claims" => {
            "authority_hints" => [issuer_id],
            "jwks" => {keys: [jwk_export]}
          }
        }

        validator = described_class.new(
          jwt_string: jwt_string,
          issuer_entity_configuration: subject_config
        )

        result = validator.validate!
        expect(result[:is_subordinate_statement]).to be true
      end

      it "raises ValidationError when issuer not in authority_hints" do
        issuer_id = "https://ta.example.com"
        subject_id = "https://rp.example.com"
        jwt_string = create_valid_jwt(iss: issuer_id, sub: subject_id)

        # issuer_entity_configuration should be the SUBJECT's Entity Configuration
        subject_config = {
          "claims" => {
            "authority_hints" => ["https://different-ta.example.com"],
            "jwks" => {keys: [jwk_export]}
          }
        }

        validator = described_class.new(
          jwt_string: jwt_string,
          issuer_entity_configuration: subject_config
        )

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /MUST be listed in the authority_hints array/
        )
      end

      it "logs warning when issuer configuration not provided" do
        issuer_id = "https://ta.example.com"
        subject_id = "https://rp.example.com"
        jwt_string = create_valid_jwt(iss: issuer_id, sub: subject_id)

        validator = described_class.new(jwt_string: jwt_string)

        # Multiple warnings may be logged (authority_hints, kid_matching)
        # We just verify that the authority_hints warning is logged
        allow(OmniauthOpenidFederation::Logger).to receive(:warn)

        begin
          validator.validate!
        rescue OmniauthOpenidFederation::ValidationError
          # May fail on other validations
        end

        # Verify the authority_hints warning was logged
        expect(OmniauthOpenidFederation::Logger).to have_received(:warn).with(/Cannot validate authority_hints/)
      end
    end

    context "crit claim validation" do
      it "validates crit claim when present" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}, crit: ["metadata_policy"]}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        result = validator.validate!
        expect(result).to be_a(Hash)
      end

      it "raises ValidationError for invalid crit format" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}, crit: "not-an-array"}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /crit claim MUST be an array of strings/
        )
      end

      it "logs warning for unknown crit claims" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}, crit: ["unknown_claim"]}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect(OmniauthOpenidFederation::Logger).to receive(:warn).with(/contains crit claim with unknown claims/)

        validator.validate!
      end
    end

    context "authority_hints syntax validation" do
      it "validates authority_hints syntax for Entity Configuration" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}, authority_hints: ["https://ta.example.com"]}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        result = validator.validate!
        expect(result).to be_a(Hash)
      end

      it "raises ValidationError for invalid authority_hints format" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}, authority_hints: "not-an-array"}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /authority_hints claim MUST be an array of strings/
        )
      end

      it "raises ValidationError for empty authority_hints" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}, authority_hints: []}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /authority_hints claim MUST NOT be an empty array/
        )
      end

      it "raises ValidationError for invalid authority_hints values" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}, authority_hints: ["not-a-uri"]}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /authority_hints claim MUST contain valid Entity Identifiers/
        )
      end
    end

    context "metadata syntax validation" do
      it "validates metadata syntax" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}, metadata: {openid_provider: {issuer: issuer}}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        result = validator.validate!
        expect(result).to be_a(Hash)
      end

      it "raises ValidationError for invalid metadata format" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}, metadata: "not-an-object"}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /metadata claim MUST be a JSON object/
        )
      end

      it "raises ValidationError for null metadata values" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}, metadata: {openid_provider: nil}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /metadata claim MUST NOT use null as metadata values/
        )
      end
    end

    context "statement type specific validations" do
      it "raises ValidationError when metadata_policy in Entity Configuration" do
        payload = {iss: issuer, sub: subject, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}, metadata_policy: {}}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /metadata_policy claim MUST only appear in Subordinate Statements/
        )
      end

      it "raises ValidationError when trust_marks in Subordinate Statement" do
        issuer_id = "https://ta.example.com"
        subject_id = "https://rp.example.com"
        payload = {iss: issuer_id, sub: subject_id, iat: Time.now.to_i, exp: Time.now.to_i + 3600, jwks: {keys: [jwk_export]}, trust_marks: []}
        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
        jwt_string = JWT.encode(payload, private_key, "RS256", header)

        validator = described_class.new(jwt_string: jwt_string)

        expect {
          validator.validate!
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /trust_marks claim MUST only appear in Entity Configurations/
        )
      end
    end
  end
end

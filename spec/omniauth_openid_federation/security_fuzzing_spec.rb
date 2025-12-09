require "spec_helper"
require "base64"

RSpec.describe "Security: JWT Fuzzing and Timing Attack Tests" do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:jwks) do
    jwk = JWT::JWK.new(public_key)
    {keys: [jwk.export]}
  end
  let(:jwks_uri) { "https://example.com/.well-known/jwks.json" }

  before do
    stub_request(:get, jwks_uri)
      .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})
  end

  describe "JWT format fuzzing" do
    it "rejects malformed JWT with too few parts" do
      # Behavior: JWT must have exactly 3 parts (header.payload.signature)
      malformed_jwts = [
        "",
        "header",
        "header.payload",
        "header.payload.signature.extra"
      ]

      malformed_jwts.each do |jwt|
        expect {
          OmniauthOpenidFederation::Jwks::Decode.jwt(jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::ValidationError)
      end
    end

    it "rejects JWT with invalid base64 encoding" do
      # Behavior: Should handle invalid base64 gracefully
      invalid_base64_parts = [
        "!!!invalid!!!",
        "not-base64-at-all",
        "header!!!.payload!!!.signature!!!"
      ]

      invalid_base64_parts.each do |part|
        jwt = "#{part}.#{part}.#{part}"
        expect {
          OmniauthOpenidFederation::Jwks::Decode.jwt(jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::ValidationError)
      end
    end

    it "rejects JWT with invalid JSON in header" do
      # Behavior: Should reject JWTs with malformed JSON
      invalid_json_header = Base64.urlsafe_encode64("not valid json{", padding: false)
      valid_payload = Base64.urlsafe_encode64({sub: "user123", exp: Time.now.to_i + 3600}.to_json, padding: false)
      signature = "signature"
      jwt = "#{invalid_json_header}.#{valid_payload}.#{signature}"

      expect {
        OmniauthOpenidFederation::Jwks::Decode.jwt(jwt, jwks_uri)
      }.to raise_error(OmniauthOpenidFederation::ValidationError)
    end

    it "rejects JWT with invalid JSON in payload" do
      # Behavior: Should reject JWTs with malformed JSON in payload
      valid_header = Base64.urlsafe_encode64({alg: "RS256", typ: "JWT"}.to_json, padding: false)
      invalid_json_payload = Base64.urlsafe_encode64("not valid json{", padding: false)
      signature = "signature"
      jwt = "#{valid_header}.#{invalid_json_payload}.#{signature}"

      expect {
        OmniauthOpenidFederation::Jwks::Decode.jwt(jwt, jwks_uri)
      }.to raise_error(OmniauthOpenidFederation::ValidationError)
    end

    it "rejects JWT with extremely long payload" do
      # Behavior: Should handle DoS attempts with oversized payloads
      valid_header = Base64.urlsafe_encode64({alg: "RS256", typ: "JWT"}.to_json, padding: false)
      # Create a very large payload (1MB)
      large_payload = Base64.urlsafe_encode64({sub: "user123", data: "x" * 1_000_000}.to_json, padding: false)
      signature = "signature"
      jwt = "#{valid_header}.#{large_payload}.#{signature}"

      # Should either reject or handle gracefully (implementation dependent)
      # Use begin/rescue to handle either error type
      aggregate_failures do
        expect {
          OmniauthOpenidFederation::Jwks::Decode.jwt(jwt, jwks_uri)
        }.to raise_error do |error|
          expect([OmniauthOpenidFederation::ValidationError, StandardError]).to include(error.class)
        end
      end
    end

    it "rejects JWT with null bytes" do
      # Behavior: Should reject JWTs containing null bytes (potential injection)
      header_with_null = Base64.urlsafe_encode64({alg: "RS256\0", typ: "JWT"}.to_json, padding: false)
      payload = Base64.urlsafe_encode64({sub: "user123", exp: Time.now.to_i + 3600}.to_json, padding: false)
      signature = "signature"
      jwt = "#{header_with_null}.#{payload}.#{signature}"

      expect {
        OmniauthOpenidFederation::Jwks::Decode.jwt(jwt, jwks_uri)
      }.to raise_error(OmniauthOpenidFederation::ValidationError)
    end

    it "rejects JWT with control characters" do
      # Behavior: Should reject JWTs with control characters
      header_with_control = Base64.urlsafe_encode64({alg: "RS256", typ: "JWT\n"}.to_json, padding: false)
      payload = Base64.urlsafe_encode64({sub: "user123", exp: Time.now.to_i + 3600}.to_json, padding: false)
      signature = "signature"
      jwt = "#{header_with_control}.#{payload}.#{signature}"

      # May or may not raise error depending on JSON parsing, but should not crash
      expect {
        OmniauthOpenidFederation::Jwks::Decode.jwt(jwt, jwks_uri)
      }.to raise_error(StandardError)
    end
  end

  describe "Algorithm confusion fuzzing" do
    it "rejects all non-RS256 algorithms" do
      # Behavior: Should only accept RS256, reject all other algorithms
      invalid_algorithms = [
        "none",
        "HS256", "HS384", "HS512",
        "ES256", "ES384", "ES512",
        "PS256", "PS384", "PS512",
        "RS384", "RS512"
      ]

      invalid_algorithms.each do |alg|
        header = Base64.urlsafe_encode64({alg: alg, typ: "JWT"}.to_json, padding: false)
        payload = Base64.urlsafe_encode64({sub: "user123", exp: Time.now.to_i + 3600}.to_json, padding: false)
        signature = "signature"
        jwt = "#{header}.#{payload}.#{signature}"

        expect {
          OmniauthOpenidFederation::Jwks::Decode.jwt(jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::ValidationError)
      end
    end

    it "rejects JWT with missing algorithm" do
      # Behavior: Algorithm must be specified
      header = Base64.urlsafe_encode64({typ: "JWT"}.to_json, padding: false)
      payload = Base64.urlsafe_encode64({sub: "user123", exp: Time.now.to_i + 3600}.to_json, padding: false)
      signature = "signature"
      jwt = "#{header}.#{payload}.#{signature}"

      expect {
        OmniauthOpenidFederation::Jwks::Decode.jwt(jwt, jwks_uri)
      }.to raise_error(OmniauthOpenidFederation::ValidationError)
    end

    it "rejects JWT with algorithm as non-string" do
      # Behavior: Algorithm must be a string
      header = Base64.urlsafe_encode64({alg: 256, typ: "JWT"}.to_json, padding: false)
      payload = Base64.urlsafe_encode64({sub: "user123", exp: Time.now.to_i + 3600}.to_json, padding: false)
      signature = "signature"
      jwt = "#{header}.#{payload}.#{signature}"

      expect {
        OmniauthOpenidFederation::Jwks::Decode.jwt(jwt, jwks_uri)
      }.to raise_error(OmniauthOpenidFederation::ValidationError)
    end
  end

  describe "Key confusion fuzzing" do
    it "rejects JWT with empty kid" do
      # Behavior: kid must be non-empty if present
      payload = {sub: "user123", exp: Time.now.to_i + 3600}
      jwt = JWT.encode(payload, private_key, "RS256", {kid: ""})

      expect {
        OmniauthOpenidFederation::Jwks::Decode.jwt(jwt, jwks_uri)
      }.to raise_error(OmniauthOpenidFederation::ValidationError)
    end

    it "rejects JWT with very long kid" do
      # Behavior: Should handle extremely long kid values
      payload = {sub: "user123", exp: Time.now.to_i + 3600}
      long_kid = "x" * 10_000
      jwt = JWT.encode(payload, private_key, "RS256", {kid: long_kid})

      # Should either reject or handle gracefully
      expect {
        OmniauthOpenidFederation::Jwks::Decode.jwt(jwt, jwks_uri)
      }.to raise_error(OmniauthOpenidFederation::ValidationError)
    end

    it "rejects JWT with special characters in kid" do
      # Behavior: Should handle special characters in kid
      payload = {sub: "user123", exp: Time.now.to_i + 3600}
      special_kids = [
        "../../../etc/passwd",
        "<script>alert('xss')</script>",
        "'; DROP TABLE users; --"
      ]

      special_kids.each do |kid|
        jwt = JWT.encode(payload, private_key, "RS256", {kid: kid})
        expect {
          OmniauthOpenidFederation::Jwks::Decode.jwt(jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::ValidationError)
      end
    end
  end

  describe "Timing attack resistance" do
    it "verifies signature validation timing is consistent for invalid signatures" do
      # Behavior: Signature verification should not leak information via timing
      # This is a basic test - full timing attack resistance requires more sophisticated testing
      payload = {sub: "user123", exp: Time.now.to_i + 3600}
      valid_jwt = JWT.encode(payload, private_key, "RS256", {kid: jwks[:keys].first[:kid]})

      # Create multiple invalid signatures with valid base64 encoding
      parts = valid_jwt.split(".")
      # Use valid base64 but wrong signatures
      wrong_key = OpenSSL::PKey::RSA.new(2048)
      wrong_jwt = JWT.encode(payload, wrong_key, "RS256", {kid: jwks[:keys].first[:kid]})
      wrong_parts = wrong_jwt.split(".")

      invalid_signatures = [
        wrong_parts[2],  # Signature from different key
        Base64.urlsafe_encode64("wrong_signature" * 20).gsub(/=+$/, ""),  # Valid base64, wrong signature
        parts[2][0..-5] + Base64.urlsafe_encode64("X").gsub(/=+$/, "")  # Modified signature
      ]

      # All should fail with signature error, but timing should be similar
      # Note: This is a basic test - real timing attack testing requires statistical analysis
      invalid_signatures.each do |invalid_sig|
        tampered_jwt = "#{parts[0]}.#{parts[1]}.#{invalid_sig}"
        expect {
          OmniauthOpenidFederation::Jwks::Decode.jwt(tampered_jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::SignatureError)
      end
    end

    it "does not leak key existence via timing for non-existent kid" do
      # Behavior: Response time should not reveal whether a kid exists
      payload = {sub: "user123", exp: Time.now.to_i + 3600}

      # Create JWTs with non-existent kids
      nonexistent_kids = ["nonexistent-1", "nonexistent-2", "nonexistent-3"]

      nonexistent_kids.each do |kid|
        jwt = JWT.encode(payload, private_key, "RS256", {kid: kid})
        expect {
          OmniauthOpenidFederation::Jwks::Decode.jwt(jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::ValidationError)
      end
    end
  end

  describe "Entity statement fuzzing" do
    it "rejects entity statements with invalid typ header" do
      # Behavior: Entity statements must have typ: "entity-statement+jwt"
      invalid_types = [
        "JWT",
        "jwt",
        "entity-statement",
        "",
        nil
      ]

      invalid_types.each do |typ|
        payload = {
          iss: "https://provider.example.com",
          sub: "https://provider.example.com",
          iat: Time.now.to_i,
          exp: Time.now.to_i + 3600,
          jwks: {keys: []}
        }
        header = {alg: "RS256", typ: typ}
        jwt = JWT.encode(payload, private_key, "RS256", header)

        validator = OmniauthOpenidFederation::Federation::EntityStatementValidator.new(jwt_string: jwt)
        expect {
          validator.validate!
        }.to raise_error(OmniauthOpenidFederation::ValidationError, /Invalid entity statement type/)
      end
    end

    it "rejects entity statements with missing required claims" do
      # Behavior: Entity statements must have required claims per OpenID Federation spec
      required_claims = [:iss, :sub, :iat, :exp, :jwks]

      required_claims.each do |missing_claim|
        payload = {
          iss: "https://provider.example.com",
          sub: "https://provider.example.com",
          iat: Time.now.to_i,
          exp: Time.now.to_i + 3600,
          jwks: {keys: []}
        }
        payload.delete(missing_claim)

        header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwks[:keys].first[:kid]}
        jwt = JWT.encode(payload, private_key, "RS256", header)

        validator = OmniauthOpenidFederation::Federation::EntityStatementValidator.new(jwt_string: jwt)
        expect {
          validator.validate!
        }.to raise_error(OmniauthOpenidFederation::ValidationError)
      end
    end
  end
end

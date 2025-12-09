require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Jwks::Decode do
  let(:jwks_uri) { "https://example.com/.well-known/jwks.json" }
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }

  describe ".jwt" do
    let(:jwks) do
      jwk = JWT::JWK.new(public_key)
      {
        keys: [jwk.export]
      }
    end

    before do
      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})
    end

    it "decodes valid JWT" do
      payload = {sub: "user123", exp: Time.now.to_i + 3600}
      encoded_jwt = JWT.encode(payload, private_key, "RS256", {kid: jwks[:keys].first[:kid]})

      result = described_class.jwt(encoded_jwt, jwks_uri)

      aggregate_failures do
        expect(result).to be_an(Array)
        expect(result.first["sub"]).to eq("user123")
      end
    end

    it "handles expired JWT" do
      payload = {sub: "user123", exp: Time.now.to_i - 3600}
      encoded_jwt = JWT.encode(payload, private_key, "RS256", {kid: jwks[:keys].first[:kid]})

      expect { described_class.jwt(encoded_jwt, jwks_uri) }.to raise_error(OmniauthOpenidFederation::ValidationError, /Signature has expired/)
    end

    context "when handling algorithm confusion attacks" do
      it "rejects JWT with alg: none" do
        # Behavior: Should reject unsigned JWTs (security requirement)
        header = Base64.urlsafe_encode64({alg: "none", typ: "JWT"}.to_json).gsub(/=+$/, "")
        payload = Base64.urlsafe_encode64({sub: "user123", exp: Time.now.to_i + 3600}.to_json).gsub(/=+$/, "")
        unsigned_jwt = "#{header}.#{payload}."

        expect {
          described_class.jwt(unsigned_jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::ValidationError)
      end

      it "rejects JWT with wrong algorithm (HS256 instead of RS256)" do
        # Behavior: Should only accept RS256, not other algorithms
        secret = "secret-key"
        payload = {sub: "user123", exp: Time.now.to_i + 3600}
        # Create JWT signed with HS256 (symmetric) instead of RS256 (asymmetric)
        hs256_jwt = JWT.encode(payload, secret, "HS256", {kid: jwks[:keys].first[:kid]})

        expect {
          described_class.jwt(hs256_jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::ValidationError)
      end

      it "rejects JWT with missing algorithm in header" do
        # Behavior: Should require algorithm to be specified
        header = Base64.urlsafe_encode64({typ: "JWT", kid: jwks[:keys].first[:kid]}.to_json).gsub(/=+$/, "")
        payload = Base64.urlsafe_encode64({sub: "user123", exp: Time.now.to_i + 3600}.to_json).gsub(/=+$/, "")
        signature = "invalid_signature"
        no_alg_jwt = "#{header}.#{payload}.#{signature}"

        expect {
          described_class.jwt(no_alg_jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::ValidationError)
      end
    end

    context "when verifying signature" do
      it "rejects JWT with tampered signature" do
        # Behavior: Should verify signature matches payload
        payload = {sub: "user123", exp: Time.now.to_i + 3600}
        valid_jwt = JWT.encode(payload, private_key, "RS256", {kid: jwks[:keys].first[:kid]})

        # Tamper with signature - use valid base64 but wrong signature
        parts = valid_jwt.split(".")
        # Create a valid base64 signature that doesn't match
        wrong_signature = Base64.urlsafe_encode64("wrong_signature_data" * 10).gsub(/=+$/, "")
        tampered_jwt = "#{parts[0]}.#{parts[1]}.#{wrong_signature}"

        expect {
          described_class.jwt(tampered_jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::SignatureError)
      end

      it "rejects JWT signed with wrong key" do
        # Behavior: Should only accept JWTs signed with keys from JWKS
        wrong_key = OpenSSL::PKey::RSA.new(2048)
        payload = {sub: "user123", exp: Time.now.to_i + 3600}
        wrong_key_jwt = JWT.encode(payload, wrong_key, "RS256", {kid: jwks[:keys].first[:kid]})

        expect {
          described_class.jwt(wrong_key_jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::SignatureError)
      end

      it "rejects JWT with tampered payload" do
        # Behavior: Signature should not match if payload is modified
        payload = {sub: "user123", exp: Time.now.to_i + 3600}
        valid_jwt = JWT.encode(payload, private_key, "RS256", {kid: jwks[:keys].first[:kid]})

        # Tamper with payload
        parts = valid_jwt.split(".")
        tampered_payload = Base64.urlsafe_encode64({sub: "admin", exp: Time.now.to_i + 3600}.to_json).gsub(/=+$/, "")
        tampered_jwt = "#{parts[0]}.#{tampered_payload}.#{parts[2]}"

        expect {
          described_class.jwt(tampered_jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::SignatureError)
      end
    end

    context "when handling key confusion attacks" do
      it "rejects JWT when kid doesn't match any key in JWKS" do
        # Behavior: Should only accept JWTs with kid that exists in JWKS
        payload = {sub: "user123", exp: Time.now.to_i + 3600}
        wrong_kid_jwt = JWT.encode(payload, private_key, "RS256", {kid: "nonexistent-kid"})

        expect {
          described_class.jwt(wrong_kid_jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::ValidationError, /Key with kid|Could not find public key/)
      end

      it "rejects JWT when kid in header doesn't match kid in JWKS key" do
        # Behavior: kid in header must exactly match kid in JWKS
        payload = {sub: "user123", exp: Time.now.to_i + 3600}
        # Use a kid that doesn't match any key in the JWKS
        mismatched_kid_jwt = JWT.encode(payload, private_key, "RS256", {kid: "wrong-kid-123"})

        expect {
          described_class.jwt(mismatched_kid_jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::ValidationError, /Key with kid|Could not find public key/)
      end
    end
  end

  describe ".json_jwt" do
    let(:jwks) do
      jwk = JWT::JWK.new(public_key)
      {
        keys: [jwk.export]
      }
    end

    before do
      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})
    end

    it "decodes JWT using jwt gem" do
      payload = {sub: "user123", exp: Time.now.to_i + 3600}
      header = {alg: "RS256", typ: "JWT", kid: jwks[:keys].first[:kid]}
      encoded_jwt = JWT.encode(payload, private_key, "RS256", header)

      result = described_class.jwt(encoded_jwt, jwks_uri)

      expect(result).to be_present
    end

    it "raises error when kid not found" do
      payload = {sub: "user123", exp: Time.now.to_i + 3600}
      header = {alg: "RS256", typ: "JWT", kid: "nonexistent-kid"}
      encoded_jwt = JWT.encode(payload, private_key, "RS256", header)

      expect { described_class.jwt(encoded_jwt, jwks_uri) }.to raise_error(OmniauthOpenidFederation::ValidationError, /Could not find public key for kid|Key with kid/)
    end

    context "when enforcing algorithm" do
      it "only accepts RS256 algorithm" do
        # Behavior: Should enforce RS256 algorithm, not accept others
        payload = {sub: "user123", exp: Time.now.to_i + 3600}

        # Try with ES256 (ECDSA) - should fail
        es256_key = OpenSSL::PKey::EC.generate("prime256v1")
        es256_jwt = JWT.encode(payload, es256_key, "ES256", {kid: jwks[:keys].first[:kid]})

        expect {
          described_class.jwt(es256_jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::ValidationError)
      end

      it "rejects JWT with alg: none" do
        # Behavior: Should reject unsigned JWTs
        header = Base64.urlsafe_encode64({alg: "none", typ: "JWT"}.to_json).gsub(/=+$/, "")
        payload = Base64.urlsafe_encode64({sub: "user123", exp: Time.now.to_i + 3600}.to_json).gsub(/=+$/, "")
        unsigned_jwt = "#{header}.#{payload}."

        expect {
          described_class.jwt(unsigned_jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::ValidationError)
      end
    end

    context "when verifying signature" do
      it "verifies signature before accepting JWT" do
        # Behavior: Signature must be valid for JWT to be accepted
        payload = {sub: "user123", exp: Time.now.to_i + 3600}
        valid_jwt = JWT.encode(payload, private_key, "RS256", {kid: jwks[:keys].first[:kid]})

        # Tamper with signature - use valid base64 but wrong signature
        parts = valid_jwt.split(".")
        # Create a valid base64 signature that doesn't match
        wrong_signature = Base64.urlsafe_encode64("wrong_signature_data" * 10).gsub(/=+$/, "")
        tampered_jwt = "#{parts[0]}.#{parts[1]}.#{wrong_signature}"

        expect {
          described_class.jwt(tampered_jwt, jwks_uri)
        }.to raise_error(OmniauthOpenidFederation::SignatureError)
      end
    end
  end

  describe ".jwt error handling" do
    let(:jwks) do
      jwk = JWT::JWK.new(public_key)
      {
        keys: [jwk.export]
      }
    end

    before do
      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})
    end

    context "when handling ArgumentError" do
      it "handles ArgumentError with Invalid in message (lines 89-91)" do
        # Test the specific path at lines 89-91 where ArgumentError with "Invalid" is caught
        allow(OmniauthOpenidFederation::Jwks::Fetch).to receive(:run).and_return(jwks)

        # Mock JWT.decode to raise ArgumentError with "Invalid" in message
        allow(JWT).to receive(:decode).and_raise(ArgumentError.new("Invalid JWT format: malformed token"))

        payload = {sub: "user123", exp: Time.now.to_i + 3600}
        encoded_jwt = JWT.encode(payload, private_key, "RS256", {kid: jwks[:keys].first[:kid]})

        expect {
          described_class.jwt(encoded_jwt, jwks_uri)
        }.to raise_error(
          OmniauthOpenidFederation::ValidationError,
          /JWT decode failed due to invalid format.*Invalid JWT format/
        )
      end

      it "re-raises ArgumentError without Invalid in message" do
        # Mock JWT.decode to raise ArgumentError without "Invalid" in message
        # We need to intercept the call inside the run method's block
        allow(OmniauthOpenidFederation::Jwks::Fetch).to receive(:run).and_return(jwks)

        # Stub JWT.decode to raise ArgumentError without "Invalid"
        original_decode = JWT.method(:decode)
        allow(JWT).to receive(:decode) do |*args|
          # Check if this is being called with our jwks
          if args.last.is_a?(Hash) && args.last[:jwks]
            raise ArgumentError.new("Unexpected argument error")
          else
            original_decode.call(*args)
          end
        end

        payload = {sub: "user123", exp: Time.now.to_i + 3600}
        encoded_jwt = JWT.encode(payload, private_key, "RS256", {kid: jwks[:keys].first[:kid]})

        expect {
          described_class.jwt(encoded_jwt, jwks_uri)
        }.to raise_error(ArgumentError, /Unexpected argument error/)
      end
    end

    context "when handling generic errors" do
      it "raises ValidationError when retried is true" do
        # Test the path where retried=true and an error occurs
        allow(OmniauthOpenidFederation::Jwks::Fetch).to receive(:run).and_return(jwks)
        allow(JWT).to receive(:decode).and_raise(StandardError.new("Unexpected error"))

        payload = {sub: "user123", exp: Time.now.to_i + 3600}
        encoded_jwt = JWT.encode(payload, private_key, "RS256", {kid: jwks[:keys].first[:kid]})

        expect {
          described_class.jwt(encoded_jwt, jwks_uri, retried: true)
        }.to raise_error(OmniauthOpenidFederation::ValidationError, /JWT decode failed after cache refresh/)
      end

      it "retries when retried is false" do
        # Test the retry path - first call fails, second succeeds
        # This tests the generic rescue block when retried=false (lines 103-106)
        allow(OmniauthOpenidFederation::Jwks::Fetch).to receive(:run).and_return(jwks)

        payload = {sub: "user123", exp: Time.now.to_i + 3600}
        encoded_jwt = JWT.encode(payload, private_key, "RS256", {kid: jwks[:keys].first[:kid]})

        allow(OmniauthOpenidFederation::Cache).to receive(:delete_jwks)

        # Mock JWT.decode to fail first time, succeed on retry
        decode_call_count = 0
        original_decode = JWT.method(:decode)
        allow(JWT).to receive(:decode) do |*args|
          decode_call_count += 1
          if decode_call_count == 1
            raise StandardError.new("Temporary error")
          else
            # On retry, call the original decode
            original_decode.call(*args)
          end
        end

        # Use run method directly to test the retry logic
        result = described_class.run(encoded_jwt, jwks_uri, retried: false) do |jwks_hash|
          JWT.decode(encoded_jwt, nil, true, {algorithms: ["RS256"], jwks: jwks_hash})
        end

        aggregate_failures do
          expect(result).to be_an(Array)
          expect(OmniauthOpenidFederation::Cache).to have_received(:delete_jwks).with(jwks_uri)
          expect(decode_call_count).to eq(2) # Should be called twice (fail + retry)
        end
      end
    end
  end

  describe ".run without block" do
    let(:jwks) do
      jwk = JWT::JWK.new(public_key)
      {
        keys: [jwk.export]
      }
    end

    before do
      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})
    end

    it "returns JWKS when no block is given" do
      # Test line 44: when block_given? is false, return jwks directly
      result = described_class.run("dummy_jwt", jwks_uri)

      # JWKS may have string keys after JSON serialization, so compare structure
      aggregate_failures do
        expect(result).to have_key(:keys).or(have_key("keys"))
        expect(result[:keys] || result["keys"]).to be_an(Array)
        expect((result[:keys] || result["keys"]).length).to eq(1)
      end
    end
  end
end

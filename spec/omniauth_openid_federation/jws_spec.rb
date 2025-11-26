require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Jws do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:client_id) { "test-client-id" }
  let(:redirect_uri) { "https://example.com/callback" }

  describe "#initialize" do
    it "sets default values" do
      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      )

      expect(jws.state).to be_present
      expect(jws.nonce).to be_nil
    end

    it "accepts custom state and nonce" do
      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        state: "custom-state",
        nonce: "custom-nonce",
        private_key: private_key
      )

      expect(jws.state).to eq("custom-state")
      expect(jws.nonce).to eq("custom-nonce")
    end
  end

  describe "#add_claim" do
    it "adds extra parameters" do
      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      )

      jws.add_claim(:custom_param, "value")
      signed = jws.sign

      expect(signed).to be_present
      expect(signed.split(".").length).to eq(3) # JWT has 3 parts
    end
  end

  describe "#sign" do
    it "signs the JWT with private key" do
      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        scope: "openid",
        audience: "https://provider.example.com",
        private_key: private_key
      )

      signed_jwt = jws.sign

      expect(signed_jwt).to be_present
      expect(signed_jwt.split(".").length).to eq(3)
    end

    it "raises error when private key is missing" do
      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri
      )

      expect { jws.sign }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Private key is required/)
    end

    it "includes all required claims in JWT payload" do
      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        scope: "openid profile",
        audience: "https://provider.example.com",
        state: "test-state",
        nonce: "test-nonce",
        private_key: private_key
      )

      signed_jwt = jws.sign

      # Decode and verify claims are present (behavior, not exact values)
      parts = signed_jwt.split(".")
      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))

      # Verify required claims are present (behavior testing)
      expect(payload).to have_key("iss")
      expect(payload).to have_key("aud")
      expect(payload).to have_key("client_id")
      expect(payload).to have_key("redirect_uri")
      expect(payload).to have_key("scope")
      expect(payload).to have_key("state")
      expect(payload).to have_key("nonce")
      expect(payload).to have_key("exp")
      expect(payload).to have_key("jti")

      # Verify claim values match input (behavior: JWT contains what was provided)
      expect(payload["iss"]).to eq(client_id)
      expect(payload["aud"]).to eq("https://provider.example.com")
      expect(payload["client_id"]).to eq(client_id)
      expect(payload["redirect_uri"]).to eq(redirect_uri)
      expect(payload["scope"]).to eq("openid profile")
      expect(payload["state"]).to eq("test-state")
      expect(payload["nonce"]).to eq("test-nonce")

      # Verify exp is in the future (behavior: token is not expired)
      expect(payload["exp"]).to be > Time.now.to_i

      # Verify jti is unique (behavior: prevents replay attacks)
      expect(payload["jti"]).to be_a(String)
      expect(payload["jti"]).not_to be_empty
    end

    it "generates unique JTI for each request" do
      jws1 = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      )

      jws2 = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      )

      jwt1 = jws1.sign
      jwt2 = jws2.sign

      parts1 = jwt1.split(".")
      parts2 = jwt2.split(".")
      payload1 = JSON.parse(Base64.urlsafe_decode64(parts1[1]))
      payload2 = JSON.parse(Base64.urlsafe_decode64(parts2[1]))

      # Behavior: JTI should be unique to prevent replay attacks
      expect(payload1["jti"]).not_to eq(payload2["jti"])
    end

    it "signs JWT with RS256 algorithm" do
      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      )

      signed_jwt = jws.sign
      parts = signed_jwt.split(".")
      header = JSON.parse(Base64.urlsafe_decode64(parts[0]))

      # Behavior: JWT must be signed with RS256 (security requirement)
      expect(header["alg"]).to eq("RS256")
    end

    it "verifies signature can be validated with corresponding public key" do
      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      )

      signed_jwt = jws.sign

      # Behavior: Signed JWT should be verifiable with public key
      public_key = private_key.public_key
      decoded = JWT.decode(signed_jwt, public_key, true, {algorithm: "RS256"})

      expect(decoded).to be_an(Array)
      expect(decoded.first).to be_a(Hash)
    end

    it "rejects tampered JWT signature" do
      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      )

      signed_jwt = jws.sign

      # Tamper with signature - use valid base64 but wrong signature
      parts = signed_jwt.split(".")
      # Create a valid base64 signature that doesn't match
      wrong_signature = Base64.urlsafe_encode64("wrong_signature_data" * 10).gsub(/=+$/, "")
      tampered_jwt = "#{parts[0]}.#{parts[1]}.#{wrong_signature}"

      # Behavior: Tampered signature should fail verification
      public_key = private_key.public_key
      expect {
        JWT.decode(tampered_jwt, public_key, true, {algorithm: "RS256"})
      }.to raise_error(JWT::VerificationError)
    end

    it "encrypts request object when provider metadata requires encryption" do
      provider_public_key = OpenSSL::PKey::RSA.new(2048)
      provider_jwk = JWT::JWK.new(provider_public_key).export
      provider_jwk[:use] = "enc"

      provider_metadata = {
        request_object_encryption_alg: "RSA-OAEP",
        request_object_encryption_enc: "A128CBC-HS256",
        jwks: {
          keys: [provider_jwk]
        }
      }

      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      )

      signed_jwt = jws.sign(provider_metadata: provider_metadata)

      # Encrypted JWT should be different from signed JWT
      expect(signed_jwt).not_to eq(jws.sign(provider_metadata: nil))
      expect(signed_jwt).to be_present
    end

    it "encrypts request object when always_encrypt is true" do
      provider_public_key = OpenSSL::PKey::RSA.new(2048)
      provider_jwk = JWT::JWK.new(provider_public_key).export
      provider_jwk[:use] = "enc"

      provider_metadata = {
        request_object_encryption_alg: "RSA-OAEP",
        request_object_encryption_enc: "A128CBC-HS256",
        jwks: {
          keys: [provider_jwk]
        }
      }

      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      )

      signed_jwt = jws.sign(provider_metadata: provider_metadata, always_encrypt: true)

      expect(signed_jwt).to be_present
      expect(signed_jwt).not_to eq(jws.sign(provider_metadata: provider_metadata, always_encrypt: false))
    end

    it "raises SignatureError when encryption algorithm is unsupported" do
      # Test unsupported algorithm through natural input - force encryption with always_encrypt
      # but with unsupported algorithm. The code should naturally fail when trying to encrypt.
      provider_public_key = OpenSSL::PKey::RSA.new(2048)
      provider_jwk = JWT::JWK.new(provider_public_key).export
      provider_jwk[:use] = "enc"

      provider_metadata = {
        request_object_encryption_alg: "unsupported-alg",
        request_object_encryption_enc: "A128CBC-HS256",
        jwks: {
          keys: [provider_jwk]
        }
      }

      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      )

      # Behavior: When encryption is forced with unsupported algorithm, sign should fail
      # Use always_encrypt: true to bypass the algorithm check in should_encrypt_request_object?
      # and force encryption to be attempted, which will then fail with unsupported algorithm
      # The sign method catches EncryptionError and re-raises as SignatureError
      expect(OmniauthOpenidFederation::Logger).to receive(:error).with(/Unsupported request object encryption algorithm/).at_least(:once)
      expect {
        jws.sign(provider_metadata: provider_metadata, always_encrypt: true)
      }.to raise_error(OmniauthOpenidFederation::SignatureError, /Unsupported request object encryption algorithm/)
    end

    it "raises SignatureError when provider JWKS is not available" do
      provider_metadata = {
        request_object_encryption_alg: "RSA-OAEP",
        request_object_encryption_enc: "A128CBC-HS256"
        # No jwks field
      }

      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      )

      expect(OmniauthOpenidFederation::Logger).to receive(:error).with(/Provider JWKS not available/).at_least(:once)
      expect {
        jws.sign(provider_metadata: provider_metadata)
      }.to raise_error(OmniauthOpenidFederation::SignatureError, /Provider JWKS not available/)
    end

    it "raises SignatureError when encryption fails" do
      provider_public_key = OpenSSL::PKey::RSA.new(2048)
      provider_jwk = JWT::JWK.new(provider_public_key).export
      provider_jwk[:use] = "enc"

      provider_metadata = {
        request_object_encryption_alg: "RSA-OAEP",
        request_object_encryption_enc: "A128CBC-HS256",
        jwks: {
          keys: [provider_jwk]
        }
      }

      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      )

      # Stub JWE.encrypt to raise an error
      allow(JWE).to receive(:encrypt).and_raise(StandardError.new("Encryption failed"))

      expect(OmniauthOpenidFederation::Logger).to receive(:error).with(/Failed to encrypt request object/).at_least(:once)
      expect {
        jws.sign(provider_metadata: provider_metadata)
      }.to raise_error(OmniauthOpenidFederation::SignatureError, /Failed to encrypt request object/)
    end
  end

  describe "#initialize with federation key source" do
    it "loads metadata from entity statement when key_source is :federation" do
      temp_file = Tempfile.new(["entity_statement", ".jwt"])
      entity_statement_jwt = "dummy.jwt.content"
      temp_file.write(entity_statement_jwt)
      temp_file.close

      metadata = {
        metadata: {
          federation_entity: {}
        },
        entity_jwks: {
          keys: [JWT::JWK.new(private_key.public_key).export]
        }
      }

      allow(OmniauthOpenidFederation::Federation::EntityStatementHelper).to receive(:parse_for_signed_jwks)
        .with(temp_file.path)
        .and_return(metadata)

      allow(OmniauthOpenidFederation::KeyExtractor).to receive(:extract_signing_key).and_return(private_key)

      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key,
        entity_statement_path: temp_file.path,
        key_source: :federation
      )

      # Behavior: Verify that signing works correctly with federation key source
      signed_jwt = jws.sign
      expect(signed_jwt).to be_present
      expect(signed_jwt.split(".").length).to eq(3)

      temp_file.unlink
    end
  end

  describe "#build_jwt with client entity statement" do
    it "includes client entity statement in trust_chain claim" do
      client_entity_statement = "client.entity.statement.jwt"

      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key,
        client_entity_statement: client_entity_statement
      )

      signed_jwt = jws.sign
      parts = signed_jwt.split(".")
      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))

      expect(payload).to have_key("trust_chain")
      expect(payload["trust_chain"]).to eq([client_entity_statement])
    end
  end

  describe "#encrypt_request_object error cases" do
    it "raises SignatureError when no encryption key is found" do
      # Behavior: When provider requires encryption but no encryption keys are available,
      # sign should fail. Test through natural input - provider metadata requires encryption
      # but jwks has no keys with use: "enc"
      provider_metadata = {
        request_object_encryption_alg: "RSA-OAEP",
        request_object_encryption_enc: "A128CBC-HS256",
        jwks: {
          keys: [] # No keys
        }
      }

      jws = described_class.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      )

      # Behavior: Sign should fail when encryption is required but no keys available
      expect(OmniauthOpenidFederation::Logger).to receive(:error).with(/No encryption key found in provider JWKS/).at_least(:once)
      expect {
        jws.sign(provider_metadata: provider_metadata)
      }.to raise_error(OmniauthOpenidFederation::SignatureError, /No encryption key found in provider JWKS/)
    end
  end
end

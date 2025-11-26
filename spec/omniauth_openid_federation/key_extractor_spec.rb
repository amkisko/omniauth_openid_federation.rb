require "spec_helper"
require "digest"
require "base64"

# Helper method for tests
def rsa_key_to_jwk_hash(key)
  n = Base64.urlsafe_encode64(key.n.to_s(2), padding: false)
  e = Base64.urlsafe_encode64(key.e.to_s(2), padding: false)

  jwk = {
    "kty" => "RSA",
    "n" => n,
    "e" => e
  }

  # Add private key components if available
  # For OpenSSL 3.0 compatibility, include CRT parameters (p, q, dp, dq, qi)
  if key.private?
    jwk["d"] = Base64.urlsafe_encode64(key.d.to_s(2), padding: false)
    if key.p && key.q
      jwk["p"] = Base64.urlsafe_encode64(key.p.to_s(2), padding: false)
      jwk["q"] = Base64.urlsafe_encode64(key.q.to_s(2), padding: false)
      # Calculate CRT parameters if available
      if key.dmp1 && key.dmq1 && key.iqmp
        jwk["dp"] = Base64.urlsafe_encode64(key.dmp1.to_s(2), padding: false)
        jwk["dq"] = Base64.urlsafe_encode64(key.dmq1.to_s(2), padding: false)
        jwk["qi"] = Base64.urlsafe_encode64(key.iqmp.to_s(2), padding: false)
      end
    end
  end

  # Generate kid (key ID) from public key
  public_key_pem = key.public_key.to_pem
  kid = Digest::SHA256.hexdigest(public_key_pem)[0, 16]
  jwk["kid"] = kid

  jwk
end

RSpec.describe OmniauthOpenidFederation::KeyExtractor do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:jwk_hash) do
    rsa_key_to_jwk_hash(private_key)
  end

  describe ".extract_signing_key" do
    context "with JWKS containing signing key" do
      it "extracts signing key from JWKS with use: 'sig'" do
        jwks = {
          "keys" => [
            jwk_hash.merge("use" => "sig", "kid" => "signing-key"),
            jwk_hash.merge("use" => "enc", "kid" => "encryption-key")
          ]
        }

        result = described_class.extract_signing_key(jwks: jwks)
        expect(result).to be_a(OpenSSL::PKey::RSA)
      end

      it "extracts first key when no use field specified (backward compatibility)" do
        jwks = {
          "keys" => [jwk_hash.merge("kid" => "key-1")]
        }

        result = described_class.extract_signing_key(jwks: jwks)
        expect(result).to be_a(OpenSSL::PKey::RSA)
      end

      it "prefers signing key over key without use field" do
        jwks = {
          "keys" => [
            jwk_hash.merge("kid" => "no-use-key"),
            jwk_hash.merge("use" => "sig", "kid" => "signing-key")
          ]
        }

        result = described_class.extract_signing_key(jwks: jwks)
        expect(result).to be_a(OpenSSL::PKey::RSA)
      end
    end

    context "with metadata containing JWKS" do
      it "extracts signing key from metadata" do
        metadata = {
          "jwks" => {
            "keys" => [jwk_hash.merge("use" => "sig")]
          }
        }

        result = described_class.extract_signing_key(metadata: metadata)
        expect(result).to be_a(OpenSSL::PKey::RSA)
      end
    end

    context "with fallback to private_key" do
      it "uses private_key when JWKS not available" do
        result = described_class.extract_signing_key(private_key: private_key)
        expect(result).to eq(private_key)
      end

      it "uses private_key when no signing key in JWKS" do
        jwks = {
          "keys" => [jwk_hash.merge("use" => "enc")]
        }

        result = described_class.extract_signing_key(jwks: jwks, private_key: private_key)
        expect(result).to eq(private_key)
      end

      it "normalizes string private key to OpenSSL::PKey::RSA" do
        pem_key = private_key.to_pem
        result = described_class.extract_signing_key(private_key: pem_key)
        expect(result).to be_a(OpenSSL::PKey::RSA)
      end
    end

    context "with empty or nil inputs" do
      it "returns nil when no keys available" do
        result = described_class.extract_signing_key
        expect(result).to be_nil
      end

      it "returns nil when JWKS is empty" do
        result = described_class.extract_signing_key(jwks: {"keys" => []})
        expect(result).to be_nil
      end
    end
  end

  describe ".extract_encryption_key" do
    context "with JWKS containing encryption key" do
      it "extracts encryption key from JWKS with use: 'enc'" do
        jwks = {
          "keys" => [
            jwk_hash.merge("use" => "sig", "kid" => "signing-key"),
            jwk_hash.merge("use" => "enc", "kid" => "encryption-key")
          ]
        }

        result = described_class.extract_encryption_key(jwks: jwks)
        expect(result).to be_a(OpenSSL::PKey::RSA)
      end

      it "extracts first key when no use field specified (backward compatibility)" do
        jwks = {
          "keys" => [jwk_hash.merge("kid" => "key-1")]
        }

        result = described_class.extract_encryption_key(jwks: jwks)
        expect(result).to be_a(OpenSSL::PKey::RSA)
      end

      it "prefers encryption key over key without use field" do
        jwks = {
          "keys" => [
            jwk_hash.merge("kid" => "no-use-key"),
            jwk_hash.merge("use" => "enc", "kid" => "encryption-key")
          ]
        }

        result = described_class.extract_encryption_key(jwks: jwks)
        expect(result).to be_a(OpenSSL::PKey::RSA)
      end
    end

    context "with metadata containing JWKS" do
      it "extracts encryption key from metadata" do
        metadata = {
          "jwks" => {
            "keys" => [jwk_hash.merge("use" => "enc")]
          }
        }

        result = described_class.extract_encryption_key(metadata: metadata)
        expect(result).to be_a(OpenSSL::PKey::RSA)
      end
    end

    context "with fallback to private_key" do
      it "uses private_key when JWKS not available" do
        result = described_class.extract_encryption_key(private_key: private_key)
        expect(result).to eq(private_key)
      end

      it "uses private_key when no encryption key in JWKS" do
        jwks = {
          "keys" => [jwk_hash.merge("use" => "sig")]
        }

        result = described_class.extract_encryption_key(jwks: jwks, private_key: private_key)
        expect(result).to eq(private_key)
      end

      it "normalizes string private key to OpenSSL::PKey::RSA" do
        pem_key = private_key.to_pem
        result = described_class.extract_encryption_key(private_key: pem_key)
        expect(result).to be_a(OpenSSL::PKey::RSA)
      end
    end

    context "with empty or nil inputs" do
      it "returns nil when no keys available" do
        result = described_class.extract_encryption_key
        expect(result).to be_nil
      end

      it "returns nil when JWKS is empty" do
        result = described_class.extract_encryption_key(jwks: {"keys" => []})
        expect(result).to be_nil
      end
    end
  end

  describe "separate signing and encryption keys" do
    it "extracts different keys for signing and encryption when both present" do
      signing_private_key = OpenSSL::PKey::RSA.new(2048)
      encryption_private_key = OpenSSL::PKey::RSA.new(2048)
      signing_jwk = rsa_key_to_jwk_hash(signing_private_key)
      encryption_jwk = rsa_key_to_jwk_hash(encryption_private_key)

      jwks = {
        "keys" => [
          signing_jwk.merge("use" => "sig", "kid" => "signing-key"),
          encryption_jwk.merge("use" => "enc", "kid" => "encryption-key")
        ]
      }

      signing_key = described_class.extract_signing_key(jwks: jwks)
      encryption_key = described_class.extract_encryption_key(jwks: jwks)

      expect(signing_key).to be_a(OpenSSL::PKey::RSA)
      expect(encryption_key).to be_a(OpenSSL::PKey::RSA)
      expect(signing_key.to_pem).not_to eq(encryption_key.to_pem)
    end

    it "uses same key for both when only one key present (backward compatibility)" do
      jwks = {
        "keys" => [jwk_hash.merge("kid" => "single-key")]
      }

      signing_key = described_class.extract_signing_key(jwks: jwks)
      encryption_key = described_class.extract_encryption_key(jwks: jwks)

      expect(signing_key).to be_a(OpenSSL::PKey::RSA)
      expect(encryption_key).to be_a(OpenSSL::PKey::RSA)
      expect(signing_key.to_pem).to eq(encryption_key.to_pem)
    end
  end

  describe ".extract_key" do
    it "extracts signing key when use is 'sig'" do
      jwks = {
        "keys" => [
          jwk_hash.merge("use" => "sig", "kid" => "signing-key"),
          jwk_hash.merge("use" => "enc", "kid" => "encryption-key")
        ]
      }

      result = described_class.extract_key(jwks: jwks, use: "sig")
      expect(result).to be_a(OpenSSL::PKey::RSA)
    end

    it "extracts encryption key when use is 'enc'" do
      jwks = {
        "keys" => [
          jwk_hash.merge("use" => "sig", "kid" => "signing-key"),
          jwk_hash.merge("use" => "enc", "kid" => "encryption-key")
        ]
      }

      result = described_class.extract_key(jwks: jwks, use: "enc")
      expect(result).to be_a(OpenSSL::PKey::RSA)
    end

    it "tries signing first, then encryption when use is not specified" do
      jwks = {
        "keys" => [
          jwk_hash.merge("use" => "sig", "kid" => "signing-key"),
          jwk_hash.merge("use" => "enc", "kid" => "encryption-key")
        ]
      }

      result = described_class.extract_key(jwks: jwks)
      expect(result).to be_a(OpenSSL::PKey::RSA)
    end

    it "falls back to encryption key when signing key not available" do
      jwks = {
        "keys" => [
          jwk_hash.merge("use" => "enc", "kid" => "encryption-key")
        ]
      }

      result = described_class.extract_key(jwks: jwks)
      expect(result).to be_a(OpenSSL::PKey::RSA)
    end
  end

  describe ".jwk_to_openssl_key" do
    it "converts public JWK to OpenSSL key" do
      jwk_data = rsa_key_to_jwk_hash(public_key)
      result = described_class.jwk_to_openssl_key(jwk_data)

      expect(result).to be_a(OpenSSL::PKey::RSA)
      expect(result.public?).to be true
    end

    it "converts private JWK to OpenSSL key" do
      jwk_data = rsa_key_to_jwk_hash(private_key)
      result = described_class.jwk_to_openssl_key(jwk_data)

      expect(result).to be_a(OpenSSL::PKey::RSA)
      expect(result.private?).to be true
    end

    it "handles symbol keys in JWK data" do
      jwk_data = rsa_key_to_jwk_hash(public_key)
      jwk_data_symbols = jwk_data.transform_keys(&:to_sym)
      result = described_class.jwk_to_openssl_key(jwk_data_symbols)

      expect(result).to be_a(OpenSSL::PKey::RSA)
    end

    context "when JWT::JWK is not available" do
      before do
        hide_const("JWT::JWK")
      end

      it "raises ArgumentError with helpful message" do
        jwk_data = {"kty" => "RSA", "n" => "n_value", "e" => "AQAB"}

        expect {
          described_class.jwk_to_openssl_key(jwk_data)
        }.to raise_error(ArgumentError, /JWT::JWK is required for OpenSSL 3.0 compatibility/)
      end
    end
  end
end

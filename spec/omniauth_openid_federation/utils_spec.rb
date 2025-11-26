require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Utils do
  describe ".to_indifferent_hash" do
    it "converts hash to HashWithIndifferentAccess when available" do
      hash = {"key" => "value", :symbol => "symbol_value"}
      result = described_class.to_indifferent_hash(hash)

      if defined?(ActiveSupport::HashWithIndifferentAccess)
        expect(result).to be_a(ActiveSupport::HashWithIndifferentAccess)
        expect(result["key"]).to eq("value")
        expect(result[:key]).to eq("value")
      else
        expect(result).to be_a(Hash)
      end
    end

    it "handles non-hash objects" do
      obj = Object.new
      result = described_class.to_indifferent_hash(obj)

      expect(result).to be_a(Hash)
    end

    context "when ActiveSupport is not available" do
      before do
        hide_const("ActiveSupport")
      end

      it "returns hash as-is" do
        hash = {"key" => "value"}
        result = described_class.to_indifferent_hash(hash)

        expect(result).to be_a(Hash)
        expect(result).to eq(hash)
      end
    end
  end

  describe ".sanitize_path" do
    it "returns filename only" do
      path = "/full/path/to/file.txt"
      result = described_class.sanitize_path(path)

      expect(result).to eq("file.txt")
    end

    it "returns [REDACTED] for nil" do
      expect(described_class.sanitize_path(nil)).to eq("[REDACTED]")
    end

    it "returns [REDACTED] for empty string" do
      expect(described_class.sanitize_path("")).to eq("[REDACTED]")
    end
  end

  describe ".sanitize_uri" do
    it "returns scheme and host only" do
      uri = "https://example.com/path/to/resource?query=value"
      result = described_class.sanitize_uri(uri)

      expect(result).to eq("https://example.com/[REDACTED]")
    end

    it "returns [REDACTED] for nil" do
      expect(described_class.sanitize_uri(nil)).to eq("[REDACTED]")
    end

    it "returns [REDACTED] for empty string" do
      expect(described_class.sanitize_uri("")).to eq("[REDACTED]")
    end

    it "returns [REDACTED] for invalid URI" do
      expect(described_class.sanitize_uri("not a uri")).to eq("[REDACTED]")
    end
  end

  describe ".validate_file_path!" do
    it "raises SecurityError for nil path" do
      expect { described_class.validate_file_path!(nil) }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /cannot be nil/)
    end

    it "raises SecurityError for empty path" do
      expect { described_class.validate_file_path!("") }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /cannot be empty/)
    end

    it "raises SecurityError for path traversal attempts" do
      expect { described_class.validate_file_path!("../../../etc/passwd") }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /Path traversal detected/)
    end

    it "raises SecurityError for tilde expansion" do
      expect { described_class.validate_file_path!("~/secret") }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /Path traversal detected/)
    end

    it "returns absolute path for valid path" do
      path = "config/file.txt"
      result = described_class.validate_file_path!(path)

      expect(result).to start_with("/")
      expect(File.absolute_path?(result)).to be true
    end

    context "with allowed_dirs" do
      it "allows path within allowed directory" do
        allowed_dir = File.expand_path("spec")
        path = File.join(allowed_dir, "file.txt")
        result = described_class.validate_file_path!(path, allowed_dirs: [allowed_dir])

        expect(result).to start_with(allowed_dir)
      end

      it "raises SecurityError for path outside allowed directory" do
        allowed_dir = File.expand_path("spec")
        path = File.expand_path("/etc/passwd")

        expect { described_class.validate_file_path!(path, allowed_dirs: [allowed_dir]) }
          .to raise_error(OmniauthOpenidFederation::SecurityError, /outside allowed directories/)
      end
    end
  end

  describe ".valid_jwt_format?" do
    it "returns true for valid JWT format" do
      jwt = "header.payload.signature"
      expect(described_class.valid_jwt_format?(jwt)).to be true
    end

    it "returns false for invalid JWT format" do
      expect(described_class.valid_jwt_format?("header.payload")).to be false
      expect(described_class.valid_jwt_format?("header")).to be false
      expect(described_class.valid_jwt_format?("header.payload.signature.extra")).to be false
    end

    it "returns false for empty parts" do
      expect(described_class.valid_jwt_format?("..")).to be false
      expect(described_class.valid_jwt_format?("header..signature")).to be false
    end

    it "returns false for non-string" do
      expect(described_class.valid_jwt_format?(nil)).to be false
      expect(described_class.valid_jwt_format?(123)).to be false
    end
  end

  describe ".extract_jwks_from_entity_statement" do
    let(:valid_jwt) do
      header = Base64.urlsafe_encode64({alg: "RS256", typ: "JWT"}.to_json, padding: false)
      payload = Base64.urlsafe_encode64({
        iss: "https://provider.example.com",
        jwks: {
          keys: [
            {kty: "RSA", kid: "key1", n: "n_value", e: "AQAB"}
          ]
        }
      }.to_json, padding: false)
      signature = "signature"
      "#{header}.#{payload}.#{signature}"
    end

    it "extracts JWKS from valid entity statement" do
      result = described_class.extract_jwks_from_entity_statement(valid_jwt)

      expect(result).to be_a(Hash)
      expect(result[:keys]).to be_an(Array)
      expect(result[:keys].length).to eq(1)
      # JSON.parse returns string keys, but we access with symbol
      key = result[:keys][0]
      expect(key["kid"] || key[:kid]).to eq("key1")
    end

    it "returns nil for invalid JWT format" do
      expect(described_class.extract_jwks_from_entity_statement("invalid")).to be_nil
    end

    it "returns nil for JWT with wrong number of parts" do
      expect(described_class.extract_jwks_from_entity_statement("header.payload")).to be_nil
    end

    it "returns nil when jwks is missing" do
      header = Base64.urlsafe_encode64({alg: "RS256"}.to_json, padding: false)
      payload = Base64.urlsafe_encode64({iss: "https://provider.example.com"}.to_json, padding: false)
      jwt = "#{header}.#{payload}.signature"

      expect(described_class.extract_jwks_from_entity_statement(jwt)).to be_nil
    end

    it "returns nil when jwks is empty" do
      header = Base64.urlsafe_encode64({alg: "RS256"}.to_json, padding: false)
      payload = Base64.urlsafe_encode64({iss: "https://provider.example.com", jwks: {}}.to_json, padding: false)
      jwt = "#{header}.#{payload}.signature"

      expect(described_class.extract_jwks_from_entity_statement(jwt)).to be_nil
    end

    it "returns nil when keys array is empty" do
      header = Base64.urlsafe_encode64({alg: "RS256"}.to_json, padding: false)
      payload = Base64.urlsafe_encode64({
        iss: "https://provider.example.com",
        jwks: {keys: []}
      }.to_json, padding: false)
      jwt = "#{header}.#{payload}.signature"

      expect(described_class.extract_jwks_from_entity_statement(jwt)).to be_nil
    end

    it "handles symbol keys in payload" do
      header = Base64.urlsafe_encode64({alg: "RS256"}.to_json, padding: false)
      payload_hash = {
        iss: "https://provider.example.com",
        jwks: {
          keys: [{kty: "RSA", kid: "key1"}]
        }
      }
      payload = Base64.urlsafe_encode64(payload_hash.to_json, padding: false)
      jwt = "#{header}.#{payload}.signature"

      result = described_class.extract_jwks_from_entity_statement(jwt)
      expect(result).not_to be_nil
      expect(result[:keys].length).to eq(1)
    end

    it "handles JSON parse errors gracefully" do
      header = Base64.urlsafe_encode64({alg: "RS256"}.to_json, padding: false)
      invalid_payload = "not-valid-json"
      jwt = "#{header}.#{invalid_payload}.signature"

      expect(OmniauthOpenidFederation::Logger).to receive(:warn).with(/Failed to extract JWKS/)
      expect(described_class.extract_jwks_from_entity_statement(jwt)).to be_nil
    end

    it "handles Base64 decode errors gracefully" do
      header = Base64.urlsafe_encode64({alg: "RS256"}.to_json, padding: false)
      invalid_payload = "invalid-base64!!!"
      jwt = "#{header}.#{invalid_payload}.signature"

      expect(OmniauthOpenidFederation::Logger).to receive(:warn).with(/Failed to extract JWKS/)
      expect(described_class.extract_jwks_from_entity_statement(jwt)).to be_nil
    end
  end

  describe ".build_endpoint_url" do
    it "returns full URL when endpoint path is relative" do
      issuer = "https://provider.example.com"
      endpoint = "/oauth2/authorize"
      result = described_class.build_endpoint_url(issuer, endpoint)

      expect(result).to eq("https://provider.example.com/oauth2/authorize")
    end

    it "handles endpoint path without leading slash" do
      issuer = "https://provider.example.com"
      endpoint = "oauth2/authorize"
      result = described_class.build_endpoint_url(issuer, endpoint)

      expect(result).to eq("https://provider.example.com/oauth2/authorize")
    end

    it "returns endpoint as-is when it's already a full URL" do
      issuer = "https://provider.example.com"
      endpoint = "https://other.example.com/oauth2/authorize"
      result = described_class.build_endpoint_url(issuer, endpoint)

      expect(result).to eq("https://other.example.com/oauth2/authorize")
    end

    it "handles issuer with trailing slash" do
      issuer = "https://provider.example.com/"
      endpoint = "/oauth2/authorize"
      result = described_class.build_endpoint_url(issuer, endpoint)

      expect(result).to eq("https://provider.example.com/oauth2/authorize")
    end

    it "handles http:// URLs" do
      issuer = "http://provider.example.com"
      endpoint = "/oauth2/authorize"
      result = described_class.build_endpoint_url(issuer, endpoint)

      expect(result).to eq("http://provider.example.com/oauth2/authorize")
    end
  end

  describe ".build_entity_statement_url" do
    it "builds URL with default endpoint" do
      issuer = "https://provider.example.com"
      result = described_class.build_entity_statement_url(issuer)

      expect(result).to eq("https://provider.example.com/.well-known/openid-federation")
    end

    it "builds URL with custom endpoint" do
      issuer = "https://provider.example.com"
      endpoint = "/custom/federation"
      result = described_class.build_entity_statement_url(issuer, entity_statement_endpoint: endpoint)

      expect(result).to eq("https://provider.example.com/custom/federation")
    end
  end

  describe ".rsa_key_to_jwk" do
    let(:private_key) { OpenSSL::PKey::RSA.new(2048) }

    it "converts RSA key to JWK with default use (sig)" do
      jwk = described_class.rsa_key_to_jwk(private_key)

      expect(jwk).to be_a(Hash)
      expect(jwk[:kty]).to eq("RSA")
      expect(jwk[:kid]).to be_a(String)
      expect(jwk[:n]).to be_a(String)
      expect(jwk[:e]).to be_a(String)
      expect(jwk[:use]).to eq("sig")
    end

    it "converts RSA key to JWK with use: enc" do
      jwk = described_class.rsa_key_to_jwk(private_key, use: "enc")

      expect(jwk[:use]).to eq("enc")
    end

    it "converts RSA key to JWK without use field when nil" do
      jwk = described_class.rsa_key_to_jwk(private_key, use: nil)

      expect(jwk).not_to have_key(:use)
    end

    it "generates consistent kid for same key" do
      jwk1 = described_class.rsa_key_to_jwk(private_key)
      jwk2 = described_class.rsa_key_to_jwk(private_key)

      expect(jwk1[:kid]).to eq(jwk2[:kid])
    end

    it "generates different kid for different keys" do
      key2 = OpenSSL::PKey::RSA.new(2048)
      jwk1 = described_class.rsa_key_to_jwk(private_key)
      jwk2 = described_class.rsa_key_to_jwk(key2)

      expect(jwk1[:kid]).not_to eq(jwk2[:kid])
    end

    it "works with public key" do
      public_key = private_key.public_key
      jwk = described_class.rsa_key_to_jwk(public_key)

      expect(jwk).to be_a(Hash)
      expect(jwk[:kty]).to eq("RSA")
    end
  end
end

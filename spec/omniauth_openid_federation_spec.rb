RSpec.describe OmniauthOpenidFederation do
  it "has a version number" do
    expect(OmniauthOpenidFederation::VERSION).not_to be nil
  end

  describe ".configure" do
    it "yields configuration instance" do
      expect { |b| described_class.configure(&b) }.to yield_with_args(be_a(OmniauthOpenidFederation::Configuration))
    end

    it "returns configuration instance" do
      result = described_class.configure { |c| c.verify_ssl = false }
      expect(result).to be_a(OmniauthOpenidFederation::Configuration)
    end

    it "works without block" do
      result = described_class.configure
      expect(result).to be_a(OmniauthOpenidFederation::Configuration)
    end
  end

  describe ".config" do
    it "returns configuration instance" do
      expect(described_class.config).to be_a(OmniauthOpenidFederation::Configuration)
    end
  end

  describe ".rotate_jwks" do
    let(:jwks_uri) { "https://example.com/.well-known/jwks.json" }
    let(:jwks_response) { {keys: [{kty: "RSA", kid: "1", use: "sig", n: "test", e: "AQAB"}]} }

    context "without entity statement" do
      it "fetches standard JWKS" do
        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: jwks_response.to_json, headers: {"Content-Type" => "application/json"})

        result = described_class.rotate_jwks(jwks_uri)

        expect(result).to be_a(Hash)
        expect(result["keys"]).to be_present
      end
    end

    context "with entity statement" do
      let(:entity_statement_path) { "spec/fixtures/entity_statement.jwt" }

      before do
        if defined?(Rails)
          FileUtils.mkdir_p("spec/fixtures")
          # Create minimal entity statement
          header = Base64.urlsafe_encode64({alg: "RS256"}.to_json, padding: false)
          payload = Base64.urlsafe_encode64({
            iss: "https://provider.example.com",
            sub: "https://provider.example.com",
            jwks: {keys: []},
            metadata: {
              openid_provider: {
                signed_jwks_uri: "https://provider.example.com/.well-known/signed-jwks.json"
              }
            }
          }.to_json, padding: false)
          File.write(entity_statement_path, "#{header}.#{payload}.signature")
        end
      end

      after do
        File.delete(entity_statement_path) if File.exist?(entity_statement_path)
      end

      it "raises SecurityError for path traversal" do
        expect { described_class.rotate_jwks(jwks_uri, entity_statement_path: "../../../etc/passwd") }
          .to raise_error(OmniauthOpenidFederation::SecurityError)
      end

      it "raises ConfigurationError when file not found" do
        if defined?(Rails)
          expect(OmniauthOpenidFederation::Logger).to receive(:warn).with(/Entity statement file not found/)
          expect { described_class.rotate_jwks(jwks_uri, entity_statement_path: "nonexistent.jwt") }
            .to raise_error(OmniauthOpenidFederation::ConfigurationError, /not found/)
        end
      end

      it "uses signed JWKS when available in entity statement" do
        if defined?(Rails)
          # Create entity statement with signed_jwks_uri
          private_key = OpenSSL::PKey::RSA.new(2048)
          public_key = private_key.public_key
          jwk = JWT::JWK.new(public_key)
          jwk_export = jwk.export

          entity_statement_payload = {
            iss: "https://provider.example.com",
            sub: "https://provider.example.com",
            jwks: {keys: [jwk_export]},
            metadata: {
              openid_provider: {
                signed_jwks_uri: "https://provider.example.com/.well-known/signed-jwks.json"
              }
            }
          }
          entity_statement_header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
          entity_statement_jwt = JWT.encode(entity_statement_payload, private_key, "RS256", entity_statement_header)
          File.write(entity_statement_path, entity_statement_jwt)

          # Stub HTTP call for signed JWKS (architectural boundary)
          signed_jwks_payload = {keys: [{kty: "RSA", kid: "key1"}]}
          signed_jwks_jwt = JWT.encode(signed_jwks_payload, private_key, "RS256", {alg: "RS256", typ: "JWT", kid: jwk_export[:kid]})
          stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
            .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})

          result = described_class.rotate_jwks(jwks_uri, entity_statement_path: entity_statement_path)
          expect(result).to be_a(Hash)
          expect(result["keys"]).to be_present
        end
      end

      it "falls back to standard JWKS when signed JWKS fails" do
        if defined?(Rails)
          # Create entity statement with signed_jwks_uri
          private_key = OpenSSL::PKey::RSA.new(2048)
          public_key = private_key.public_key
          jwk = JWT::JWK.new(public_key)
          jwk_export = jwk.export

          entity_statement_payload = {
            iss: "https://provider.example.com",
            sub: "https://provider.example.com",
            jwks: {keys: [jwk_export]},
            metadata: {
              openid_provider: {
                signed_jwks_uri: "https://provider.example.com/.well-known/signed-jwks.json"
              }
            }
          }
          entity_statement_header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
          entity_statement_jwt = JWT.encode(entity_statement_payload, private_key, "RS256", entity_statement_header)
          File.write(entity_statement_path, entity_statement_jwt)

          # Stub HTTP call for signed JWKS to fail (architectural boundary)
          stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
            .to_return(status: 500)

          expect(OmniauthOpenidFederation::Logger).to receive(:warn).with(/Failed to use signed JWKS/)

          stub_request(:get, jwks_uri)
            .to_return(status: 200, body: jwks_response.to_json, headers: {"Content-Type" => "application/json"})

          result = described_class.rotate_jwks(jwks_uri, entity_statement_path: entity_statement_path)
          expect(result).to be_a(Hash)
          expect(result["keys"]).to be_present
        end
      end

      it "re-raises SecurityError from path validation" do
        if defined?(Rails)
          # Behavior: SecurityError should be re-raised when path validation fails
          # Test through natural input - use path traversal attempt
          expect {
            described_class.rotate_jwks(jwks_uri, entity_statement_path: "../../../etc/passwd")
          }.to raise_error(OmniauthOpenidFederation::SecurityError)
        end
      end

      it "uses entity statement keys for standard JWKS fallback" do
        if defined?(Rails)
          # Create entity statement without signed_jwks_uri
          header = Base64.urlsafe_encode64({alg: "RS256"}.to_json, padding: false)
          payload = Base64.urlsafe_encode64({
            iss: "https://provider.example.com",
            jwks: {keys: [{kty: "RSA", kid: "key1"}]}
          }.to_json, padding: false)
          File.write(entity_statement_path, "#{header}.#{payload}.signature")

          stub_request(:get, jwks_uri)
            .to_return(status: 200, body: jwks_response.to_json, headers: {"Content-Type" => "application/json"})

          result = described_class.rotate_jwks(jwks_uri, entity_statement_path: entity_statement_path)
          expect(result).to be_a(Hash)
        end
      end
    end

    context "when Rails is not available" do
      before do
        hide_const("Rails")
      end

      it "uses config.root_path for entity statement" do
        config = OmniauthOpenidFederation::Configuration.config
        config.root_path = Dir.mktmpdir

        # Create entity statement in allowed directory
        allowed_dir = File.join(config.root_path, "config")
        FileUtils.mkdir_p(allowed_dir) unless File.directory?(allowed_dir)
        file_path = File.join(allowed_dir, "entity_statement.jwt")

        header = Base64.urlsafe_encode64({alg: "RS256"}.to_json, padding: false)
        payload = Base64.urlsafe_encode64({
          iss: "https://provider.example.com",
          jwks: {keys: []}
        }.to_json, padding: false)
        File.write(file_path, "#{header}.#{payload}.signature")

        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: jwks_response.to_json, headers: {"Content-Type" => "application/json"})

        result = described_class.rotate_jwks(jwks_uri, entity_statement_path: file_path)
        expect(result).to be_a(Hash)

        FileUtils.rm_rf(config.root_path) if File.directory?(config.root_path)
        config.root_path = nil
      end
    end
  end
end

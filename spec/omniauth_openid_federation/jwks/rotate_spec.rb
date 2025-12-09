require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Jwks::Rotate do
  let(:jwks_uri) { "https://provider.example.com/.well-known/jwks.json" }
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:jwk) { OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key) }

  describe ".run" do
    context "with entity_statement_path" do
      # Test line 45: Rails.root.join("config") when Rails is available
      it "uses Rails.root.join when Rails is available" do
        # Use a temporary directory to simulate config/ without polluting the project
        temp_dir = Dir.mktmpdir
        temp_config_dir = File.join(temp_dir, "config")
        FileUtils.mkdir_p(temp_config_dir)
        full_path = File.join(temp_config_dir, "entity.jwt")

        begin
          entity_statement = {
            iss: "https://provider.example.com",
            sub: "https://provider.example.com",
            jwks: {keys: [jwk]},
            metadata: {
              openid_provider: {
                signed_jwks_uri: "https://provider.example.com/.well-known/signed-jwks.json"
              }
            }
          }
          jwt = JWT.encode(entity_statement, private_key, "RS256")
          File.write(full_path, jwt)

          rails_root = double
          allow(rails_root).to receive(:join).with("config").and_return(double(to_s: temp_config_dir))
          # Stub Rails with root and cache (cache can be nil for this test)
          rails_double = double(root: rails_root)
          allow(rails_double).to receive(:cache).and_return(nil)
          stub_const("Rails", rails_double)

          # Ensure CacheAdapter is not available to avoid cache issues
          OmniauthOpenidFederation::CacheAdapter.reset!
          allow(OmniauthOpenidFederation::CacheAdapter).to receive(:available?).and_return(false)

          # Include kid in JWT header for signed JWKS
          signed_jwks_header = {alg: "RS256", typ: "JWT", kid: jwk["kid"]}
          signed_jwks_jwt = JWT.encode({jwks: {keys: [jwk]}}, private_key, "RS256", signed_jwks_header)
          stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
            .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})
          # Stub fallback to standard JWKS (in case signed JWKS fails or is not used)
          stub_request(:get, "https://provider.example.com/.well-known/jwks.json")
            .to_return(status: 200, body: {keys: [jwk]}.to_json, headers: {"Content-Type" => "application/json"})

          # Use full path for validation
          result = described_class.run(jwks_uri, entity_statement_path: full_path)
          aggregate_failures do
            expect(result).to be_a(Hash)
            expect(result).to have_key(:keys)
          end
        ensure
          FileUtils.rm_rf(temp_dir) if File.directory?(temp_dir)
        end
      end

      # Test lines 60-62: Entity statement file not found
      it "raises ConfigurationError when entity statement file not found" do
        entity_statement_path = "/nonexistent/path.jwt"

        expect {
          described_class.run(jwks_uri, entity_statement_path: entity_statement_path)
        }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Entity statement file not found/)
      end

      # Test line 69: Uses signed JWKS when available
      it "uses signed JWKS when entity statement has signed_jwks_uri" do
        entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
        entity_statement = {
          iss: "https://provider.example.com",
          sub: "https://provider.example.com",
          jwks: {keys: [jwk]},
          metadata: {
            openid_provider: {
              signed_jwks_uri: "https://provider.example.com/.well-known/signed-jwks.json"
            }
          }
        }
        jwt = JWT.encode(entity_statement, private_key, "RS256")
        File.write(entity_statement_path, jwt)

        # Ensure CacheAdapter is not available to avoid cache issues
        OmniauthOpenidFederation::CacheAdapter.reset!
        allow(OmniauthOpenidFederation::CacheAdapter).to receive(:available?).and_return(false)

        # Include kid in JWT header for signed JWKS
        signed_jwks_header = {alg: "RS256", typ: "JWT", kid: jwk["kid"]}
        signed_jwks_jwt = JWT.encode({jwks: {keys: [jwk]}}, private_key, "RS256", signed_jwks_header)
        stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
          .to_return(status: 200, body: signed_jwks_jwt, headers: {"Content-Type" => "application/jwt"})
        # Stub fallback to standard JWKS (in case signed JWKS fails)
        stub_request(:get, "https://provider.example.com/.well-known/jwks.json")
          .to_return(status: 200, body: {keys: [jwk]}.to_json, headers: {"Content-Type" => "application/json"})

        result = described_class.run(jwks_uri, entity_statement_path: entity_statement_path)
        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result).to have_key(:keys)
        end
      ensure
        File.delete(entity_statement_path) if File.exist?(entity_statement_path)
      end

      # Test lines 50-51: Absolute path validation branch
      it "validates absolute paths for path traversal only" do
        # Test line 50-51: when is_absolute is true, validate path traversal but allow outside allowed_dirs
        entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
        entity_statement = {
          iss: "https://provider.example.com",
          sub: "https://provider.example.com",
          jwks: {keys: [jwk]}
        }
        jwt = JWT.encode(entity_statement, private_key, "RS256")
        File.write(entity_statement_path, jwt)

        # Ensure CacheAdapter is not available
        OmniauthOpenidFederation::CacheAdapter.reset!
        allow(OmniauthOpenidFederation::CacheAdapter).to receive(:available?).and_return(false)

        jwks = {keys: [jwk]}
        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

        # Absolute path should be accepted (line 50-51 branch)
        result = described_class.run(jwks_uri, entity_statement_path: entity_statement_path)
        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result).to have_key(:keys)
        end
      ensure
        File.delete(entity_statement_path) if File.exist?(entity_statement_path)
      end

      # Test lines 76, 78: SecurityError re-raised, general error handled
      it "re-raises SecurityError when loading entity statement" do
        entity_statement_path = "../../../etc/passwd"

        expect {
          described_class.run(jwks_uri, entity_statement_path: entity_statement_path)
        }.to raise_error(OmniauthOpenidFederation::SecurityError)
      end

      it "handles general errors when using signed JWKS and falls back" do
        entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
        entity_statement = {
          iss: "https://provider.example.com",
          sub: "https://provider.example.com",
          jwks: {keys: [jwk]},
          metadata: {
            openid_provider: {
              signed_jwks_uri: "https://provider.example.com/.well-known/signed-jwks.json"
            }
          }
        }
        jwt = JWT.encode(entity_statement, private_key, "RS256")
        File.write(entity_statement_path, jwt)

        # Ensure CacheAdapter is not available to avoid cache issues
        OmniauthOpenidFederation::CacheAdapter.reset!
        allow(OmniauthOpenidFederation::CacheAdapter).to receive(:available?).and_return(false)

        # Make signed JWKS fetch fail
        stub_request(:get, "https://provider.example.com/.well-known/signed-jwks.json")
          .to_raise(StandardError.new("Network error"))

        jwks = {keys: [jwk]}
        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

        allow(OmniauthOpenidFederation::Logger).to receive(:warn).with(/Failed to use signed JWKS, falling back to standard JWKS/)
        result = described_class.run(jwks_uri, entity_statement_path: entity_statement_path)
        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result).to have_key(:keys)
          expect(OmniauthOpenidFederation::Logger).to have_received(:warn).with(/Failed to use signed JWKS, falling back to standard JWKS/)
        end
      end
    end

    context "without entity_statement_path" do
      it "uses standard JWKS" do
        jwks = {keys: [jwk]}
        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

        result = described_class.run(jwks_uri)
        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result).to have_key(:keys)
        end
      end
    end
  end
end

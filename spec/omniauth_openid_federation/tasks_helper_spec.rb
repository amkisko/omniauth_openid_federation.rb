require "spec_helper"

RSpec.describe OmniauthOpenidFederation::TasksHelper do
  describe ".resolve_path" do
    context "with absolute path" do
      it "returns the path as-is" do
        expect(described_class.resolve_path("/absolute/path")).to eq("/absolute/path")
      end
    end

    context "with relative path" do
      context "when Rails.root is available" do
        before do
          rails_root = double("Rails.root")
          allow(rails_root).to receive(:join).with("relative/path").and_return(double(to_s: "/rails/root/relative/path"))
          stub_const("Rails", double(root: rails_root))
        end

        it "uses Rails.root.join" do
          expect(described_class.resolve_path("relative/path")).to eq("/rails/root/relative/path")
        end
      end

      context "when config.root_path is set" do
        before do
          hide_const("Rails")
          config = OmniauthOpenidFederation::Configuration.config
          config.root_path = "/config/root"
        end

        after do
          config = OmniauthOpenidFederation::Configuration.config
          config.root_path = nil
        end

        it "uses config.root_path" do
          expect(described_class.resolve_path("relative/path")).to eq("/config/root/relative/path")
        end
      end

      context "when neither Rails nor config.root_path is available" do
        before do
          hide_const("Rails")
          config = OmniauthOpenidFederation::Configuration.config
          config.root_path = nil
        end

        it "uses File.expand_path" do
          result = described_class.resolve_path("relative/path")
          expect(result).to be_a(String)
          expect(result).to include("relative/path")
        end
      end
    end
  end

  describe ".fetch_entity_statement" do
    let(:url) { "https://provider.example.com/.well-known/openid-federation" }
    let(:output_file) { "config/provider-entity-statement.jwt" }
    let(:fingerprint) { "abc123" }
    let(:entity_statement) { double("EntityStatement") }
    let(:metadata) { {issuer: "https://provider.example.com", metadata: {openid_provider: {}}} }

    before do
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_return(entity_statement)
      allow(entity_statement).to receive(:save_to_file)
      allow(entity_statement).to receive(:fingerprint).and_return(fingerprint)
      allow(entity_statement).to receive(:parse).and_return(metadata)
      allow(described_class).to receive(:resolve_path).and_return("/resolved/path")
    end

    it "fetches and saves entity statement" do
      result = described_class.fetch_entity_statement(
        url: url,
        fingerprint: fingerprint,
        output_file: output_file
      )

      expect(OmniauthOpenidFederation::Federation::EntityStatement).to have_received(:fetch!).with(url, fingerprint: fingerprint)
      expect(entity_statement).to have_received(:save_to_file).with("/resolved/path")
      expect(result[:success]).to be true
      expect(result[:entity_statement]).to eq(entity_statement)
      expect(result[:output_path]).to eq("/resolved/path")
      expect(result[:fingerprint]).to eq(fingerprint)
      expect(result[:metadata]).to eq(metadata)
    end

    it "works without fingerprint" do
      result = described_class.fetch_entity_statement(
        url: url,
        fingerprint: nil,
        output_file: output_file
      )

      expect(OmniauthOpenidFederation::Federation::EntityStatement).to have_received(:fetch!).with(url, fingerprint: nil)
      expect(result[:success]).to be true
    end
  end

  describe ".validate_entity_statement" do
    let(:file_path) { "config/provider-entity-statement.jwt" }
    let(:resolved_path) { "/resolved/path" }
    let(:entity_statement_content) { "jwt.token.here" }
    let(:entity_statement) { double("EntityStatement") }
    let(:fingerprint) { "abc123" }
    let(:metadata) { {issuer: "https://provider.example.com"} }

    before do
      allow(described_class).to receive(:resolve_path).and_return(resolved_path)
      allow(File).to receive(:exist?).with(resolved_path).and_return(true)
      allow(File).to receive(:read).with(resolved_path).and_return(entity_statement_content)
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:new).and_return(entity_statement)
      allow(entity_statement).to receive(:validate_fingerprint).and_return(true)
      allow(entity_statement).to receive(:fingerprint).and_return(fingerprint)
      allow(entity_statement).to receive(:parse).and_return(metadata)
    end

    context "when file exists" do
      it "validates entity statement" do
        result = described_class.validate_entity_statement(
          file_path: file_path,
          expected_fingerprint: fingerprint
        )

        expect(OmniauthOpenidFederation::Federation::EntityStatement).to have_received(:new).with(entity_statement_content, fingerprint: fingerprint)
        expect(entity_statement).to have_received(:validate_fingerprint).with(fingerprint)
        expect(result[:success]).to be true
        expect(result[:fingerprint]).to eq(fingerprint)
        expect(result[:metadata]).to eq(metadata)
      end

      it "works without expected fingerprint" do
        result = described_class.validate_entity_statement(
          file_path: file_path,
          expected_fingerprint: nil
        )

        expect(entity_statement).not_to have_received(:validate_fingerprint)
        expect(result[:success]).to be true
      end

      context "when fingerprint mismatch" do
        before do
          allow(entity_statement).to receive(:validate_fingerprint).and_return(false)
        end

        it "raises ValidationError" do
          expect {
            described_class.validate_entity_statement(
              file_path: file_path,
              expected_fingerprint: "wrong"
            )
          }.to raise_error(OmniauthOpenidFederation::Federation::EntityStatement::ValidationError, /Fingerprint mismatch/)
        end
      end
    end

    context "when file does not exist" do
      before do
        allow(File).to receive(:exist?).with(resolved_path).and_return(false)
      end

      it "raises ConfigurationError" do
        expect {
          described_class.validate_entity_statement(file_path: file_path)
        }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /not found/)
      end
    end
  end

  describe ".fetch_jwks" do
    let(:jwks_uri) { "https://provider.example.com/.well-known/jwks.json" }
    let(:output_file) { "config/provider-jwks.json" }
    let(:jwks) { {"keys" => [{"kid" => "key1"}]} }

    before do
      allow(described_class).to receive(:resolve_path).and_return("/resolved/path")
      allow(OmniauthOpenidFederation::Jwks::Fetch).to receive(:run).and_return(jwks)
      allow(File).to receive(:write)
    end

    it "fetches and saves JWKS" do
      result = described_class.fetch_jwks(
        jwks_uri: jwks_uri,
        output_file: output_file
      )

      expect(OmniauthOpenidFederation::Jwks::Fetch).to have_received(:run).with(jwks_uri)
      expect(File).to have_received(:write).with("/resolved/path", JSON.pretty_generate(jwks))
      expect(result[:success]).to be true
      expect(result[:jwks]).to eq(jwks)
      expect(result[:output_path]).to eq("/resolved/path")
    end
  end

  describe ".parse_entity_statement" do
    let(:file_path) { "config/provider-entity-statement.jwt" }
    let(:resolved_path) { "/resolved/path" }
    let(:metadata) { {issuer: "https://provider.example.com"} }

    before do
      allow(described_class).to receive(:resolve_path).and_return(resolved_path)
      allow(File).to receive(:exist?).with(resolved_path).and_return(true)
      allow(OmniauthOpenidFederation::EntityStatementReader).to receive(:parse_metadata).and_return(metadata)
    end

    it "parses entity statement metadata" do
      result = described_class.parse_entity_statement(file_path: file_path)

      expect(OmniauthOpenidFederation::EntityStatementReader).to have_received(:parse_metadata).with(entity_statement_path: resolved_path)
      expect(result).to eq(metadata)
    end

    context "when file does not exist" do
      before do
        allow(File).to receive(:exist?).with(resolved_path).and_return(false)
      end

      it "raises ConfigurationError" do
        expect {
          described_class.parse_entity_statement(file_path: file_path)
        }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /not found/)
      end
    end

    context "when parsing fails" do
      before do
        allow(OmniauthOpenidFederation::EntityStatementReader).to receive(:parse_metadata).and_return(nil)
      end

      it "raises ValidationError" do
        expect {
          described_class.parse_entity_statement(file_path: file_path)
        }.to raise_error(OmniauthOpenidFederation::Federation::EntityStatement::ValidationError, /Failed to parse/)
      end
    end
  end

  describe ".prepare_client_keys" do
    let(:output_dir) { "config" }
    let(:resolved_path) { "/resolved/path" }

    before do
      allow(described_class).to receive(:resolve_path).and_return(resolved_path)
      allow(File).to receive(:directory?).with(resolved_path).and_return(true)
    end

    context "with single key type" do
      it "generates single key" do
        allow(described_class).to receive(:generate_single_key).and_return({
          private_key_path: "/path/private.pem",
          public_jwks_path: "/path/jwks.json",
          jwks: {keys: []}
        })

        result = described_class.prepare_client_keys(
          key_type: "single",
          output_dir: output_dir
        )

        expect(described_class).to have_received(:generate_single_key).with(resolved_path)
        expect(result[:success]).to be true
        expect(result[:output_path]).to eq(resolved_path)
      end
    end

    context "with separate key type" do
      it "generates separate keys" do
        allow(described_class).to receive(:generate_separate_keys).and_return({
          signing_key_path: "/path/signing.pem",
          encryption_key_path: "/path/encryption.pem",
          public_jwks_path: "/path/jwks.json",
          jwks: {keys: []}
        })

        result = described_class.prepare_client_keys(
          key_type: "separate",
          output_dir: output_dir
        )

        expect(described_class).to have_received(:generate_separate_keys).with(resolved_path)
        expect(result[:success]).to be true
      end
    end

    context "with invalid key type" do
      it "raises ArgumentError" do
        expect {
          described_class.prepare_client_keys(
            key_type: "invalid",
            output_dir: output_dir
          )
        }.to raise_error(ArgumentError, /Invalid key_type/)
      end
    end

    context "when output directory does not exist" do
      before do
        allow(File).to receive(:directory?).with(resolved_path).and_return(false)
        allow(FileUtils).to receive(:mkdir_p)
      end

      it "creates the directory" do
        allow(described_class).to receive(:generate_single_key).and_return({
          private_key_path: "/path/private.pem",
          public_jwks_path: "/path/jwks.json",
          jwks: {keys: []}
        })

        described_class.prepare_client_keys(
          key_type: "single",
          output_dir: output_dir
        )

        expect(FileUtils).to have_received(:mkdir_p).with(resolved_path)
      end
    end
  end

  describe ".test_local_endpoint" do
    let(:base_url) { "http://localhost:3000" }
    let(:entity_statement) { double("EntityStatement") }
    let(:metadata) do
      {
        issuer: "https://localhost:3000",
        sub: "https://localhost:3000",
        exp: Time.now.to_i + 3600,
        iat: Time.now.to_i,
        metadata: {
          openid_provider: {
            authorization_endpoint: "http://localhost:3000/authorize",
            token_endpoint: "http://localhost:3000/token",
            jwks_uri: "http://localhost:3000/.well-known/jwks.json",
            signed_jwks_uri: "http://localhost:3000/.well-known/signed-jwks.json"
          }
        },
        jwks: {"keys" => []}
      }
    end

    before do
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_return(entity_statement)
      allow(entity_statement).to receive(:parse).and_return(metadata)
    end

    it "fetches and tests entity statement endpoints" do
      allow(OmniauthOpenidFederation::Jwks::Fetch).to receive(:run).and_return({"keys" => [{"kid" => "key1"}]})
      allow(OmniauthOpenidFederation::Federation::SignedJWKS).to receive(:fetch!).and_return({"keys" => [{"kid" => "key2"}]})

      # Mock HTTP requests for other endpoints
      URI("http://localhost:3000/authorize")
      http = double("HTTP")
      response = double("Response", code: "200")
      allow(Net::HTTP).to receive(:new).and_return(http)
      allow(http).to receive(:use_ssl=)
      allow(http).to receive(:verify_mode=)
      allow(http).to receive(:request).and_return(response)

      result = described_class.test_local_endpoint(base_url: base_url)

      expect(result[:success]).to be true
      expect(result[:entity_statement]).to eq(entity_statement)
      expect(result[:metadata]).to eq(metadata)
      expect(result[:results]).to be_a(Hash)
    end

    context "when endpoint returns error" do
      it "handles FetchError gracefully" do
        # Stub the entity statement endpoint first (required for metadata)
        entity_statement = {
          iss: base_url,
          sub: base_url,
          metadata: {
            openid_provider: {
              issuer: base_url,
              authorization_endpoint: "#{base_url}/authorize",
              token_endpoint: "#{base_url}/token",
              jwks_uri: "#{base_url}/.well-known/jwks.json"
            }
          }
        }
        entity_statement_jwt = JWT.encode(entity_statement, OpenSSL::PKey::RSA.new(2048), "RS256")
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/openid-federation")
          .to_return(status: 200, body: entity_statement_jwt, headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/jwks.json")
          .to_return(status: 200, body: {keys: []}.to_json, headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/signed-jwks.json")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/authorize")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "text/html"})
        WebMock.stub_request(:get, "http://localhost:3000/token")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/userinfo")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})

        allow(OmniauthOpenidFederation::Jwks::Fetch).to receive(:run).and_raise(OmniauthOpenidFederation::FetchError.new("Network error"))

        result = described_class.test_local_endpoint(base_url: base_url)

        expect(result[:results]["JWKS URI"][:status]).to eq(:error)
        expect(result[:results]["JWKS URI"][:message]).to eq("Network error")
      end

      it "handles SignedJWKS::FetchError gracefully" do
        # Stub the entity statement endpoint first (required for metadata)
        entity_statement = {
          iss: base_url,
          sub: base_url,
          metadata: {
            openid_provider: {
              issuer: base_url,
              authorization_endpoint: "#{base_url}/authorize",
              token_endpoint: "#{base_url}/token",
              jwks_uri: "#{base_url}/.well-known/jwks.json",
              signed_jwks_uri: "#{base_url}/.well-known/signed-jwks.json"
            }
          }
        }
        entity_statement_jwt = JWT.encode(entity_statement, OpenSSL::PKey::RSA.new(2048), "RS256")
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/openid-federation")
          .to_return(status: 200, body: entity_statement_jwt, headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/jwks.json")
          .to_return(status: 200, body: {keys: []}.to_json, headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/signed-jwks.json")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/authorize")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "text/html"})
        WebMock.stub_request(:get, "http://localhost:3000/token")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/userinfo")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})

        allow(OmniauthOpenidFederation::Federation::SignedJWKS).to receive(:fetch!).and_raise(
          OmniauthOpenidFederation::Federation::SignedJWKS::FetchError.new("Fetch failed")
        )

        result = described_class.test_local_endpoint(base_url: base_url)

        expect(result[:results]["Signed JWKS URI"][:status]).to eq(:error)
        expect(result[:results]["Signed JWKS URI"][:message]).to eq("Fetch failed")
      end

      it "handles SignedJWKS::ValidationError gracefully" do
        # Stub the entity statement endpoint first (required for metadata)
        entity_statement = {
          iss: base_url,
          sub: base_url,
          metadata: {
            openid_provider: {
              issuer: base_url,
              authorization_endpoint: "#{base_url}/authorize",
              token_endpoint: "#{base_url}/token",
              jwks_uri: "#{base_url}/.well-known/jwks.json",
              signed_jwks_uri: "#{base_url}/.well-known/signed-jwks.json"
            }
          }
        }
        entity_statement_jwt = JWT.encode(entity_statement, OpenSSL::PKey::RSA.new(2048), "RS256")
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/openid-federation")
          .to_return(status: 200, body: entity_statement_jwt, headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/jwks.json")
          .to_return(status: 200, body: {keys: []}.to_json, headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/signed-jwks.json")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/authorize")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "text/html"})
        WebMock.stub_request(:get, "http://localhost:3000/token")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/userinfo")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})

        allow(OmniauthOpenidFederation::Federation::SignedJWKS).to receive(:fetch!).and_raise(
          OmniauthOpenidFederation::Federation::SignedJWKS::ValidationError.new("Validation failed")
        )

        result = described_class.test_local_endpoint(base_url: base_url)

        expect(result[:results]["Signed JWKS URI"][:status]).to eq(:error)
        expect(result[:results]["Signed JWKS URI"][:message]).to eq("Validation failed")
      end

      it "handles generic errors gracefully" do
        # Stub the entity statement endpoint first (required for metadata)
        entity_statement = {
          iss: base_url,
          sub: base_url,
          metadata: {
            openid_provider: {
              issuer: base_url,
              authorization_endpoint: "#{base_url}/authorize",
              token_endpoint: "#{base_url}/token",
              jwks_uri: "#{base_url}/.well-known/jwks.json"
            }
          }
        }
        entity_statement_jwt = JWT.encode(entity_statement, OpenSSL::PKey::RSA.new(2048), "RS256")
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/openid-federation")
          .to_return(status: 200, body: entity_statement_jwt, headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/jwks.json")
          .to_return(status: 200, body: {keys: []}.to_json, headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/signed-jwks.json")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/jwt"})
        # Stub all other endpoints that might be called
        WebMock.stub_request(:get, "http://localhost:3000/authorize")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "text/html"})
        WebMock.stub_request(:get, "http://localhost:3000/token")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/userinfo")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})

        allow(OmniauthOpenidFederation::Jwks::Fetch).to receive(:run).and_raise(StandardError.new("Unexpected error"))

        result = described_class.test_local_endpoint(base_url: base_url)

        expect(result[:results]["JWKS URI"][:status]).to eq(:error)
        expect(result[:results]["JWKS URI"][:message]).to eq("Unexpected error")
      end

      it "handles HTTP endpoint errors with warning status" do
        # Stub the HTTP request using WebMock
        # First stub the entity statement endpoint (required for metadata)
        entity_statement = {
          iss: base_url,
          sub: base_url,
          metadata: {
            openid_provider: {
              issuer: base_url,
              authorization_endpoint: "#{base_url}/authorize",
              token_endpoint: "#{base_url}/token",
              jwks_uri: "#{base_url}/.well-known/jwks.json"
            }
          }
        }
        entity_statement_jwt = JWT.encode(entity_statement, OpenSSL::PKey::RSA.new(2048), "RS256")
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/openid-federation")
          .to_return(status: 200, body: entity_statement_jwt, headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/jwks.json")
          .to_return(status: 200, body: {keys: []}.to_json, headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/signed-jwks.json")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/jwt"})
        # Stub the authorization endpoint
        # The code uses Net::HTTP which WebMock should intercept
        WebMock.stub_request(:get, "http://localhost:3000/authorize")
          .to_return(status: 404, body: "Not Found", headers: {"Content-Type" => "text/html"})

        # Also stub the token endpoint in case it's called
        WebMock.stub_request(:get, "http://localhost:3000/token")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})

        result = described_class.test_local_endpoint(base_url: base_url)

        expect(result[:results]["Authorization Endpoint"][:status]).to eq(:warning)
        expect(result[:results]["Authorization Endpoint"][:code]).to eq("404")
      end
    end
  end

  describe ".generate_single_key" do
    let(:output_path) { "/tmp/test_keys" }
    let(:private_key) { OpenSSL::PKey::RSA.new(2048) }

    before do
      allow(OpenSSL::PKey::RSA).to receive(:new).and_return(private_key)
      allow(OmniauthOpenidFederation::Utils).to receive(:rsa_key_to_jwk).and_return({
        kty: "RSA",
        n: "n_value",
        e: "e_value",
        kid: "kid_value",
        d: "d_value",
        p: "p_value",
        q: "q_value"
      })
      allow(File).to receive(:join).and_call_original
      allow(File).to receive(:write)
      allow(File).to receive(:chmod)
    end

    it "generates single key and saves files" do
      result = described_class.send(:generate_single_key, output_path)

      expect(OpenSSL::PKey::RSA).to have_received(:new).with(2048)
      expect(OmniauthOpenidFederation::Utils).to have_received(:rsa_key_to_jwk).with(private_key, use: "sig")
      expect(File).to have_received(:write).at_least(:once)
      expect(File).to have_received(:chmod).with(0o600, anything)
      expect(result[:private_key_path]).to include("client-private-key.pem")
      expect(result[:public_jwks_path]).to include("client-jwks.json")
      expect(result[:jwks]).to have_key(:keys)
    end
  end

  describe ".generate_separate_keys" do
    let(:output_path) { "/tmp/test_keys" }
    let(:signing_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:encryption_key) { OpenSSL::PKey::RSA.new(2048) }

    before do
      allow(OpenSSL::PKey::RSA).to receive(:new).and_return(signing_key, encryption_key)
      allow(OmniauthOpenidFederation::Utils).to receive(:rsa_key_to_jwk).and_return({
        kty: "RSA",
        n: "n_value",
        e: "e_value",
        kid: "kid_value"
      })
      allow(File).to receive(:write)
      allow(File).to receive(:chmod)
    end

    it "generates separate keys and saves files" do
      result = described_class.send(:generate_separate_keys, output_path)

      expect(OpenSSL::PKey::RSA).to have_received(:new).with(2048).twice
      expect(OmniauthOpenidFederation::Utils).to have_received(:rsa_key_to_jwk).with(signing_key, use: "sig")
      expect(OmniauthOpenidFederation::Utils).to have_received(:rsa_key_to_jwk).with(encryption_key, use: "enc")
      expect(File).to have_received(:write).at_least(:twice)
      expect(File).to have_received(:chmod).with(0o600, anything).at_least(:twice)
      expect(result[:signing_key_path]).to include("client-signing-private-key.pem")
      expect(result[:encryption_key_path]).to include("client-encryption-private-key.pem")
      expect(result[:public_jwks_path]).to include("client-jwks.json")
      expect(result[:jwks][:keys].length).to eq(2)
    end
  end
end

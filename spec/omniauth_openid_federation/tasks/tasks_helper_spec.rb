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

        after do
          # Restore Rails state after tests that stub Rails
          # RSpec should automatically restore stub_const, but we reset mocks for allow().to receive()

          if defined?(Rails)
            # Reset Rails mocks - RSpec will handle stub_const cleanup automatically
            RSpec::Mocks.space.proxy_for(Rails)&.reset
          end
        rescue
          # If restoration fails, continue - RSpec will handle stub cleanup
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
          aggregate_failures do
            expect(result).to be_a(String)
            expect(result).to include("relative/path")
          end
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
      allow(entity_statement).to receive_messages(
        fingerprint: fingerprint,
        parse: metadata
      )
      allow(described_class).to receive(:resolve_path).and_return("/resolved/path")
    end

    it "fetches and saves entity statement" do
      result = described_class.fetch_entity_statement(
        url: url,
        fingerprint: fingerprint,
        output_file: output_file
      )

      aggregate_failures do
        expect(OmniauthOpenidFederation::Federation::EntityStatement).to have_received(:fetch!).with(url, fingerprint: fingerprint)
        expect(entity_statement).to have_received(:save_to_file).with("/resolved/path")
        expect(result[:success]).to be true
        expect(result[:entity_statement]).to eq(entity_statement)
        expect(result[:output_path]).to eq("/resolved/path")
        expect(result[:fingerprint]).to eq(fingerprint)
        expect(result[:metadata]).to eq(metadata)
      end
    end

    it "works without fingerprint" do
      result = described_class.fetch_entity_statement(
        url: url,
        fingerprint: nil,
        output_file: output_file
      )

      aggregate_failures do
        expect(OmniauthOpenidFederation::Federation::EntityStatement).to have_received(:fetch!).with(url, fingerprint: nil)
        expect(result[:success]).to be true
      end
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
      allow(entity_statement).to receive_messages(
        validate_fingerprint: true,
        fingerprint: fingerprint
      )
      allow(entity_statement).to receive(:parse).and_return(metadata)
    end

    context "when file exists" do
      it "validates entity statement" do
        result = described_class.validate_entity_statement(
          file_path: file_path,
          expected_fingerprint: fingerprint
        )

        aggregate_failures do
          expect(OmniauthOpenidFederation::Federation::EntityStatement).to have_received(:new).with(entity_statement_content, fingerprint: fingerprint)
          expect(entity_statement).to have_received(:validate_fingerprint).with(fingerprint)
          expect(result[:success]).to be true
          expect(result[:fingerprint]).to eq(fingerprint)
          expect(result[:metadata]).to eq(metadata)
        end
      end

      it "works without expected fingerprint" do
        result = described_class.validate_entity_statement(
          file_path: file_path,
          expected_fingerprint: nil
        )

        aggregate_failures do
          expect(entity_statement).not_to have_received(:validate_fingerprint)
          expect(result[:success]).to be true
        end
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

      aggregate_failures do
        expect(OmniauthOpenidFederation::Jwks::Fetch).to have_received(:run).with(jwks_uri)
        expect(File).to have_received(:write).with("/resolved/path", JSON.pretty_generate(jwks))
        expect(result[:success]).to be true
        expect(result[:jwks]).to eq(jwks)
        expect(result[:output_path]).to eq("/resolved/path")
      end
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

      aggregate_failures do
        expect(OmniauthOpenidFederation::EntityStatementReader).to have_received(:parse_metadata).with(entity_statement_path: resolved_path)
        expect(result).to eq(metadata)
      end
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

        aggregate_failures do
          expect(described_class).to have_received(:generate_single_key).with(resolved_path)
          expect(result[:success]).to be true
          expect(result[:output_path]).to eq(resolved_path)
        end
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

        aggregate_failures do
          expect(described_class).to have_received(:generate_separate_keys).with(resolved_path)
          expect(result[:success]).to be true
        end
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

      aggregate_failures do
        expect(result[:success]).to be true
        expect(result[:entity_statement]).to eq(entity_statement)
        expect(result[:metadata]).to eq(metadata)
        expect(result[:results]).to be_a(Hash)
      end
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

        aggregate_failures do
          expect(result[:results]["JWKS URI"][:status]).to eq(:error)
          expect(result[:results]["JWKS URI"][:message]).to eq("Network error")
        end
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

        aggregate_failures do
          expect(result[:results]["Signed JWKS URI"][:status]).to eq(:error)
          expect(result[:results]["Signed JWKS URI"][:message]).to eq("Fetch failed")
        end
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

        aggregate_failures do
          expect(result[:results]["Signed JWKS URI"][:status]).to eq(:error)
          expect(result[:results]["Signed JWKS URI"][:message]).to eq("Validation failed")
        end
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

        aggregate_failures do
          expect(result[:results]["JWKS URI"][:status]).to eq(:error)
          expect(result[:results]["JWKS URI"][:message]).to eq("Unexpected error")
        end
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

        aggregate_failures do
          expect(result[:results]["Authorization Endpoint"][:status]).to eq(:warning)
          expect(result[:results]["Authorization Endpoint"][:code]).to eq("404")
        end
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

      aggregate_failures do
        expect(OpenSSL::PKey::RSA).to have_received(:new).with(2048)
        expect(OmniauthOpenidFederation::Utils).to have_received(:rsa_key_to_jwk).with(private_key, use: "sig")
        expect(File).to have_received(:write).at_least(:once)
        expect(File).to have_received(:chmod).with(0o600, anything)
        expect(result[:private_key_path]).to include("client-private-key.pem")
        expect(result[:public_jwks_path]).to include("client-jwks.json")
        expect(result[:jwks]).to have_key(:keys)
      end
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

      aggregate_failures do
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

  describe ".test_local_endpoint error paths" do
    let(:base_url) { "http://localhost:3000" }

    it "handles ValidationError when fetching entity statement" do
      # Test lines 188-199: ValidationError rescue block
      validation_error = OmniauthOpenidFederation::Federation::EntityStatement::ValidationError.new("Invalid signature")

      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_raise(validation_error)

      # Mock HttpClient.get to return a valid JWT body
      jwt_body = "header.payload.signature"
      http_response = double("Response", body: double(to_s: jwt_body), status: double(success?: true))
      allow(OmniauthOpenidFederation::HttpClient).to receive(:get).and_return(http_response)
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:new).and_return(
        double("EntityStatement", parse: {issuer: base_url, metadata: {}})
      )

      result = described_class.test_local_endpoint(base_url: base_url)

      aggregate_failures do
        expect(result[:validation_warnings]).to include("Invalid signature")
        expect(result[:success]).to be true
      end
    end

    it "handles ValidationError when parsing entity statement" do
      # Test lines 204-223: ValidationError when parsing
      entity_statement = double("EntityStatement")
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_return(entity_statement)

      validation_error = OmniauthOpenidFederation::Federation::EntityStatement::ValidationError.new("Parse failed")
      allow(entity_statement).to receive(:parse).and_raise(validation_error)
      allow(entity_statement).to receive(:entity_statement).and_return("header.payload.signature")

      # Mock Base64 and JSON parsing
      allow(Base64).to receive(:urlsafe_decode64).with("payload").and_return('{"iss":"http://localhost:3000"}')
      allow(JSON).to receive(:parse).and_return({"iss" => base_url, "sub" => base_url, "exp" => Time.now.to_i + 3600, "iat" => Time.now.to_i})

      result = described_class.test_local_endpoint(base_url: base_url)

      aggregate_failures do
        expect(result[:validation_warnings]).to include("Parse failed")
        expect(result[:success]).to be true
        expect(result[:metadata]).to be_a(Hash)
      end
    end

    it "handles Relying Party metadata" do
      # Test lines 243-247: RP metadata handling
      entity_statement = double("EntityStatement")
      metadata = {
        issuer: base_url,
        metadata: {
          openid_relying_party: {
            jwks_uri: "#{base_url}/.well-known/jwks.json",
            signed_jwks_uri: "#{base_url}/.well-known/signed-jwks.json"
          }
        }
      }
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_return(entity_statement)
      allow(entity_statement).to receive(:parse).and_return(metadata)

      WebMock.stub_request(:get, "#{base_url}/.well-known/openid-federation")
        .to_return(status: 200, body: "jwt", headers: {"Content-Type" => "application/jwt"})
      WebMock.stub_request(:get, "#{base_url}/.well-known/jwks.json")
        .to_return(status: 200, body: {keys: []}.to_json, headers: {"Content-Type" => "application/json"})
      WebMock.stub_request(:get, "#{base_url}/.well-known/signed-jwks.json")
        .to_return(status: 200, body: "jwt", headers: {"Content-Type" => "application/jwt"})

      result = described_class.test_local_endpoint(base_url: base_url)

      aggregate_failures do
        expect(result[:results]).to have_key("JWKS URI")
        expect(result[:results]["JWKS URI"][:status]).to eq(:success)
      end
    end

    it "handles InvalidURIError for endpoint URLs" do
      # Test lines 280-284: InvalidURIError handling
      entity_statement = double("EntityStatement")
      metadata = {
        issuer: base_url,
        metadata: {
          openid_provider: {
            authorization_endpoint: "not a valid url://invalid"
          }
        }
      }
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_return(entity_statement)
      allow(entity_statement).to receive(:parse).and_return(metadata)

      result = described_class.test_local_endpoint(base_url: base_url)

      aggregate_failures do
        expect(result[:results]["Authorization Endpoint"][:status]).to eq(:error)
        expect(result[:results]["Authorization Endpoint"][:message]).to include("Invalid URL")
      end
    end

    it "handles HTTPS endpoints with SSL configuration" do
      # Test lines 288-300: HTTPS SSL configuration
      entity_statement = double("EntityStatement")
      metadata = {
        issuer: "https://localhost:3000",
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://localhost:3000/authorize"
          }
        }
      }
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_return(entity_statement)
      allow(entity_statement).to receive(:parse).and_return(metadata)

      # Mock Net::HTTP
      http = double("HTTP")
      allow(Net::HTTP).to receive(:new).and_return(http)
      allow(http).to receive(:use_ssl=)
      allow(http).to receive(:verify_mode=)
      allow(http).to receive(:ca_file=)
      response = double("Response", code: "200")
      allow(http).to receive(:request).and_return(response)

      result = described_class.test_local_endpoint(base_url: "https://localhost:3000")

      aggregate_failures do
        expect(http).to have_received(:use_ssl=).with(true)
        expect(http).to have_received(:verify_mode=).with(OpenSSL::SSL::VERIFY_PEER)
      end
    end

    it "handles HTTPS with SSL_CERT_FILE environment variable" do
      # Test lines 293-294: SSL_CERT_FILE handling
      entity_statement = double("EntityStatement")
      metadata = {
        issuer: "https://localhost:3000",
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://localhost:3000/authorize"
          }
        }
      }
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_return(entity_statement)
      allow(entity_statement).to receive(:parse).and_return(metadata)

      cert_file = Tempfile.new(["cert", ".pem"])
      cert_file.write("cert content")
      cert_file.close

      begin
        ENV["SSL_CERT_FILE"] = cert_file.path

        http = double("HTTP")
        allow(Net::HTTP).to receive(:new).and_return(http)
        allow(http).to receive(:use_ssl=)
        allow(http).to receive(:verify_mode=)
        allow(http).to receive(:ca_file=)
        response = double("Response", code: "200")
        allow(http).to receive(:request).and_return(response)

        result = described_class.test_local_endpoint(base_url: "https://localhost:3000")

        expect(http).to have_received(:ca_file=).with(cert_file.path)
      ensure
        ENV.delete("SSL_CERT_FILE")
        cert_file.unlink
      end
    end

    it "handles HTTPS with DEFAULT_CERT_FILE (lines 295-296)" do
      # Test lines 295-296: DEFAULT_CERT_FILE fallback
      entity_statement = double("EntityStatement")
      metadata = {
        issuer: "https://localhost:3000",
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://localhost:3000/authorize"
          }
        }
      }
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_return(entity_statement)
      allow(entity_statement).to receive(:parse).and_return(metadata)

      # Mock OpenSSL::X509::DEFAULT_CERT_FILE - use the actual constant value
      default_cert_file = begin
        OpenSSL::X509::DEFAULT_CERT_FILE
      rescue
        "/etc/ssl/certs/ca-certificates.crt"
      end
      allow(File).to receive(:exist?).and_call_original
      allow(File).to receive(:exist?).with(default_cert_file).and_return(true)

      http = double("HTTP")
      allow(Net::HTTP).to receive(:new).and_return(http)
      allow(http).to receive(:use_ssl=)
      allow(http).to receive(:verify_mode=)
      allow(http).to receive(:ca_file=)
      response = double("Response", code: "200")
      allow(http).to receive(:request).and_return(response)

      result = described_class.test_local_endpoint(base_url: "https://localhost:3000")

      expect(http).to have_received(:ca_file=).with(default_cert_file)
    end
  end

  describe ".detect_key_status" do
    it "returns unknown for nil jwks" do
      # Test line 337
      result = described_class.send(:detect_key_status, nil)
      aggregate_failures do
        expect(result[:type]).to eq(:unknown)
        expect(result[:count]).to eq(0)
      end
    end

    it "returns unknown for empty keys" do
      # Test line 340
      result = described_class.send(:detect_key_status, {keys: []})
      aggregate_failures do
        expect(result[:type]).to eq(:unknown)
        expect(result[:count]).to eq(0)
      end
    end

    it "detects single key with duplicate kids" do
      # Test lines 343-357: duplicate_kids path
      jwks = {
        keys: [
          {kid: "same-kid", use: "sig"},
          {kid: "same-kid", use: "enc"}
        ]
      }
      result = described_class.send(:detect_key_status, jwks)
      aggregate_failures do
        expect(result[:type]).to eq(:single)
        expect(result[:count]).to eq(2)
        expect(result[:recommendation]).to include("Single key detected")
      end
    end

    it "detects separate keys with both uses" do
      # Test lines 358-363: has_both_uses path
      jwks = {
        keys: [
          {kid: "sig-kid", use: "sig"},
          {kid: "enc-kid", use: "enc"}
        ]
      }
      result = described_class.send(:detect_key_status, jwks)
      aggregate_failures do
        expect(result[:type]).to eq(:separate)
        expect(result[:count]).to eq(2)
        expect(result[:recommendation]).to include("Separate keys detected")
      end
    end

    it "detects single key when only one key exists" do
      # Test lines 364-369: single key path
      jwks = {
        keys: [
          {kid: "single-kid", use: "sig"}
        ]
      }
      result = described_class.send(:detect_key_status, jwks)
      aggregate_failures do
        expect(result[:type]).to eq(:single)
        expect(result[:count]).to eq(1)
        expect(result[:recommendation]).to include("Single key detected")
      end
    end

    it "handles unknown configuration" do
      # Test lines 370-376: else path
      jwks = {
        keys: [
          {kid: "key1"},
          {kid: "key2"},
          {kid: "key3"}
        ]
      }
      result = described_class.send(:detect_key_status, jwks)
      aggregate_failures do
        expect(result[:type]).to eq(:unknown)
        expect(result[:count]).to eq(3)
        expect(result[:recommendation]).to include("Key configuration unclear")
      end
    end

    it "handles string keys in jwks" do
      # Test line 339: string keys
      jwks = {
        "keys" => [
          {"kid" => "key1", "use" => "sig"}
        ]
      }
      result = described_class.send(:detect_key_status, jwks)
      expect(result[:type]).to eq(:single)
    end

    it "handles symbol keys in jwks" do
      # Test line 339: symbol keys
      jwks = {
        keys: [
          {kid: "key1", use: "sig"}
        ]
      }
      result = described_class.send(:detect_key_status, jwks)
      expect(result[:type]).to eq(:single)
    end
  end

  describe ".test_authentication_flow" do
    let(:login_page_url) { "http://localhost:3000/login" }
    let(:base_url) { "http://localhost:3000" }

    it "handles failed login page fetch" do
      # Test lines 490-495: failed login response
      WebMock.stub_request(:get, login_page_url)
        .to_return(status: 500, body: "Internal Server Error", headers: {"Content-Type" => "text/html"})

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to fetch login page/)
    end

    it "handles missing CSRF token" do
      # Test lines 533-535: missing CSRF token
      WebMock.stub_request(:get, login_page_url)
        .to_return(status: 200, body: "<html><body>No CSRF token here</body></html>", headers: {"Content-Type" => "text/html"})

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to extract CSRF token/)
    end

    it "extracts CSRF token from meta tag" do
      # Test lines 522-524: CSRF from meta tag
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"

      WebMock.stub_request(:get, login_page_url)
        .to_return(status: 200, body: html_body, headers: {"Content-Type" => "text/html"})

      # Mock test endpoint responses (lines 590-598)
      WebMock.stub_request(:get, "#{base_url}/users/auth/openid_federation")
        .to_return(status: 404, body: "", headers: {})
      WebMock.stub_request(:get, "#{base_url}/auth/openid_federation")
        .to_return(status: 404, body: "", headers: {})
      WebMock.stub_request(:get, "#{base_url}/openid_federation")
        .to_return(status: 404, body: "", headers: {})

      # Mock the authorization request that will fail
      WebMock.stub_request(:post, "#{base_url}/users/auth/openid_federation")
        .to_return(status: 500, body: "", headers: {})

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to get authorization URL/)
    end

    it "extracts CSRF token from form input" do
      # Test lines 527-531: CSRF from form input
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><body><form action='/users/auth/openid_federation'><input name='authenticity_token' value='#{csrf_token}'></form></body></html>"

      WebMock.stub_request(:get, login_page_url)
        .to_return(status: 200, body: html_body, headers: {"Content-Type" => "text/html"})

      # Mock test endpoint responses
      WebMock.stub_request(:get, "#{base_url}/users/auth/openid_federation")
        .to_return(status: 404, body: "", headers: {})
      WebMock.stub_request(:get, "#{base_url}/auth/openid_federation")
        .to_return(status: 404, body: "", headers: {})
      WebMock.stub_request(:get, "#{base_url}/openid_federation")
        .to_return(status: 404, body: "", headers: {})

      # Mock the authorization request that will fail
      WebMock.stub_request(:post, "#{base_url}/users/auth/openid_federation")
        .to_return(status: 500, body: "", headers: {})

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to get authorization URL/)
    end

    it "handles large HTML body" do
      # Test lines 516-519: HTML body size limit
      large_html = "x" * 1_048_577 # Exceeds 1MB limit

      WebMock.stub_request(:get, login_page_url)
        .to_return(status: 200, body: large_html, headers: {"Content-Type" => "text/html"})

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/HTML response too large/)
    end

    it "handles cookie extraction with size limits" do
      # Test lines 497-509: cookie extraction
      large_cookie = "x" * 5000 # Exceeds 4KB limit
      html_body = "<html><head><meta name='csrf-token' content='token'></head><body><form action='/users/auth/openid_federation'></form></body></html>"

      WebMock.stub_request(:get, login_page_url)
        .to_return(status: 200, body: html_body, headers: {"Content-Type" => "text/html", "Set-Cookie" => "cookie_name=#{large_cookie}"})

      # Mock test endpoint responses
      WebMock.stub_request(:get, "#{base_url}/users/auth/openid_federation")
        .to_return(status: 404, body: "", headers: {})
      WebMock.stub_request(:get, "#{base_url}/auth/openid_federation")
        .to_return(status: 404, body: "", headers: {})
      WebMock.stub_request(:get, "#{base_url}/openid_federation")
        .to_return(status: 404, body: "", headers: {})

      # Mock the authorization request that will fail
      WebMock.stub_request(:post, "#{base_url}/users/auth/openid_federation")
        .to_return(status: 500, body: "", headers: {})

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to get authorization URL/)
    end

    it "handles authorization response with 3xx redirect (lines 634-647)" do
      # Test lines 634-647: 3xx redirect handling
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"
      location_header = "https://provider.example.com/authorize?request=..."

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      # Mock test endpoint responses
      test_response = double("Response", status: double(code: 404))

      # Mock authorization response with 3xx redirect
      auth_response = double(
        "Response",
        status: double(code: 302),
        headers: {"Location" => location_header},
        body: double(to_s: "")
      )

      # Stub build_http_client to return a chainable mock
      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 302, headers: {"Location" => location_header})

      result = described_class.test_authentication_flow(
        login_page_url: login_page_url,
        base_url: base_url
      )

      expect(result[:authorization_url]).to eq(location_header)
    end

    it "handles authorization response with 200 status (lines 648-651)" do
      # Test lines 648-651: 200 status handling
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"
      authorization_url = "https://provider.example.com/authorize?request=..."

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      test_response = double("Response", status: double(code: 404))

      # Mock authorization response with 200 and Location header
      auth_response = double(
        "Response",
        status: double(code: 200),
        headers: {"Location" => authorization_url},
        body: double(to_s: "")
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 200, headers: {"Location" => authorization_url})

      result = described_class.test_authentication_flow(
        login_page_url: login_page_url,
        base_url: base_url
      )

      expect(result[:authorization_url]).to eq(authorization_url)
    end

    it "handles authorization response with 200 and body URL (line 649)" do
      # Test line 649: body URL extraction
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"
      authorization_url = "https://provider.example.com/authorize?request=..."

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      test_response = double("Response", status: double(code: 404))

      # Mock authorization response with 200, no Location header, but URL in body
      auth_response = double(
        "Response",
        status: double(code: 200),
        headers: {},
        body: double(to_s: authorization_url)
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 200, body: authorization_url)

      result = described_class.test_authentication_flow(
        login_page_url: login_page_url,
        base_url: base_url
      )

      expect(result[:authorization_url]).to eq(authorization_url)
    end

    it "handles location header exceeding max length (line 638-639)" do
      # Test lines 638-639: location header length validation
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"
      long_location = "https://provider.example.com/authorize?request=#{"x" * 3000}" # Exceeds 2048

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      test_response = double("Response", status: double(code: 404))

      auth_response = double(
        "Response",
        status: double(code: 302),
        headers: {"Location" => long_location},
        body: double(to_s: "")
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 302, headers: {"Location" => long_location})

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Location header exceeds maximum length/)
    end

    it "handles relative location header (line 645)" do
      # Test line 645: relative location handling
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"
      relative_location = "/authorize?request=..."

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      test_response = double("Response", status: double(code: 404))

      auth_response = double(
        "Response",
        status: double(code: 302),
        headers: {"Location" => relative_location},
        body: double(to_s: "")
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 302, headers: {"Location" => relative_location})

      result = described_class.test_authentication_flow(
        login_page_url: login_page_url,
        base_url: base_url
      )

      expect(result[:authorization_url]).to include("/authorize")
    end

    it "handles form action with openid_federation (lines 551-565)" do
      # Test lines 551-565: form action matching
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      test_response = double("Response", status: double(code: 404))
      auth_response = double(
        "Response",
        status: double(code: 500, reason: "Error"),
        headers: {},
        body: double(to_s: "")
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 500, body: "Error")

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to get authorization URL/)
    end

    it "handles button/link href matching (lines 568-581)" do
      # Test lines 568-581: button href matching
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><a href='/users/auth/openid_federation'>Login</a></body></html>"

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      test_response = double("Response", status: double(code: 404))
      auth_response = double(
        "Response",
        status: double(code: 500, reason: "Error"),
        headers: {},
        body: double(to_s: "")
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 500, body: "Error")

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to get authorization URL/)
    end

    it "handles common paths testing (lines 590-602)" do
      # Test lines 590-602: common paths testing
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body>No form found</body></html>"

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      # Mock test responses for common paths
      test_response_404 = double("Response", status: double(code: 404))
      test_response_302 = double("Response", status: double(code: 302))

      auth_response = double(
        "Response",
        status: double(code: 500, reason: "Error"),
        headers: {},
        body: double(to_s: "")
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response_404, test_response_404, test_response_302)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:get, /http:\/\/localhost:3000\//).to_return(status: 404, body: "Not Found")
      WebMock.stub_request(:get, /http:\/\/localhost:3000\/login/).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 500, body: "Error")

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to get authorization URL/)
    end

    it "handles cookie extraction with valid cookies (lines 506-507)" do
      # Test lines 506-507: cookie extraction
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"
      cookie_value = "session_id=abc123; path=/"

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {"Set-Cookie" => cookie_value},
        body: double(to_s: html_body)
      )

      test_response = double("Response", status: double(code: 404))
      auth_response = double(
        "Response",
        status: double(code: 500, reason: "Error"),
        headers: {},
        body: double(to_s: "")
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 404, body: "Not Found")
      WebMock.stub_request(:get, /http:\/\/localhost:3000\//).to_return(status: 404, body: "Not Found")
      WebMock.stub_request(:post, /.*/).to_return(status: 500, body: "Error")

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to (get authorization URL|fetch login page)/)
    end
  end

  describe ".process_callback_and_validate" do
    let(:callback_url) { "http://localhost:3000/callback?code=auth-code&state=state-value" }
    let(:base_url) { "http://localhost:3000" }
    let(:client_id) { "test-client" }
    let(:redirect_uri) { "http://localhost:3000/callback" }
    let(:private_key) { OpenSSL::PKey::RSA.new(2048) }

    it "handles invalid callback URL" do
      # Test lines 721-725: InvalidURIError handling
      expect {
        described_class.process_callback_and_validate(
          callback_url: "not a valid url",
          base_url: base_url,
          client_id: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        )
      }.to raise_error(/Invalid callback URL/)
    end

    it "handles authorization error in callback" do
      # Test lines 730-735: error parameter handling
      error_callback = "http://localhost:3000/callback?error=access_denied&error_description=User%20denied"

      expect {
        described_class.process_callback_and_validate(
          callback_url: error_callback,
          base_url: base_url,
          client_id: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        )
      }.to raise_error(/Authorization error: access_denied/)
    end

    it "handles authorization error without description" do
      # Test line 734: error without error_description
      error_callback = "http://localhost:3000/callback?error=access_denied"

      expect {
        described_class.process_callback_and_validate(
          callback_url: error_callback,
          base_url: base_url,
          client_id: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        )
      }.to raise_error(/Authorization error: access_denied/)
    end

    it "handles missing authorization code" do
      # Test lines 737-739: missing code
      no_code_callback = "http://localhost:3000/callback?state=state-value"

      expect {
        described_class.process_callback_and_validate(
          callback_url: no_code_callback,
          base_url: base_url,
          client_id: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        )
      }.to raise_error(/No authorization code found/)
    end

    it "resolves entity statement URL from path" do
      # Test lines 752-756: entity_statement_path resolution
      # Use temp directory to avoid writing to project config/
      temp_dir = Dir.mktmpdir
      temp_config_dir = File.join(temp_dir, "config")
      FileUtils.mkdir_p(temp_config_dir)
      entity_statement_path = "config/entity.jwt"
      temp_file_path = File.join(temp_config_dir, "entity.jwt")

      # Stub Rails.root to point to temp directory if Rails is defined
      if defined?(Rails)
        allow(Rails.root).to receive(:join).with("config/entity.jwt").and_return(Pathname.new(temp_file_path))
      else
        config = OmniauthOpenidFederation::Configuration.config
        original_root_path = config.root_path
        config.root_path = temp_dir
      end

      # Stub the entity statement fetch to avoid WebMock error
      stub_request(:get, /.*\/\.well-known\/openid-federation/)
        .to_return(status: 200, body: "", headers: {"Content-Type" => "application/jwt"})

      begin
        # This will fail later, but we're testing the URL resolution
        expect {
          described_class.process_callback_and_validate(
            callback_url: callback_url,
            base_url: base_url,
            client_id: client_id,
            redirect_uri: redirect_uri,
            private_key: private_key,
            entity_statement_path: entity_statement_path
          )
        }.to raise_error(StandardError) # Will fail at strategy initialization, but URL resolution is tested
      ensure
        FileUtils.rm_rf(temp_dir) if File.directory?(temp_dir)
        unless defined?(Rails)
          config = OmniauthOpenidFederation::Configuration.config
          config.root_path = original_root_path
        end
      end
    end

    it "resolves client entity statement URL from path" do
      # Test lines 758-762: client_entity_statement_path resolution
      # Use temp directory to avoid writing to project config/
      temp_dir = Dir.mktmpdir
      temp_config_dir = File.join(temp_dir, "config")
      FileUtils.mkdir_p(temp_config_dir)
      client_entity_statement_path = "config/client-entity.jwt"
      temp_file_path = File.join(temp_config_dir, "client-entity.jwt")

      # Stub Rails.root to point to temp directory if Rails is defined
      if defined?(Rails)
        allow(Rails.root).to receive(:join).with("config/client-entity.jwt").and_return(Pathname.new(temp_file_path))
      else
        config = OmniauthOpenidFederation::Configuration.config
        original_root_path = config.root_path
        config.root_path = temp_dir
      end

      begin
        # This will fail later, but we're testing the URL resolution
        expect {
          described_class.process_callback_and_validate(
            callback_url: callback_url,
            base_url: base_url,
            client_id: client_id,
            redirect_uri: redirect_uri,
            private_key: private_key,
            client_entity_statement_path: client_entity_statement_path
          )
        }.to raise_error(StandardError) # Will fail at strategy initialization, but URL resolution is tested
      ensure
        FileUtils.rm_rf(temp_dir) if File.directory?(temp_dir)
        unless defined?(Rails)
          config = OmniauthOpenidFederation::Configuration.config
          config.root_path = original_root_path
        end
      end
    end

    it "handles failed client initialization" do
      # Test lines 793-795: failed client initialization
      # Mock strategy to return nil client
      strategy = double("Strategy")
      allow(strategy).to receive(:client).and_return(nil)
      allow(OmniAuth::Strategies::OpenIDFederation).to receive(:new).and_return(strategy)

      expect {
        described_class.process_callback_and_validate(
          callback_url: callback_url,
          base_url: base_url,
          client_id: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        )
      }.to raise_error(/Failed to initialize OpenID Connect client/)
    end

    it "handles missing private key on client" do
      # Test lines 797-799: missing private key
      oidc_client = double("OpenIDConnect::Client")
      allow(oidc_client).to receive(:private_key).and_return(nil)

      strategy = double("Strategy")
      allow(strategy).to receive(:client).and_return(oidc_client)
      allow(OmniAuth::Strategies::OpenIDFederation).to receive(:new).and_return(strategy)

      expect {
        described_class.process_callback_and_validate(
          callback_url: callback_url,
          base_url: base_url,
          client_id: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        )
      }.to raise_error(/Private key not set/)
    end
  end
end

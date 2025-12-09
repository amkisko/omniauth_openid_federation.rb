# frozen_string_literal: true

require "spec_helper"
require "rake"

# rubocop:disable RSpec/DescribeClass
RSpec.describe "openid_federation:fetch_entity_statement" do
  include_context "with rake tasks helpers"

  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:entity_statement_url) { "https://provider.example.com/.well-known/openid-federation" }

  def entity_statement_content
    public_key = private_key.public_key
    jwk = JWT::JWK.new(public_key)
    jwk_export = jwk.export
    jwk_export[:kid] = "key-1"
    payload = {
      iss: "https://provider.example.com",
      sub: "https://provider.example.com",
      exp: Time.now.to_i + 3600,
      iat: Time.now.to_i,
      jwks: {
        keys: [jwk_export]
      },
      metadata: {
        openid_provider: {
          issuer: "https://provider.example.com",
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token",
          userinfo_endpoint: "https://provider.example.com/oauth2/userinfo",
          jwks_uri: "https://provider.example.com/.well-known/jwks.json"
        }
      }
    }
    header = {alg: "RS256", typ: "entity-statement+jwt", kid: "key-1"}
    JWT.encode(payload, private_key, "RS256", header)
  end

  context "when URL is missing" do
    it "exits with error and shows usage" do
      result = run_rake_task("openid_federation:fetch_entity_statement")

      aggregate_failures do
        expect(result[:stdout]).to include("❌ Entity statement URL is required")
        expect(result[:stdout]).to include("Usage:")
      end
    end
  end

  context "when URL is provided via argument" do
    before do
      stub_request(:get, entity_statement_url)
        .to_return(status: 200, body: entity_statement_content, headers: {"Content-Type" => "application/jwt"})
    end

    it "fetches and saves entity statement" do
      result = run_rake_task("openid_federation:fetch_entity_statement", entity_statement_url, nil, output_file)

      aggregate_failures do
        expect(File.exist?(output_file)).to be true
        expect(File.read(output_file)).to eq(entity_statement_content)
        expect(result[:stdout]).to include("✅ Entity statement saved to:")
        expect(result[:stdout]).to include("✅ Fingerprint:")
      end
    end

    it "displays metadata after fetching" do
      result = run_rake_task("openid_federation:fetch_entity_statement", entity_statement_url, nil, output_file)

      aggregate_failures do
        expect(result[:stdout]).to include("📋 Entity Statement Metadata:")
        expect(result[:stdout]).to include("Issuer:")
        expect(result[:stdout]).to include("Authorization Endpoint:")
      end
    end

    it "validates fingerprint when provided" do
      fingerprint = Digest::SHA256.hexdigest(entity_statement_content).downcase
      stub_request(:get, entity_statement_url)
        .to_return(status: 200, body: entity_statement_content, headers: {"Content-Type" => "application/jwt"})
      result = run_rake_task("openid_federation:fetch_entity_statement", entity_statement_url, fingerprint, output_file)

      aggregate_failures do
        expect(result[:stdout]).to include("Expected fingerprint:")
        expect(File.exist?(output_file)).to be true
      end
    end
  end

  context "when URL is provided via environment variable" do
    # rubocop:disable RSpec/MultipleMemoizedHelpers
    let!(:test_dir) { Dir.mktmpdir }

    before do
      test_config_dir = File.join(test_dir, "config")
      default_output_path = File.join(test_config_dir, "provider-entity-statement.jwt")
      FileUtils.mkdir_p(test_config_dir)
      ENV["ENTITY_STATEMENT_URL"] = entity_statement_url
      ENV["ENTITY_STATEMENT_OUTPUT"] = default_output_path
      stub_request(:get, entity_statement_url)
        .to_return(status: 200, body: entity_statement_content, headers: {"Content-Type" => "application/jwt"})
    end

    after do
      ENV.delete("ENTITY_STATEMENT_URL")
      ENV.delete("ENTITY_STATEMENT_OUTPUT")
      FileUtils.rm_rf(test_dir) if File.directory?(test_dir)
    end

    it "uses environment variable" do
      default_output_path = File.join(File.join(test_dir, "config"), "provider-entity-statement.jwt")
      result = run_rake_task("openid_federation:fetch_entity_statement")

      aggregate_failures do
        expect(File.exist?(default_output_path)).to be true
        expect(result[:stdout]).to include("✅ Entity statement saved to:")
      end
    end
  end
  # rubocop:enable RSpec/MultipleMemoizedHelpers

  context "when fetch fails" do
    before do
      stub_request(:get, entity_statement_url)
        .to_return(status: 404, body: "Not Found")
    end

    it "exits with error" do
      result = run_rake_task("openid_federation:fetch_entity_statement", entity_statement_url, nil, output_file)

      aggregate_failures do
        expect(result[:stdout]).to include("❌ Error fetching entity statement")
        expect(File.exist?(output_file)).to be false
      end
    end
  end

  context "when fingerprint validation fails" do
    before do
      stub_request(:get, entity_statement_url)
        .to_return(status: 200, body: entity_statement_content, headers: {"Content-Type" => "application/jwt"})
    end

    it "exits with validation error" do
      wrong_fingerprint = "wrong-fingerprint"
      result = run_rake_task("openid_federation:fetch_entity_statement", entity_statement_url, wrong_fingerprint, output_file)

      aggregate_failures do
        expect(result[:stdout]).to include("❌ Validation error")
        expect(result[:stdout]).to include("fingerprint mismatch")
      end
    end
  end
end
# rubocop:enable RSpec/DescribeClass

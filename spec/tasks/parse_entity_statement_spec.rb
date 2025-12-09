# frozen_string_literal: true

require "spec_helper"
require "rake"

# rubocop:disable RSpec/DescribeClass
RSpec.describe "openid_federation:parse_entity_statement" do
  include_context "with rake tasks helpers"

  let(:entity_statement_content) do
    header = Base64.urlsafe_encode64({alg: "RS256", kid: "key-1"}.to_json).gsub(/=+$/, "")
    payload = Base64.urlsafe_encode64({
      iss: "https://provider.example.com",
      sub: "https://provider.example.com",
      exp: Time.now.to_i + 3600,
      iat: Time.now.to_i,
      jwks: {keys: []},
      metadata: {
        openid_provider: {
          issuer: "https://provider.example.com",
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token",
          userinfo_endpoint: "https://provider.example.com/oauth2/userinfo",
          jwks_uri: "https://provider.example.com/.well-known/jwks.json"
        }
      }
    }.to_json).gsub(/=+$/, "")
    signature = "signature"
    "#{header}.#{payload}.#{signature}"
  end

  context "when file does not exist" do
    it "exits with error" do
      result = run_rake_task("openid_federation:parse_entity_statement", "/nonexistent/file.jwt")

      expect(result[:stdout]).to include("❌ Error: Entity statement file not found")
    end
  end

  context "when file exists" do
    before do
      File.write(entity_statement_file, entity_statement_content)
    end

    it "parses and displays metadata as JSON" do
      result = run_rake_task("openid_federation:parse_entity_statement", entity_statement_file)

      aggregate_failures do
        expect(result[:stdout]).to include("📋 Entity Statement Metadata:")
        # Should be valid JSON
        json_match = result[:stdout].match(/\{.*\}/m)
        expect(json_match).to be_present
        parsed = JSON.parse(json_match[0])
        expect(parsed).to be_a(Hash)
      end
    end
  end
end
# rubocop:enable RSpec/DescribeClass

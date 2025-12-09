# frozen_string_literal: true

require "spec_helper"
require "rake"

# rubocop:disable RSpec/DescribeClass
RSpec.describe "openid_federation:fetch_jwks" do
  include_context "with rake tasks helpers"

  let(:jwks_uri) { "https://provider.example.com/.well-known/jwks.json" }
  let(:jwks_file) { File.join(temp_dir, "jwks.json") }

  def jwks_content
    {
      keys: [
        {
          kid: "key-1",
          kty: "RSA",
          use: "sig",
          n: "n-value",
          e: "AQAB"
        }
      ]
    }
  end

  context "when JWKS URI is missing" do
    it "exits with error and shows usage" do
      result = run_rake_task("openid_federation:fetch_jwks")

      aggregate_failures do
        expect(result[:stdout]).to include("❌ JWKS URI is required")
        expect(result[:stdout]).to include("Usage:")
      end
    end
  end

  context "when JWKS URI is provided" do
    before do
      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks_content.to_json, headers: {"Content-Type" => "application/json"})
    end

    it "fetches and saves JWKS" do
      result = run_rake_task("openid_federation:fetch_jwks", jwks_uri, jwks_file)

      aggregate_failures do
        expect(File.exist?(jwks_file)).to be true
        saved_jwks = JSON.parse(File.read(jwks_file))
        expect(saved_jwks["keys"].length).to eq(1)
        expect(result[:stdout]).to include("✅ JWKS saved to:")
        expect(result[:stdout]).to include("✅ Keys found:")
      end
    end

    it "displays key information" do
      result = run_rake_task("openid_federation:fetch_jwks", jwks_uri, jwks_file)

      aggregate_failures do
        expect(result[:stdout]).to include("Key 1:")
        expect(result[:stdout]).to include("kid:")
        expect(result[:stdout]).to include("kty:")
      end
    end
  end

  context "when fetch fails" do
    before do
      stub_request(:get, jwks_uri)
        .to_return(status: 404, body: "Not Found")
    end

    it "exits with error" do
      result = run_rake_task("openid_federation:fetch_jwks", jwks_uri, jwks_file)

      aggregate_failures do
        expect(result[:stdout]).to include("❌ Error fetching JWKS")
        expect(File.exist?(jwks_file)).to be false
      end
    end
  end
end
# rubocop:enable RSpec/DescribeClass

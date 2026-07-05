require "spec_helper"

RSpec.describe OmniauthOpenidFederation::TasksHelper do
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

end

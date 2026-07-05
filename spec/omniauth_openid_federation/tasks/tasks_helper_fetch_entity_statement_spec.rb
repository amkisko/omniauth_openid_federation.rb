require "spec_helper"

RSpec.describe OmniauthOpenidFederation::TasksHelper do
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
end

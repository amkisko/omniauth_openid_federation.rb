require "spec_helper"

RSpec.describe OmniauthOpenidFederation::TasksHelper do
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
end

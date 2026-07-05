require "spec_helper"

RSpec.describe OmniauthOpenidFederation::TasksHelper do
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

end

require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Federation::EntityStatementHelper do
  let(:entity_statement_path) { "spec/fixtures/entity_statement.jwt" }
  let(:entity_statement_content) do
    # Minimal valid JWT structure
    header = Base64.urlsafe_encode64({alg: "RS256", kid: "key1"}.to_json, padding: false)
    payload = Base64.urlsafe_encode64({
      iss: "https://provider.example.com",
      sub: "https://provider.example.com",
      jwks: {keys: []},
      metadata: {
        openid_provider: {
          signed_jwks_uri: "https://provider.example.com/.well-known/signed-jwks.json"
        }
      }
    }.to_json, padding: false)
    signature = "signature"
    "#{header}.#{payload}.#{signature}"
  end

  before do
    # Create fixtures directory if it doesn't exist
    fixtures_dir = File.dirname(entity_statement_path)
    FileUtils.mkdir_p(fixtures_dir) unless File.directory?(fixtures_dir)

    # Create a temporary entity statement file
    File.write(entity_statement_path, entity_statement_content) if defined?(Rails)
  end

  after do
    File.delete(entity_statement_path) if File.exist?(entity_statement_path)
  end

  describe ".parse_for_signed_jwks" do
    context "when Rails is available" do
      let(:temp_rails_root) { Dir.mktmpdir }
      let(:temp_rails_root_pathname) { Pathname.new(temp_rails_root) }

      before do
        # Stub Rails.root to use temp directory to avoid creating files in project config/
        if defined?(Rails)
          allow(Rails).to receive(:root).and_return(temp_rails_root_pathname)
        else
          stub_const("Rails", double(root: temp_rails_root_pathname))
        end
      end

      after do
        FileUtils.rm_rf(temp_rails_root) if File.directory?(temp_rails_root)
      end

      it "parses entity statement and returns metadata" do
        # Create file in temp Rails config directory using absolute path
        temp_config_dir = File.join(temp_rails_root, "config")
        FileUtils.mkdir_p(temp_config_dir)
        rails_config_path = File.join(temp_config_dir, "entity_statement.jwt")
        File.write(rails_config_path, entity_statement_content)

        # Use full path to pass validation
        result = described_class.parse_for_signed_jwks(rails_config_path)

        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result).to have_key(:signed_jwks_uri)
          expect(result).to have_key(:entity_jwks)
          expect(result).to have_key(:metadata)
        end
      end

      it "uses Rails.root.join when Rails is available (line 22)" do
        # Create file in temp Rails config directory using absolute path
        temp_config_dir = File.join(temp_rails_root, "config")
        FileUtils.mkdir_p(temp_config_dir)
        rails_config_path = File.join(temp_config_dir, "test_entity.jwt")
        File.write(rails_config_path, entity_statement_content)

        # This should use the Rails branch at line 22
        # Use full path to pass validation
        result = described_class.parse_for_signed_jwks(rails_config_path)
        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result).to have_key(:signed_jwks_uri)
        end
      end

      it "returns nil when file does not exist" do
        # Use a path within the temp allowed directory
        temp_config_dir = File.join(temp_rails_root, "config")
        FileUtils.mkdir_p(temp_config_dir)
        nonexistent_path = File.join(temp_config_dir, "nonexistent.jwt")
        result = described_class.parse_for_signed_jwks(nonexistent_path)
        expect(result).to be_nil
      end

      it "raises SecurityError for path traversal attempts" do
        expect { described_class.parse_for_signed_jwks("../../../etc/passwd") }
          .to raise_error(OmniauthOpenidFederation::SecurityError)
      end

      it "raises ValidationError when parsing fails" do
        # Create file in temp Rails config directory using absolute path
        temp_config_dir = File.join(temp_rails_root, "config")
        FileUtils.mkdir_p(temp_config_dir)
        invalid_path = File.join(temp_config_dir, "invalid.jwt")
        File.write(invalid_path, "invalid jwt")

        expect { described_class.parse_for_signed_jwks(invalid_path) }
          .to raise_error(OmniauthOpenidFederation::ValidationError)
      end
    end

    context "when Rails is not available" do
      before do
        hide_const("Rails")
      end

      it "uses config.root_path when available" do
        config = OmniauthOpenidFederation::Configuration.config
        config.root_path = Dir.mktmpdir

        # Create file in the allowed directory
        allowed_dir = File.join(config.root_path, "config")
        FileUtils.mkdir_p(allowed_dir) unless File.directory?(allowed_dir)
        file_path = File.join(allowed_dir, "entity_statement.jwt")
        File.write(file_path, entity_statement_content)

        # Use absolute path within allowed directory
        result = described_class.parse_for_signed_jwks(file_path)
        expect(result).to be_a(Hash)

        FileUtils.rm_rf(config.root_path) if File.directory?(config.root_path)
        config.root_path = nil
      end

      it "returns nil when file does not exist" do
        config = OmniauthOpenidFederation::Configuration.config
        config.root_path = Dir.mktmpdir

        # Use absolute path within allowed directory
        allowed_dir = File.join(config.root_path, "config")
        nonexistent_path = File.join(allowed_dir, "nonexistent.jwt")

        allow(OmniauthOpenidFederation::Logger).to receive(:warn)
        result = described_class.parse_for_signed_jwks(nonexistent_path)
        aggregate_failures do
          expect(OmniauthOpenidFederation::Logger).to have_received(:warn).with(/Entity statement file not found/)
          expect(result).to be_nil
        end

        FileUtils.rm_rf(config.root_path) if File.directory?(config.root_path)
        config.root_path = nil
      end

      it "logs error and raises ValidationError when parsing fails" do
        config = OmniauthOpenidFederation::Configuration.config
        config.root_path = Dir.mktmpdir
        allowed_dir = File.join(config.root_path, "config")
        FileUtils.mkdir_p(allowed_dir) unless File.directory?(allowed_dir)
        file_path = File.join(allowed_dir, "invalid.jwt")
        File.write(file_path, "invalid jwt")

        allow(OmniauthOpenidFederation::Logger).to receive(:error)
        aggregate_failures do
          expect {
            described_class.parse_for_signed_jwks(file_path)
          }.to raise_error(OmniauthOpenidFederation::ValidationError, /Failed to parse entity statement/)
          expect(OmniauthOpenidFederation::Logger).to have_received(:error).with(/Failed to parse entity statement/)
        end

        FileUtils.rm_rf(config.root_path) if File.directory?(config.root_path)
        config.root_path = nil
      end
    end
  end
end

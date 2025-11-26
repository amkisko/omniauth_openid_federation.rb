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
    # Create a temporary entity statement file
    File.write(entity_statement_path, entity_statement_content) if defined?(Rails)
  end

  after do
    File.delete(entity_statement_path) if File.exist?(entity_statement_path)
  end

  describe ".parse_for_signed_jwks" do
    context "when Rails is available" do
      let(:temp_rails_root) { Dir.mktmpdir }

      before do
        # Ensure Rails is defined for these tests
        unless defined?(Rails)
          rails_root_pathname = Pathname.new(temp_rails_root)
          stub_const("Rails", double(root: rails_root_pathname))
        end
      end

      after do
        FileUtils.rm_rf(temp_rails_root) if File.directory?(temp_rails_root)
      end

      it "parses entity statement and returns metadata" do
        if defined?(Rails)
          # Create file in Rails config directory
          rails_config_path = Rails.root.join("config", "entity_statement.jwt").to_s
          FileUtils.mkdir_p(File.dirname(rails_config_path))
          File.write(rails_config_path, entity_statement_content)

          # Use full path to pass validation
          result = described_class.parse_for_signed_jwks(rails_config_path)

          expect(result).to be_a(Hash)
          expect(result).to have_key(:signed_jwks_uri)
          expect(result).to have_key(:entity_jwks)
          expect(result).to have_key(:metadata)
        end
      end

      it "uses Rails.root.join when Rails is available (line 22)" do
        if defined?(Rails)
          # Create file in Rails config directory
          rails_config_path = Rails.root.join("config", "test_entity.jwt").to_s
          FileUtils.mkdir_p(File.dirname(rails_config_path))
          File.write(rails_config_path, entity_statement_content)

          # This should use the Rails branch at line 22
          # Use full path to pass validation
          result = described_class.parse_for_signed_jwks(rails_config_path)
          expect(result).to be_a(Hash)
          expect(result).to have_key(:signed_jwks_uri)
        end
      end

      it "returns nil when file does not exist" do
        if defined?(Rails)
          # Use a path within the allowed directory
          nonexistent_path = Rails.root.join("config", "nonexistent.jwt").to_s
          result = described_class.parse_for_signed_jwks(nonexistent_path)
          expect(result).to be_nil
        end
      end

      it "raises SecurityError for path traversal attempts" do
        if defined?(Rails)
          expect { described_class.parse_for_signed_jwks("../../../etc/passwd") }
            .to raise_error(OmniauthOpenidFederation::SecurityError)
        end
      end

      it "raises ValidationError when parsing fails" do
        if defined?(Rails)
          # Create file in Rails config directory
          invalid_path = Rails.root.join("config", "invalid.jwt").to_s
          FileUtils.mkdir_p(File.dirname(invalid_path))
          File.write(invalid_path, "invalid jwt")

          expect { described_class.parse_for_signed_jwks(invalid_path) }
            .to raise_error(OmniauthOpenidFederation::ValidationError)
        end
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

        expect(OmniauthOpenidFederation::Logger).to receive(:warn).with(/Entity statement file not found/)
        result = described_class.parse_for_signed_jwks(nonexistent_path)
        expect(result).to be_nil

        FileUtils.rm_rf(config.root_path) if File.directory?(config.root_path)
        config.root_path = nil
      end

      it "logs error and raises ValidationError when parsing fails" do
        config = OmniauthOpenidFederation::Configuration.config
        config.root_path = Dir.mktmpdir

        # Create file in the allowed directory
        allowed_dir = File.join(config.root_path, "config")
        FileUtils.mkdir_p(allowed_dir) unless File.directory?(allowed_dir)
        file_path = File.join(allowed_dir, "invalid.jwt")
        File.write(file_path, "invalid jwt")

        expect(OmniauthOpenidFederation::Logger).to receive(:error).with(/Failed to parse entity statement/)
        expect {
          described_class.parse_for_signed_jwks(file_path)
        }.to raise_error(OmniauthOpenidFederation::ValidationError, /Failed to parse entity statement/)

        FileUtils.rm_rf(config.root_path) if File.directory?(config.root_path)
        config.root_path = nil
      end
    end
  end
end

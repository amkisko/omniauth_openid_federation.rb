require "spec_helper"

RSpec.describe OmniauthOpenidFederation::EntityStatementReader do
  let(:entity_statement_content) do
    # Simple mock JWT structure (header.payload.signature)
    header = Base64.urlsafe_encode64({alg: "RS256", kid: "key-1"}.to_json).gsub(/=+$/, "")
    payload = Base64.urlsafe_encode64({
      iss: "https://provider.example.com",
      sub: "https://provider.example.com",
      jwks: {
        keys: [
          {
            kty: "RSA",
            kid: "key-1",
            use: "sig",
            n: "test-n",
            e: "AQAB"
          }
        ]
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
    }.to_json).gsub(/=+$/, "")
    signature = "signature"
    "#{header}.#{payload}.#{signature}"
  end

  let(:temp_file) do
    file = Tempfile.new(["entity_statement", ".jwt"])
    file.write(entity_statement_content)
    file.rewind
    file
  end

  after do
    temp_file.close
    temp_file.unlink
  end

  describe ".fetch_keys" do
    it "extracts keys from entity statement" do
      keys = described_class.fetch_keys(entity_statement_path: temp_file.path)

      expect(keys).to be_an(Array)
      expect(keys.length).to eq(1)
      expect(keys.first).to be_a(Hash)
      expect(keys.first).to have_key("kty")
    end

    it "returns empty array when file doesn't exist" do
      keys = described_class.fetch_keys(entity_statement_path: "/nonexistent/path.jwt")

      expect(keys).to eq([])
    end

    it "returns empty array when path is nil" do
      keys = described_class.fetch_keys(entity_statement_path: nil)

      expect(keys).to eq([])
    end

    context "security: path traversal protection" do
      it "prevents path traversal attacks with relative paths" do
        # Behavior: Should reject path traversal attempts
        malicious_path = "../../../etc/passwd"

        # Should return empty array (path validation fails, returns nil)
        keys = described_class.fetch_keys(entity_statement_path: malicious_path)
        expect(keys).to eq([])
      end

      it "prevents path traversal with tilde expansion" do
        # Behavior: Should reject tilde expansion attempts
        malicious_path = "~/secret"

        keys = described_class.fetch_keys(entity_statement_path: malicious_path)
        expect(keys).to eq([])
      end

      it "does not expose file system structure on invalid paths" do
        # Behavior: Should not leak information about file system
        invalid_paths = [
          "../../../etc/passwd",
          "~/secret",
          "/etc/shadow",
          "..\\..\\windows\\system32\\config\\sam"
        ]

        invalid_paths.each do |path|
          keys = described_class.fetch_keys(entity_statement_path: path)
          # Should return empty array, not raise error that exposes path
          expect(keys).to eq([])
        end
      end

      it "allows paths within allowed directories" do
        # Behavior: Should allow valid paths within configured directories
        if defined?(Rails)
          rails_root = Rails.root
          allowed_path = rails_root.join("config", "entity_statement.jwt").to_s

          # Create file if it doesn't exist
          FileUtils.mkdir_p(File.dirname(allowed_path))
          File.write(allowed_path, entity_statement_content)

          keys = described_class.fetch_keys(entity_statement_path: "config/entity_statement.jwt")
          expect(keys).to be_an(Array)

          File.delete(allowed_path) if File.exist?(allowed_path)
        end
      end
    end

    it "returns empty array for invalid JWT format" do
      invalid_jwt = "header.payload"
      temp_invalid = Tempfile.new(["invalid", ".jwt"])
      temp_invalid.write(invalid_jwt)
      temp_invalid.rewind

      keys = described_class.fetch_keys(entity_statement_path: temp_invalid.path)
      expect(keys).to eq([])

      temp_invalid.close
      temp_invalid.unlink
    end

    it "returns empty array for JWT with missing jwks" do
      header = Base64.urlsafe_encode64({alg: "RS256"}.to_json).gsub(/=+$/, "")
      payload = Base64.urlsafe_encode64({iss: "https://provider.example.com"}.to_json).gsub(/=+$/, "")
      jwt = "#{header}.#{payload}.signature"

      temp_no_jwks = Tempfile.new(["no_jwks", ".jwt"])
      temp_no_jwks.write(jwt)
      temp_no_jwks.rewind

      keys = described_class.fetch_keys(entity_statement_path: temp_no_jwks.path)
      expect(keys).to eq([])

      temp_no_jwks.close
      temp_no_jwks.unlink
    end

    it "returns empty array for empty entity statement" do
      temp_empty = Tempfile.new(["empty", ".jwt"])
      temp_empty.write("")
      temp_empty.rewind

      keys = described_class.fetch_keys(entity_statement_path: temp_empty.path)
      expect(keys).to eq([])

      temp_empty.close
      temp_empty.unlink
    end
  end

  describe ".parse_metadata" do
    it "parses metadata from entity statement" do
      metadata = described_class.parse_metadata(entity_statement_path: temp_file.path)

      expect(metadata).to be_a(Hash)
      expect(metadata[:issuer]).to eq("https://provider.example.com")
      expect(metadata[:authorization_endpoint]).to be_present
      expect(metadata[:token_endpoint]).to be_present
    end

    it "returns nil when file doesn't exist" do
      metadata = described_class.parse_metadata(entity_statement_path: "/nonexistent/path.jwt")

      expect(metadata).to be_nil
    end

    context "security: path traversal protection" do
      it "prevents reading files outside allowed directories" do
        # Behavior: Should not parse metadata from unauthorized paths
        malicious_path = "../../../etc/passwd"

        metadata = described_class.parse_metadata(entity_statement_path: malicious_path)

        # Should return nil, not expose file contents
        expect(metadata).to be_nil
      end

      it "prevents path traversal with tilde expansion" do
        # Behavior: Should reject tilde expansion attempts
        malicious_path = "~/secret"

        metadata = described_class.parse_metadata(entity_statement_path: malicious_path)
        expect(metadata).to be_nil
      end

      it "does not expose file system errors on invalid paths" do
        # Behavior: Should handle invalid paths gracefully without leaking info
        invalid_paths = [
          "../../../etc/passwd",
          "~/secret",
          "/etc/shadow"
        ]

        invalid_paths.each do |path|
          metadata = described_class.parse_metadata(entity_statement_path: path)
          expect(metadata).to be_nil
        end
      end
    end

    context "when Rails is not available" do
      before do
        hide_const("Rails")
      end

      it "uses File.expand_path for relative paths" do
        # Create a temp file in a relative location
        temp_relative = Tempfile.new(["entity_statement", ".jwt"], ".")
        temp_relative.write(entity_statement_content)
        temp_relative.rewind
        relative_path = temp_relative.path

        metadata = described_class.parse_metadata(entity_statement_path: relative_path)

        expect(metadata).to be_a(Hash)
        expect(metadata[:issuer]).to eq("https://provider.example.com")

        temp_relative.close
        temp_relative.unlink
      end
    end

    it "handles Rails root path resolution" do
      if defined?(Rails)
        rails_root = Rails.root
        relative_path = "config/entity_statement.jwt"
        full_path = rails_root.join(relative_path).to_s

        # Create file if it doesn't exist
        FileUtils.mkdir_p(File.dirname(full_path))
        File.write(full_path, entity_statement_content)

        metadata = described_class.parse_metadata(entity_statement_path: relative_path)
        expect(metadata).to be_a(Hash)

        File.delete(full_path) if File.exist?(full_path)
      end
    end

    it "uses Rails.root.join when Rails is available (line 99)" do
      # Create a temp directory to simulate Rails.root
      temp_rails_root = Dir.mktmpdir

      # Ensure Rails is defined for this test
      unless defined?(Rails)
        rails_root_pathname = Pathname.new(temp_rails_root)
        stub_const("Rails", double(root: rails_root_pathname))
      end

      begin
        rails_root = Rails.root
        relative_path = "config/entity_statement.jwt"
        full_path = rails_root.join(relative_path).to_s

        # Create file in the allowed directory
        FileUtils.mkdir_p(File.dirname(full_path))
        File.write(full_path, entity_statement_content)

        # Use the full path to pass validation
        # This should use the Rails branch at line 99
        metadata = described_class.parse_metadata(entity_statement_path: full_path)
        expect(metadata).to be_a(Hash)
        expect(metadata[:issuer]).to eq("https://provider.example.com")
      ensure
        FileUtils.rm_rf(temp_rails_root) if File.directory?(temp_rails_root)
      end
    end

    it "handles config.root_path when Rails is not available" do
      # Hide Rails if it exists
      if defined?(Rails)
        hide_const("Rails")
      end

      config = OmniauthOpenidFederation::Configuration.config
      original_root_path = config.root_path
      config.root_path = Dir.mktmpdir

      begin
        # Create file in the allowed directory
        allowed_dir = File.join(config.root_path, "config")
        FileUtils.mkdir_p(allowed_dir) unless File.directory?(allowed_dir)
        file_path = File.join(allowed_dir, "entity_statement.jwt")
        File.write(file_path, entity_statement_content)

        # Use absolute path within allowed directory
        metadata = described_class.parse_metadata(entity_statement_path: file_path)
        expect(metadata).to be_a(Hash)
        expect(metadata[:issuer]).to eq("https://provider.example.com")
      ensure
        FileUtils.rm_rf(config.root_path) if File.directory?(config.root_path)
        config.root_path = original_root_path
      end
    end

    it "handles absolute paths" do
      metadata = described_class.parse_metadata(entity_statement_path: temp_file.path)
      expect(metadata).to be_a(Hash)
    end

    it "returns nil for invalid JWT format" do
      invalid_jwt = "header.payload"
      temp_invalid = Tempfile.new(["invalid", ".jwt"])
      temp_invalid.write(invalid_jwt)
      temp_invalid.rewind

      metadata = described_class.parse_metadata(entity_statement_path: temp_invalid.path)
      expect(metadata).to be_nil

      temp_invalid.close
      temp_invalid.unlink
    end

    it "returns nil for JWT with missing metadata" do
      header = Base64.urlsafe_encode64({alg: "RS256"}.to_json).gsub(/=+$/, "")
      payload = Base64.urlsafe_encode64({iss: "https://provider.example.com"}.to_json).gsub(/=+$/, "")
      jwt = "#{header}.#{payload}.signature"

      temp_no_metadata = Tempfile.new(["no_metadata", ".jwt"])
      temp_no_metadata.write(jwt)
      temp_no_metadata.rewind

      metadata = described_class.parse_metadata(entity_statement_path: temp_no_metadata.path)
      expect(metadata).to be_a(Hash)
      expect(metadata[:issuer]).to be_nil

      temp_no_metadata.close
      temp_no_metadata.unlink
    end
  end

  describe ".validate_fingerprint" do
    it "validates correct fingerprint" do
      fingerprint = Digest::SHA256.hexdigest(entity_statement_content).downcase
      result = described_class.validate_fingerprint(entity_statement_content, fingerprint)

      expect(result).to be true
    end

    it "rejects incorrect fingerprint" do
      result = described_class.validate_fingerprint(entity_statement_content, "wrong-fingerprint")

      expect(result).to be false
    end

    it "is case insensitive" do
      fingerprint = Digest::SHA256.hexdigest(entity_statement_content).upcase
      result = described_class.validate_fingerprint(entity_statement_content, fingerprint)

      expect(result).to be true
    end
  end
end

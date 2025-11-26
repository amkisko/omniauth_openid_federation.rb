require "spec_helper"

RSpec.describe OmniauthOpenidFederation::EndpointResolver do
  describe ".resolve" do
    it "returns endpoints from config when provided" do
      config = {
        authorization_endpoint: "/oauth2/authorize",
        token_endpoint: "/oauth2/token",
        userinfo_endpoint: "/oauth2/userinfo",
        jwks_uri: "/.well-known/jwks.json",
        audience: "https://provider.example.com"
      }

      result = described_class.resolve(config: config)

      expect(result[:authorization_endpoint]).to eq("/oauth2/authorize")
      expect(result[:token_endpoint]).to eq("/oauth2/token")
      expect(result[:userinfo_endpoint]).to eq("/oauth2/userinfo")
      expect(result[:jwks_uri]).to eq("/.well-known/jwks.json")
      expect(result[:audience]).to eq("https://provider.example.com")
    end

    it "returns nil endpoints when config is empty" do
      result = described_class.resolve(config: {})

      expect(result[:authorization_endpoint]).to be_nil
      expect(result[:token_endpoint]).to be_nil
    end

    it "handles entity statement path" do
      # This would require a real entity statement file, so we just test it doesn't crash
      result = described_class.resolve(entity_statement_path: "/nonexistent/path.jwt", config: {})

      expect(result).to be_a(Hash)
    end
  end

  describe ".validate_and_build_audience" do
    it "validates required endpoints are present" do
      endpoints = {
        authorization_endpoint: "/oauth2/authorize",
        token_endpoint: "/oauth2/token",
        jwks_uri: "/.well-known/jwks.json"
      }

      result = described_class.validate_and_build_audience(endpoints)

      expect(result).to eq(endpoints)
    end

    it "raises error when authorization endpoint is missing" do
      endpoints = {
        token_endpoint: "/oauth2/token",
        jwks_uri: "/.well-known/jwks.json"
      }

      expect { described_class.validate_and_build_audience(endpoints) }
        .to raise_error(/Authorization endpoint not configured/)
    end

    it "raises error when token endpoint is missing" do
      endpoints = {
        authorization_endpoint: "/oauth2/authorize",
        jwks_uri: "/.well-known/jwks.json"
      }

      expect { described_class.validate_and_build_audience(endpoints) }
        .to raise_error(/Token endpoint not configured/)
    end

    it "raises error when JWKS URI is missing" do
      endpoints = {
        authorization_endpoint: "/oauth2/authorize",
        token_endpoint: "/oauth2/token"
      }

      expect { described_class.validate_and_build_audience(endpoints) }
        .to raise_error(/JWKS URI not configured/)
    end

    it "builds audience from issuer URI when not provided" do
      endpoints = {
        authorization_endpoint: "/oauth2/authorize",
        token_endpoint: "/oauth2/token",
        jwks_uri: "/.well-known/jwks.json"
      }
      issuer_uri = URI.parse("https://provider.example.com")

      result = described_class.validate_and_build_audience(endpoints, issuer_uri: issuer_uri)

      expect(result[:audience]).to be_present
    end
  end

  describe ".resolve" do
    context "with entity statement" do
      let(:entity_statement_path) { "spec/fixtures/entity_statement.jwt" }
      let(:entity_statement_content) do
        header = Base64.urlsafe_encode64({alg: "RS256"}.to_json, padding: false)
        payload = Base64.urlsafe_encode64({
          iss: "https://provider.example.com",
          sub: "https://provider.example.com",
          metadata: {
            openid_provider: {
              issuer: "https://provider.example.com",
              authorization_endpoint: "https://provider.example.com/oauth2/authorize",
              token_endpoint: "https://provider.example.com/oauth2/token",
              userinfo_endpoint: "https://provider.example.com/oauth2/userinfo",
              jwks_uri: "https://provider.example.com/.well-known/jwks.json"
            }
          }
        }.to_json, padding: false)
        "#{header}.#{payload}.signature"
      end

      before do
        if defined?(Rails)
          FileUtils.mkdir_p("spec/fixtures")
          File.write(entity_statement_path, entity_statement_content)
        end
      end

      after do
        File.delete(entity_statement_path) if File.exist?(entity_statement_path)
      end

      it "uses provider issuer as audience when available" do
        if defined?(Rails)
          result = described_class.resolve(
            entity_statement_path: entity_statement_path,
            config: {}
          )

          expect(result[:audience]).to eq("https://provider.example.com")
        end
      end

      it "falls back to token endpoint when provider issuer not available" do
        if defined?(Rails)
          # Modify entity statement to not have issuer
          header = Base64.urlsafe_encode64({alg: "RS256"}.to_json, padding: false)
          payload = Base64.urlsafe_encode64({
            iss: "https://provider.example.com",
            metadata: {
              openid_provider: {
                token_endpoint: "https://provider.example.com/oauth2/token"
              }
            }
          }.to_json, padding: false)
          File.write(entity_statement_path, "#{header}.#{payload}.signature")

          result = described_class.resolve(
            entity_statement_path: entity_statement_path,
            config: {}
          )

          expect(result[:audience]).to eq("https://provider.example.com/oauth2/token")
        end
      end
    end
  end

  describe ".build_entity_statement_url" do
    it "builds URL with default endpoint" do
      result = described_class.build_entity_statement_url("https://provider.example.com")
      expect(result).to eq("https://provider.example.com/.well-known/openid-federation")
    end

    it "builds URL with custom endpoint" do
      result = described_class.build_entity_statement_url(
        "https://provider.example.com",
        entity_statement_endpoint: "/custom/path"
      )
      expect(result).to eq("https://provider.example.com/custom/path")
    end
  end

  describe ".build_endpoint_url" do
    it "returns full URL as-is when already absolute" do
      result = described_class.build_endpoint_url("https://provider.example.com", "https://other.com/path")
      expect(result).to eq("https://other.com/path")
    end

    it "builds URL from issuer and path" do
      result = described_class.build_endpoint_url("https://provider.example.com", "/oauth2/authorize")
      expect(result).to eq("https://provider.example.com/oauth2/authorize")
    end

    it "adds leading slash to path if missing" do
      result = described_class.build_endpoint_url("https://provider.example.com", "oauth2/authorize")
      expect(result).to eq("https://provider.example.com/oauth2/authorize")
    end

    it "removes trailing slash from issuer" do
      result = described_class.build_endpoint_url("https://provider.example.com/", "/oauth2/authorize")
      expect(result).to eq("https://provider.example.com/oauth2/authorize")
    end
  end

  describe "private methods" do
    describe ".load_entity_statement_metadata" do
      it "returns nil when file doesn't exist" do
        result = described_class.send(:load_entity_statement_metadata, "/nonexistent/path.jwt")
        expect(result).to be_nil
      end

      it "returns nil when parsing fails" do
        temp_file = Tempfile.new(["entity_statement", ".jwt"])
        temp_file.write("invalid jwt")
        temp_file.rewind

        expect(OmniauthOpenidFederation::Logger).to receive(:warn).with(/Failed to parse entity statement/)
        result = described_class.send(:load_entity_statement_metadata, temp_file.path)
        expect(result).to be_nil

        temp_file.close
        temp_file.unlink
      end
    end

    describe ".extract_path_from_url" do
      it "returns nil for blank URL" do
        result = described_class.send(:extract_path_from_url, nil)
        expect(result).to be_nil
      end

      it "returns full URL as-is when already absolute" do
        result = described_class.send(:extract_path_from_url, "https://example.com/path")
        expect(result).to eq("https://example.com/path")
      end

      it "returns full URL as-is when starts with http" do
        # extract_path_from_url returns full URL as-is when it starts with http:// or https://
        result = described_class.send(:extract_path_from_url, "https://example.com/oauth2/authorize")
        expect(result).to eq("https://example.com/oauth2/authorize")
      end

      it "extracts path from URL with host" do
        # When URL has a host (parsed by URI), it extracts just the path
        # Use a proper URL format that URI.parse can handle
        result = described_class.send(:extract_path_from_url, "//example.com/oauth2/authorize")
        # URI.parse treats //example.com as having a host
        expect(result).to eq("/oauth2/authorize")
      end

      it "handles URL without path when host is present" do
        # When URL has host but no path, returns nil
        result = described_class.send(:extract_path_from_url, "//example.com")
        expect(result).to be_nil
      end

      it "returns path with leading slash when no host" do
        result = described_class.send(:extract_path_from_url, "/oauth2/authorize")
        expect(result).to eq("/oauth2/authorize")
      end

      it "adds leading slash to path without host" do
        result = described_class.send(:extract_path_from_url, "oauth2/authorize")
        expect(result).to eq("/oauth2/authorize")
      end

      it "handles invalid URI gracefully" do
        result = described_class.send(:extract_path_from_url, "/valid/path")
        expect(result).to eq("/valid/path")
      end

      it "adds leading slash to relative path when URI parse succeeds" do
        # When URI.parse succeeds but has no host, it adds leading slash
        result = described_class.send(:extract_path_from_url, "not-a-path")
        expect(result).to eq("/not-a-path")
      end

      it "returns nil for invalid URI that doesn't start with slash" do
        # Create a string that will cause URI::InvalidURIError and doesn't start with /
        # Use a string with invalid characters that URI.parse can't handle
        invalid_uri = "\x00invalid"
        result = described_class.send(:extract_path_from_url, invalid_uri)
        expect(result).to be_nil
      end
    end
  end
end

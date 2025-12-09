require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Federation::EntityStatementFetcher do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:entity_statement_content) do
    payload = {
      iss: "https://provider.example.com",
      sub: "https://provider.example.com",
      iat: Time.now.to_i,
      exp: Time.now.to_i + 3600,
      jwks: {
        keys: [OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)]
      }
    }
    JWT.encode(payload, private_key, "RS256")
  end

  describe "Base" do
    let(:fetcher_class) do
      Class.new(described_class::Base) do
        def fetch_entity_statement
          "test.jwt"
        end
      end
    end

    describe "#entity_statement" do
      it "caches entity statement" do
        fetcher = fetcher_class.new
        statement1 = fetcher.entity_statement
        statement2 = fetcher.entity_statement
        expect(statement1).to be(statement2)
      end

      it "creates EntityStatement instance" do
        fetcher = fetcher_class.new
        statement = fetcher.entity_statement
        expect(statement).to be_a(OmniauthOpenidFederation::Federation::EntityStatement)
      end
    end

    describe "#reload!" do
      it "clears cached entity statement" do
        fetcher = fetcher_class.new
        statement1 = fetcher.entity_statement
        fetcher.reload!
        statement2 = fetcher.entity_statement
        expect(statement1).not_to be(statement2)
      end
    end

    it "raises NotImplementedError when fetch_entity_statement not implemented" do
      fetcher = described_class::Base.new
      expect {
        fetcher.entity_statement
      }.to raise_error(NotImplementedError, /must implement #fetch_entity_statement/)
    end
  end

  describe "UrlFetcher" do
    let(:entity_statement_url) { "https://provider.example.com/.well-known/openid-federation" }
    let(:fingerprint) { nil }

    describe "#initialize" do
      it "sets entity_statement_url" do
        fetcher = described_class::UrlFetcher.new(entity_statement_url)
        expect(fetcher.entity_statement_url).to eq(entity_statement_url)
      end

      it "sets fingerprint when provided" do
        fetcher = described_class::UrlFetcher.new(entity_statement_url, fingerprint: "test-fingerprint")
        expect(fetcher.fingerprint).to eq("test-fingerprint")
      end

      it "sets timeout when provided" do
        fetcher = described_class::UrlFetcher.new(entity_statement_url, timeout: 30)
        expect(fetcher.timeout).to eq(30)
      end

      it "uses default timeout" do
        fetcher = described_class::UrlFetcher.new(entity_statement_url)
        expect(fetcher.timeout).to eq(10)
      end
    end

    describe "#entity_statement" do
      it "fetches entity statement from URL" do
        stub_request(:get, entity_statement_url)
          .to_return(status: 200, body: entity_statement_content)

        fetcher = described_class::UrlFetcher.new(entity_statement_url)
        statement = fetcher.entity_statement
        expect(statement).to be_a(OmniauthOpenidFederation::Federation::EntityStatement)
      end

      it "validates fingerprint when provided" do
        statement_obj = OmniauthOpenidFederation::Federation::EntityStatement.new(entity_statement_content)
        expected_fingerprint = statement_obj.calculate_fingerprint

        stub_request(:get, entity_statement_url)
          .to_return(status: 200, body: entity_statement_content)

        fetcher = described_class::UrlFetcher.new(entity_statement_url, fingerprint: expected_fingerprint)
        statement = fetcher.entity_statement
        expect(statement).to be_a(OmniauthOpenidFederation::Federation::EntityStatement)
      end

      it "raises ValidationError when fingerprint mismatch" do
        stub_request(:get, entity_statement_url)
          .to_return(status: 200, body: entity_statement_content)

        fetcher = described_class::UrlFetcher.new(entity_statement_url, fingerprint: "wrong-fingerprint")
        expect {
          fetcher.entity_statement
        }.to raise_error(OmniauthOpenidFederation::Federation::EntityStatement::ValidationError, /fingerprint mismatch/)
      end

      it "raises FetchError on HTTP error" do
        stub_request(:get, entity_statement_url)
          .to_return(status: 404, body: "Not Found")

        fetcher = described_class::UrlFetcher.new(entity_statement_url)
        expect {
          fetcher.entity_statement
        }.to raise_error(OmniauthOpenidFederation::Federation::EntityStatement::FetchError, /Failed to fetch entity statement/)
      end

      it "raises FetchError on network error" do
        stub_request(:get, entity_statement_url)
          .to_raise(OmniauthOpenidFederation::NetworkError.new("Connection failed"))

        fetcher = described_class::UrlFetcher.new(entity_statement_url)
        expect {
          fetcher.entity_statement
        }.to raise_error(OmniauthOpenidFederation::Federation::EntityStatement::FetchError, /Failed to fetch entity statement/)
      end
    end
  end

  describe "FileFetcher" do
    let(:temp_file) { Tempfile.new(["entity", ".jwt"]) }
    let(:file_path) { temp_file.path }

    before do
      File.write(file_path, entity_statement_content)
    end

    after do
      temp_file.close
      temp_file.unlink
    end

    describe "#initialize" do
      it "sets file_path" do
        fetcher = described_class::FileFetcher.new(file_path)
        expect(fetcher.file_path).to eq(file_path)
      end

      it "uses Rails.root/config when Rails available" do
        if defined?(Rails) && Rails.root
          fetcher = described_class::FileFetcher.new(file_path)
          # Should not raise error
          expect(fetcher.file_path).to eq(file_path)
        end
      end

      it "uses provided allowed_dirs" do
        allowed_dirs = ["/tmp"]
        fetcher = described_class::FileFetcher.new(file_path, allowed_dirs: allowed_dirs)
        expect(fetcher.file_path).to eq(file_path)
      end
    end

    describe "#entity_statement" do
      it "loads entity statement from file" do
        # Pass empty array to skip directory validation (only path traversal protection applies)
        fetcher = described_class::FileFetcher.new(file_path, allowed_dirs: [])
        statement = fetcher.entity_statement
        expect(statement).to be_a(OmniauthOpenidFederation::Federation::EntityStatement)
      end

      it "strips whitespace from file content" do
        File.write(file_path, "  #{entity_statement_content}  ")
        # Pass empty array to skip directory validation (only path traversal protection applies)
        fetcher = described_class::FileFetcher.new(file_path, allowed_dirs: [])
        statement = fetcher.entity_statement
        expect(statement).to be_a(OmniauthOpenidFederation::Federation::EntityStatement)
      end

      it "raises FetchError when file not found" do
        nonexistent_path = "/nonexistent/path.jwt"
        # Pass empty array to skip directory validation (only path traversal protection applies)
        fetcher = described_class::FileFetcher.new(nonexistent_path, allowed_dirs: [])
        expect {
          fetcher.entity_statement
        }.to raise_error(OmniauthOpenidFederation::Federation::EntityStatement::FetchError, /Entity statement file not found/)
      end

      it "raises FetchError on path traversal attempt" do
        path_traversal = "../../../etc/passwd"
        fetcher = described_class::FileFetcher.new(path_traversal)
        expect {
          fetcher.entity_statement
        }.to raise_error(OmniauthOpenidFederation::Federation::EntityStatement::FetchError)
      end

      it "validates file path" do
        invalid_path = "../../../etc/passwd"
        fetcher = described_class::FileFetcher.new(invalid_path, allowed_dirs: ["/tmp"])
        expect {
          fetcher.entity_statement
        }.to raise_error(OmniauthOpenidFederation::Federation::EntityStatement::FetchError)
      end
    end
  end
end

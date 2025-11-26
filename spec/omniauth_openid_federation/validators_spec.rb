require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Validators do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:private_key_pem) { private_key.to_pem }

  describe ".validate_private_key!" do
    it "passes validation for valid RSA key object" do
      expect { described_class.validate_private_key!(private_key) }.not_to raise_error
    end

    it "passes validation for valid PEM string" do
      expect { described_class.validate_private_key!(private_key_pem) }.not_to raise_error
    end

    it "raises ConfigurationError for nil" do
      expect { described_class.validate_private_key!(nil) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /Private key is required for signed request objects/)
    end

    it "raises ConfigurationError for invalid PEM string" do
      expect { described_class.validate_private_key!("invalid key") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /Invalid private key format/)
    end

    it "raises ConfigurationError for non-RSA key object" do
      expect { described_class.validate_private_key!(Object.new) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /Private key must be an OpenSSL::PKey::RSA/)
    end
  end

  describe ".validate_uri!" do
    it "passes validation for valid HTTP URI" do
      expect { described_class.validate_uri!("http://example.com", required: true) }.not_to raise_error
    end

    it "passes validation for valid HTTPS URI" do
      expect { described_class.validate_uri!("https://example.com", required: true) }.not_to raise_error
    end

    it "raises ConfigurationError for invalid URI" do
      expect { described_class.validate_uri!("not a uri", required: true) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /Invalid URI format/)
    end

    it "raises ConfigurationError for non-HTTP/HTTPS URI" do
      expect { described_class.validate_uri!("ftp://example.com", required: true) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /URI must be HTTP or HTTPS/)
    end

    it "raises ConfigurationError when required and blank" do
      expect { described_class.validate_uri!(nil, required: true) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /URI is required/)
    end

    it "returns false when not required and blank" do
      expect(described_class.validate_uri!(nil, required: false)).to be false
    end
  end

  describe ".validate_file_path!" do
    let(:temp_file) { Tempfile.new(["test", ".txt"]) }
    let(:file_path) { temp_file.path }

    after do
      temp_file.close
      temp_file.unlink
    end

    it "passes validation for existing file" do
      expect { described_class.validate_file_path!(file_path, required: true) }.not_to raise_error
    end

    it "raises ConfigurationError when required and file doesn't exist" do
      expect { described_class.validate_file_path!("/nonexistent/file.txt", required: true) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /File not found/)
    end

    it "raises ConfigurationError when required and path is blank" do
      expect { described_class.validate_file_path!(nil, required: true) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /File path is required/)
    end

    it "returns false when not required and file doesn't exist" do
      expect(described_class.validate_file_path!("/nonexistent/file.txt", required: false)).to be false
    end

    it "returns false when not required and path is blank" do
      expect(described_class.validate_file_path!(nil, required: false)).to be false
    end
  end

  describe ".validate_client_options!" do
    let(:valid_options) do
      {
        identifier: "client-id",
        redirect_uri: "https://example.com/callback",
        private_key: private_key
      }
    end

    it "passes validation for valid options" do
      result = described_class.validate_client_options!(valid_options)
      expect(result).to be_a(Hash)
      expect(result[:identifier]).to eq("client-id")
    end

    it "normalizes hash keys to symbols" do
      options = {
        "identifier" => "client-id",
        "redirect_uri" => "https://example.com/callback",
        "private_key" => private_key
      }

      result = described_class.validate_client_options!(options)
      expect(result[:identifier]).to eq("client-id")
      expect(result["identifier"]).to be_nil
    end

    it "raises ConfigurationError when identifier is missing" do
      options = valid_options.dup
      options.delete(:identifier)

      expect { described_class.validate_client_options!(options) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /Client identifier is required/)
    end

    it "raises ConfigurationError when redirect_uri is missing" do
      options = valid_options.dup
      options.delete(:redirect_uri)

      expect { described_class.validate_client_options!(options) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /Redirect URI is required/)
    end

    it "raises ConfigurationError when private_key is missing" do
      options = valid_options.dup
      options.delete(:private_key)

      expect { described_class.validate_client_options!(options) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /Private key is required/)
    end

    it "raises ConfigurationError for invalid redirect_uri format" do
      options = valid_options.dup
      options[:redirect_uri] = "not a uri"

      expect { described_class.validate_client_options!(options) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /Invalid URI format/)
    end

    it "validates endpoint formats when provided" do
      options = valid_options.dup
      options[:authorization_endpoint] = "invalid-endpoint"

      expect { described_class.validate_client_options!(options) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /Invalid endpoint format/)
    end

    it "allows valid endpoint paths" do
      options = valid_options.dup
      options[:authorization_endpoint] = "/oauth2/authorize"

      result = described_class.validate_client_options!(options)
      expect(result).to be_a(Hash)
    end

    it "allows valid endpoint URLs" do
      options = valid_options.dup
      options[:authorization_endpoint] = "https://example.com/oauth2/authorize"

      result = described_class.validate_client_options!(options)
      expect(result).to be_a(Hash)
    end
  end

  describe ".normalize_hash" do
    it "converts string keys to symbols" do
      hash = {"key" => "value", "another" => "value2"}
      result = described_class.normalize_hash(hash)

      expect(result[:key]).to eq("value")
      expect(result[:another]).to eq("value2")
      expect(result["key"]).to be_nil
    end

    it "preserves symbol keys" do
      hash = {key: "value", another: "value2"}
      result = described_class.normalize_hash(hash)

      expect(result[:key]).to eq("value")
      expect(result[:another]).to eq("value2")
    end

    it "handles mixed string and symbol keys" do
      hash = {"key" => "value", :another => "value2"}
      result = described_class.normalize_hash(hash)

      expect(result[:key]).to eq("value")
      expect(result[:another]).to eq("value2")
    end

    it "returns empty hash for nil" do
      expect(described_class.normalize_hash(nil)).to eq({})
    end

    it "handles empty hash" do
      expect(described_class.normalize_hash({})).to eq({})
    end
  end
end

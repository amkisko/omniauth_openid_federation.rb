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
      expect { described_class.validate_uri!("file:///path/to/file", required: true) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /URI must be HTTP or HTTPS/)
    end

    it "raises SecurityError when URI is not HTTP or HTTPS instance" do
      uri_object = URI.parse("http://example.com")
      allow(uri_object).to receive(:is_a?).and_call_original
      allow(uri_object).to receive(:is_a?).with(URI::HTTP).and_return(false)
      allow(uri_object).to receive(:is_a?).with(URI::HTTPS).and_return(false)
      allow(URI).to receive(:parse).and_return(uri_object)
      allow(uri_object).to receive(:scheme).and_return("http")

      expect { described_class.validate_uri_safe!("http://example.com") }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /URI must be HTTP or HTTPS/)
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
      aggregate_failures do
        expect(result).to be_a(Hash)
        expect(result[:identifier]).to eq("client-id")
      end
    end

    it "normalizes hash keys to symbols" do
      options = {
        "identifier" => "client-id",
        "redirect_uri" => "https://example.com/callback",
        "private_key" => private_key
      }

      result = described_class.validate_client_options!(options)
      aggregate_failures do
        expect(result[:identifier]).to eq("client-id")
        expect(result["identifier"]).to be_nil
      end
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
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /Invalid redirect URI format/)
    end

    it "raises ConfigurationError for redirect_uri that is not HTTP/HTTPS" do
      options = valid_options.dup
      options[:redirect_uri] = "file:///path/to/file"

      expect { described_class.validate_client_options!(options) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /Redirect URI must be HTTP or HTTPS/)
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

      aggregate_failures do
        expect(result[:key]).to eq("value")
        expect(result[:another]).to eq("value2")
        expect(result["key"]).to be_nil
      end
    end

    it "preserves symbol keys" do
      hash = {key: "value", another: "value2"}
      result = described_class.normalize_hash(hash)

      aggregate_failures do
        expect(result[:key]).to eq("value")
        expect(result[:another]).to eq("value2")
      end
    end

    it "handles mixed string and symbol keys" do
      hash = {"key" => "value", :another => "value2"}
      result = described_class.normalize_hash(hash)

      aggregate_failures do
        expect(result[:key]).to eq("value")
        expect(result[:another]).to eq("value2")
      end
    end

    it "returns empty hash for nil" do
      expect(described_class.normalize_hash(nil)).to eq({})
    end

    it "handles empty hash" do
      expect(described_class.normalize_hash({})).to eq({})
    end
  end

  describe ".sanitize_request_param" do
    it "returns nil for nil input" do
      expect(described_class.sanitize_request_param(nil)).to be_nil
    end

    it "strips whitespace and returns sanitized string" do
      expect(described_class.sanitize_request_param("  test  ")).to eq("test")
    end

    it "returns nil for strings exceeding max_length" do
      long_string = "a" * 9000
      expect(described_class.sanitize_request_param(long_string)).to be_nil
    end

    it "removes control characters by default" do
      expect(described_class.sanitize_request_param("test\x00\x01string")).to eq("teststring")
    end

    it "allows control characters when allow_control_chars is true" do
      expect(described_class.sanitize_request_param("test\x00string", allow_control_chars: true)).to eq("test\x00string")
    end

    it "returns nil for empty string after sanitization" do
      expect(described_class.sanitize_request_param("   ")).to be_nil
    end

    it "uses custom max_length when provided" do
      expect(described_class.sanitize_request_param("a" * 100, max_length: 50)).to be_nil
    end
  end

  describe ".validate_uri_safe!" do
    it "raises SecurityError for nil" do
      expect { described_class.validate_uri_safe!(nil) }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /URI cannot be nil/)
    end

    it "raises SecurityError for empty string" do
      expect { described_class.validate_uri_safe!("") }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /URI cannot be empty/)
    end

    it "raises SecurityError for URI exceeding max_length" do
      long_uri = "https://example.com/" + "a" * 9000
      expect { described_class.validate_uri_safe!(long_uri) }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /exceeds maximum length/)
    end

    it "raises SecurityError for URIs with invalid characters" do
      invalid_uri = "https://example.com/test" + [0].pack("C")
      aggregate_failures do
        expect(invalid_uri.bytes.include?(0)).to be true
        expect { described_class.validate_uri_safe!(invalid_uri) }
          .to raise_error(OmniauthOpenidFederation::SecurityError, /contains invalid characters/)
      end
    end

    it "raises SecurityError for invalid URI format" do
      expect { described_class.validate_uri_safe!("not a valid uri") }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /Invalid URI format/)
    end

    it "raises SecurityError for invalid scheme" do
      expect { described_class.validate_uri_safe!("ftp://example.com") }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /URI scheme must be one of/)
    end

    it "raises SecurityError for URI without host" do
      expect { described_class.validate_uri_safe!("http://") }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /URI host cannot be empty/)
    end

    it "passes validation for valid HTTPS URI" do
      result = described_class.validate_uri_safe!("https://example.com")
      expect(result).to be_a(URI::HTTPS)
    end

    it "passes validation for valid HTTP URI" do
      result = described_class.validate_uri_safe!("http://example.com")
      expect(result).to be_a(URI::HTTP)
    end

    it "strips whitespace from URI" do
      result = described_class.validate_uri_safe!("  https://example.com  ")
      expect(result.to_s).to eq("https://example.com")
    end

    it "uses custom max_length when provided" do
      long_uri = "https://example.com/" + "a" * 100
      expect { described_class.validate_uri_safe!(long_uri, max_length: 50) }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /exceeds maximum length/)
    end

    it "validates scheme case-insensitively" do
      result = described_class.validate_uri_safe!("HTTPS://example.com")
      expect(result).to be_a(URI::HTTPS)
    end

    it "raises SecurityError for URI that parses but is not HTTP/HTTPS" do
      expect { described_class.validate_uri_safe!("file:///path") }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /URI scheme must be one of/)
    end
  end

  describe ".normalize_acr_values" do
    it "returns nil for nil input" do
      expect(described_class.normalize_acr_values(nil)).to be_nil
    end

    it "returns nil for blank string" do
      expect(described_class.normalize_acr_values("")).to be_nil
    end

    it "normalizes array of ACR values" do
      result = described_class.normalize_acr_values(["acr1", "acr2"])
      expect(result).to eq("acr1 acr2")
    end

    it "normalizes space-separated string" do
      result = described_class.normalize_acr_values("acr1 acr2 acr3")
      expect(result).to eq("acr1 acr2 acr3")
    end

    it "strips whitespace from values" do
      result = described_class.normalize_acr_values("  acr1  acr2  ")
      expect(result).to eq("acr1 acr2")
    end

    it "filters out blank values" do
      result = described_class.normalize_acr_values(["acr1", "", "acr2", " "])
      expect(result).to eq("acr1 acr2")
    end

    it "returns nil for empty array" do
      expect(described_class.normalize_acr_values([])).to be_nil
    end

    it "returns nil when all values are blank" do
      expect(described_class.normalize_acr_values(["", " ", "  "])).to be_nil
    end

    it "returns nil for result exceeding max_length" do
      long_values = ["a" * 5000, "b" * 5000]
      expect(described_class.normalize_acr_values(long_values)).to be_nil
    end

    it "skips sanitization when skip_sanitization is true" do
      result = described_class.normalize_acr_values("acr1 acr2", skip_sanitization: true)
      expect(result).to eq("acr1 acr2")
    end

    it "handles non-string, non-array input" do
      result = described_class.normalize_acr_values(123)
      expect(result).to eq("123")
    end

    it "returns nil for non-string input exceeding max_length" do
      long_input = "a" * 9000
      expect(described_class.normalize_acr_values(long_input)).to be_nil
    end
  end

  describe ".validate_client_id!" do
    it "raises ConfigurationError for nil" do
      expect { described_class.validate_client_id!(nil) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /client_id is REQUIRED/)
    end

    it "raises ConfigurationError for blank string" do
      expect { described_class.validate_client_id!("") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /client_id is REQUIRED/)
    end

    it "raises ConfigurationError for whitespace-only string" do
      expect { described_class.validate_client_id!("   ") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /cannot be empty after trimming|is REQUIRED/)
    end

    it "raises ConfigurationError for invalid characters" do
      allow(described_class).to receive(:sanitize_request_param).and_return(nil)
      expect { described_class.validate_client_id!("test") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /contains invalid characters/)
    end

    it "returns sanitized client_id for valid input" do
      result = described_class.validate_client_id!("  test-client-id  ")
      expect(result).to eq("test-client-id")
    end

    it "handles non-string input" do
      result = described_class.validate_client_id!(12345)
      expect(result).to eq("12345")
    end

    it "raises ConfigurationError when sanitized client_id is empty" do
      allow(described_class).to receive(:sanitize_request_param).and_return("")
      expect { described_class.validate_client_id!("test") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /contains invalid characters/)
    end

    it "raises ConfigurationError when client_id becomes empty after trimming" do
      obj = Object.new
      def obj.to_s
        "   "
      end
      allow(OmniauthOpenidFederation::StringHelpers).to receive(:blank?).with(obj).and_return(false)

      expect { described_class.validate_client_id!(obj) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /client_id cannot be empty after trimming/)
    end
  end

  describe ".validate_redirect_uri!" do
    it "raises ConfigurationError for nil" do
      expect { described_class.validate_redirect_uri!(nil) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /redirect_uri is REQUIRED/)
    end

    it "raises ConfigurationError for blank string" do
      expect { described_class.validate_redirect_uri!("") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /redirect_uri is REQUIRED/)
    end

    it "raises ConfigurationError for whitespace-only string" do
      expect { described_class.validate_redirect_uri!("   ") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /cannot be empty after trimming|is REQUIRED/)
    end

    it "raises ConfigurationError for invalid URI" do
      expect { described_class.validate_redirect_uri!("not a uri") }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /Invalid URI format/)
    end

    it "returns validated redirect_uri for valid HTTPS URI" do
      result = described_class.validate_redirect_uri!("https://example.com/callback")
      expect(result).to eq("https://example.com/callback")
    end

    it "strips whitespace from redirect_uri" do
      result = described_class.validate_redirect_uri!("  https://example.com/callback  ")
      expect(result).to eq("https://example.com/callback")
    end

    it "raises ConfigurationError when redirect_uri becomes empty after trimming" do
      expect { described_class.validate_redirect_uri!("   ") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /cannot be empty after trimming|is REQUIRED/)
    end
  end

  describe ".validate_scope!" do
    it "raises ConfigurationError for nil when require_openid is true" do
      expect { described_class.validate_scope!(nil) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /scope is REQUIRED/)
    end

    it "returns nil for nil when require_openid is false" do
      expect(described_class.validate_scope!(nil, require_openid: false)).to be_nil
    end

    it "normalizes array of scopes" do
      result = described_class.validate_scope!(["openid", "profile", "email"])
      expect(result).to eq("openid profile email")
    end

    it "normalizes space-separated string" do
      result = described_class.validate_scope!("openid profile email")
      expect(result).to eq("openid profile email")
    end

    it "raises ConfigurationError when openid scope is missing" do
      expect { described_class.validate_scope!("profile email") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /MUST include 'openid'/)
    end

    it "passes validation when openid scope is present" do
      result = described_class.validate_scope!("openid profile")
      expect(result).to eq("openid profile")
    end

    it "passes validation when require_openid is false and openid is missing" do
      result = described_class.validate_scope!("profile email", require_openid: false)
      expect(result).to eq("profile email")
    end

    it "strips whitespace from scopes" do
      result = described_class.validate_scope!("  openid  profile  ")
      expect(result).to eq("openid profile")
    end

    it "filters out blank scopes" do
      result = described_class.validate_scope!(["openid", "", "profile", " "])
      expect(result).to eq("openid profile")
    end

    it "raises ConfigurationError for empty scope after validation" do
      expect { described_class.validate_scope!(["", " "]) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /cannot be empty after validation/)
    end

    it "raises ConfigurationError for scope exceeding max_length" do
      max_length = OmniauthOpenidFederation::Configuration.config.max_string_length
      long_scope_value = "a" * (max_length - 5)
      expect { described_class.validate_scope!(["openid", long_scope_value]) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /exceeds maximum length/)
    end

    it "handles non-string, non-array input" do
      result = described_class.validate_scope!(12345, require_openid: false)
      expect(result).to eq("12345")
    end

    it "raises ConfigurationError when scope result exceeds max_length after joining" do
      max_length = OmniauthOpenidFederation::Configuration.config.max_string_length
      long_scope_value = "a" * (max_length / 2)
      scopes = ["openid", long_scope_value, long_scope_value]
      expect { described_class.validate_scope!(scopes) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /exceeds maximum length/)
    end
  end

  describe ".validate_state!" do
    it "raises ConfigurationError for nil" do
      expect { described_class.validate_state!(nil) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /state is REQUIRED/)
    end

    it "raises ConfigurationError for blank string" do
      expect { described_class.validate_state!("") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /state is REQUIRED/)
    end

    it "raises ConfigurationError for whitespace-only string" do
      expect { described_class.validate_state!("   ") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /cannot be empty after trimming|is REQUIRED/)
    end

    it "raises ConfigurationError for invalid characters" do
      allow(described_class).to receive(:sanitize_request_param).and_return(nil)
      expect { described_class.validate_state!("test") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /contains invalid characters/)
    end

    it "returns sanitized state for valid input" do
      result = described_class.validate_state!("  test-state-123  ")
      expect(result).to eq("test-state-123")
    end

    it "handles non-string input" do
      result = described_class.validate_state!(12345)
      expect(result).to eq("12345")
    end

    it "raises ConfigurationError when state becomes empty after trimming" do
      expect { described_class.validate_state!("   ") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /cannot be empty after trimming|is REQUIRED/)
    end

    it "raises ConfigurationError when sanitized state is empty" do
      allow(described_class).to receive(:sanitize_request_param).and_return("")
      expect { described_class.validate_state!("test") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /contains invalid characters/)
    end
  end

  describe ".validate_nonce" do
    it "returns nil for nil input" do
      expect(described_class.validate_nonce(nil)).to be_nil
    end

    it "returns nil for blank string when not required" do
      expect(described_class.validate_nonce("")).to be_nil
    end

    it "raises ConfigurationError for blank string when required" do
      expect { described_class.validate_nonce("", required: true) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /nonce is REQUIRED/)
    end

    it "raises ConfigurationError for whitespace-only string when required" do
      expect { described_class.validate_nonce("   ", required: true) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /is empty after trimming/)
    end

    it "raises ConfigurationError for invalid characters when required" do
      allow(described_class).to receive(:sanitize_request_param).and_return(nil)
      expect { described_class.validate_nonce("test", required: true) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /contains invalid characters/)
    end

    it "returns nil for invalid characters when not required" do
      result = described_class.validate_nonce("test\x00string")
      expect(result).to eq("teststring")
    end

    it "returns sanitized nonce for valid input" do
      result = described_class.validate_nonce("  test-nonce-123  ")
      expect(result).to eq("test-nonce-123")
    end

    it "handles non-string input" do
      result = described_class.validate_nonce(12345)
      expect(result).to eq("12345")
    end

    it "returns nil when sanitized nonce is empty and not required" do
      allow(described_class).to receive(:sanitize_request_param).and_return("")
      expect(described_class.validate_nonce("test")).to be_nil
    end
  end

  describe ".validate_response_type!" do
    it "raises ConfigurationError for nil" do
      expect { described_class.validate_response_type!(nil) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /response_type is REQUIRED/)
    end

    it "raises ConfigurationError for blank string" do
      expect { described_class.validate_response_type!("") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /response_type is REQUIRED/)
    end

    it "raises ConfigurationError for whitespace-only string" do
      expect { described_class.validate_response_type!("   ") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /cannot be empty after trimming|is REQUIRED/)
    end

    it "raises ConfigurationError for invalid characters" do
      allow(described_class).to receive(:sanitize_request_param).and_return(nil)
      expect { described_class.validate_response_type!("test") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /contains invalid characters/)
    end

    it "raises ConfigurationError for invalid response type" do
      expect { described_class.validate_response_type!("Code123") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /contains invalid value/)
    end

    it "passes validation for valid response type 'code'" do
      result = described_class.validate_response_type!("code")
      expect(result).to eq("code")
    end

    it "passes validation for valid response type 'id_token'" do
      result = described_class.validate_response_type!("id_token")
      expect(result).to eq("id_token")
    end

    it "passes validation for valid response type 'code id_token'" do
      result = described_class.validate_response_type!("code id_token")
      expect(result).to eq("code id_token")
    end

    it "passes validation for custom response type matching pattern" do
      result = described_class.validate_response_type!("custom_type")
      expect(result).to eq("custom_type")
    end

    it "strips whitespace from response_type" do
      result = described_class.validate_response_type!("  code  ")
      expect(result).to eq("code")
    end

    it "handles non-string input" do
      expect { described_class.validate_response_type!(12345) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /contains invalid value/)
    end

    it "raises ConfigurationError when response_type becomes empty after trimming" do
      expect { described_class.validate_response_type!("   ") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /cannot be empty after trimming|is REQUIRED/)
    end

    it "raises ConfigurationError when sanitized response_type is empty" do
      allow(described_class).to receive(:sanitize_request_param).and_return("")
      expect { described_class.validate_response_type!("code") }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /contains invalid characters/)
    end

    it "raises ConfigurationError when response_type object becomes empty after trimming" do
      obj = Object.new
      def obj.to_s
        "   "
      end
      allow(OmniauthOpenidFederation::StringHelpers).to receive(:blank?).with(obj).and_return(false)

      expect { described_class.validate_response_type!(obj) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /response_type cannot be empty after trimming/)
    end
  end

  describe ".validate_entity_identifier!" do
    it "raises SecurityError for nil" do
      expect { described_class.validate_entity_identifier!(nil) }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /Entity identifier cannot be nil or empty/)
    end

    it "raises SecurityError for blank string" do
      expect { described_class.validate_entity_identifier!("") }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /Entity identifier cannot be nil or empty/)
    end

    it "raises SecurityError for whitespace-only string" do
      expect { described_class.validate_entity_identifier!("   ") }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /Entity identifier cannot be nil or empty/)
    end

    it "raises SecurityError for invalid URI" do
      expect { described_class.validate_entity_identifier!("not a uri") }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /Invalid URI format/)
    end

    it "returns validated entity identifier for valid HTTPS URI" do
      result = described_class.validate_entity_identifier!("https://example.com")
      expect(result).to eq("https://example.com")
    end

    it "strips whitespace from entity identifier" do
      result = described_class.validate_entity_identifier!("  https://example.com  ")
      expect(result).to eq("https://example.com")
    end

    it "uses custom max_length when provided" do
      long_uri = "https://example.com/" + "a" * 2100
      expect { described_class.validate_entity_identifier!(long_uri, max_length: 2048) }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /exceeds maximum length/)
    end

    it "handles non-string input" do
      expect { described_class.validate_entity_identifier!(12345) }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /URI scheme must be one of|Invalid URI format/)
    end

    it "raises SecurityError when entity_id becomes empty after trimming" do
      expect { described_class.validate_entity_identifier!("   ") }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /Entity identifier cannot be nil or empty/)
    end

    it "raises SecurityError when entity_id object becomes empty after trimming" do
      obj = Object.new
      def obj.to_s
        "   "
      end
      allow(OmniauthOpenidFederation::StringHelpers).to receive(:blank?).with(obj).and_return(false)

      expect { described_class.validate_entity_identifier!(obj) }
        .to raise_error(OmniauthOpenidFederation::SecurityError, /Entity identifier cannot be empty after trimming/)
    end
  end
end

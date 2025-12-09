require "spec_helper"
require "rake"

# rubocop:disable RSpec/DescribeClass
RSpec.describe "Rake tasks", type: :rake do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:provider_issuer) { "https://provider.example.com" }

  before do
    # Load rake tasks
    Rake::Task.clear
    # Define a mock :environment task if it doesn't exist (required by rake tasks)
    unless Rake::Task.task_defined?(:environment)
      Rake::Task.define_task(:environment) do
        # Mock environment task - no-op for tests
      end
    end
    load "lib/tasks/omniauth_openid_federation.rake"
  end

  after do
    # Re-enable all tasks to allow them to run again in subsequent tests
    Rake::Task.tasks.each do |task|
      task.reenable if task.respond_to?(:reenable)
    end
    # Clear any environment variables that might affect tests
    ENV.delete("ENTITY_STATEMENT_URL")
    ENV.delete("ENTITY_STATEMENT_FINGERPRINT")
    ENV.delete("ENTITY_STATEMENT_OUTPUT")
    ENV.delete("ENTITY_STATEMENT_PATH")
    ENV.delete("JWKS_URI")
    ENV.delete("JWKS_OUTPUT")
    ENV.delete("KEY_TYPE")
    ENV.delete("KEYS_OUTPUT_DIR")
  end

  describe "openid_federation:fetch_entity_statement" do
    it "handles missing URL" do
      expect {
        Rake::Task["openid_federation:fetch_entity_statement"].invoke(nil, nil, nil)
      }.to raise_error(SystemExit)
    end

    it "fetches entity statement successfully" do
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token",
            userinfo_endpoint: "https://provider.example.com/oauth2/userinfo",
            jwks_uri: "https://provider.example.com/.well-known/jwks.json"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")

      output_file = Tempfile.new(["entity", ".jwt"]).path

      stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
        .to_return(status: 200, body: jwt, headers: {"Content-Type" => "application/jwt"})

      # Mock TasksHelper
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:fetch_entity_statement).and_return({
        output_path: output_file,
        fingerprint: "test-fingerprint",
        metadata: {
          issuer: provider_issuer,
          metadata: {
            openid_provider: {
              authorization_endpoint: "https://provider.example.com/oauth2/authorize",
              token_endpoint: "https://provider.example.com/oauth2/token",
              userinfo_endpoint: "https://provider.example.com/oauth2/userinfo",
              jwks_uri: "https://provider.example.com/.well-known/jwks.json"
            }
          }
        }
      })

      Rake::Task["openid_federation:fetch_entity_statement"].reenable
      Rake::Task["openid_federation:fetch_entity_statement"].invoke(
        "#{provider_issuer}/.well-known/openid-federation",
        nil,
        output_file
      )

      expect(OmniauthOpenidFederation::TasksHelper).to have_received(:fetch_entity_statement).with(
        url: "#{provider_issuer}/.well-known/openid-federation",
        fingerprint: nil,
        output_file: output_file
      )
    end

    it "handles fetch errors" do
      stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
        .to_return(status: 500, body: "Internal Server Error")

      allow(OmniauthOpenidFederation::TasksHelper).to receive(:fetch_entity_statement).and_raise(
        OmniauthOpenidFederation::Federation::EntityStatement::FetchError.new("Fetch failed")
      )

      Rake::Task["openid_federation:fetch_entity_statement"].reenable
      expect {
        Rake::Task["openid_federation:fetch_entity_statement"].invoke(
          "#{provider_issuer}/.well-known/openid-federation",
          nil,
          nil
        )
      }.to raise_error(SystemExit)
    end

    it "handles validation errors" do
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:fetch_entity_statement).and_raise(
        OmniauthOpenidFederation::Federation::EntityStatement::ValidationError.new("Validation failed")
      )

      Rake::Task["openid_federation:fetch_entity_statement"].reenable
      expect {
        Rake::Task["openid_federation:fetch_entity_statement"].invoke(
          "#{provider_issuer}/.well-known/openid-federation",
          nil,
          nil
        )
      }.to raise_error(SystemExit)
    end

    it "handles unexpected errors" do
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:fetch_entity_statement).and_raise(
        StandardError.new("Unexpected error")
      )

      Rake::Task["openid_federation:fetch_entity_statement"].reenable
      expect {
        Rake::Task["openid_federation:fetch_entity_statement"].invoke(
          "#{provider_issuer}/.well-known/openid-federation",
          nil,
          nil
        )
      }.to raise_error(SystemExit)
    end
  end

  describe "openid_federation:validate_entity_statement" do
    it "validates entity statement successfully" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      allow(OmniauthOpenidFederation::TasksHelper).to receive(:validate_entity_statement).and_return({
        fingerprint: "test-fingerprint",
        metadata: {
          issuer: provider_issuer,
          metadata: {
            openid_provider: {
              authorization_endpoint: "https://provider.example.com/oauth2/authorize",
              token_endpoint: "https://provider.example.com/oauth2/token",
              userinfo_endpoint: "https://provider.example.com/oauth2/userinfo",
              jwks_uri: "https://provider.example.com/.well-known/jwks.json"
            }
          }
        }
      })

      Rake::Task["openid_federation:validate_entity_statement"].reenable
      Rake::Task["openid_federation:validate_entity_statement"].invoke(entity_statement_path, nil)

      expect(OmniauthOpenidFederation::TasksHelper).to have_received(:validate_entity_statement).with(
        file_path: entity_statement_path,
        expected_fingerprint: nil
      )
    end

    it "handles configuration errors" do
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:validate_entity_statement).and_raise(
        OmniauthOpenidFederation::ConfigurationError.new("Configuration error")
      )

      Rake::Task["openid_federation:validate_entity_statement"].reenable
      expect {
        Rake::Task["openid_federation:validate_entity_statement"].invoke("/nonexistent/path.jwt", nil)
      }.to raise_error(SystemExit)
    end

    it "handles validation errors" do
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:validate_entity_statement).and_raise(
        OmniauthOpenidFederation::ValidationError.new("Validation error")
      )

      Rake::Task["openid_federation:validate_entity_statement"].reenable
      expect {
        Rake::Task["openid_federation:validate_entity_statement"].invoke("/nonexistent/path.jwt", nil)
      }.to raise_error(SystemExit)
    end

    it "handles unexpected errors" do
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:validate_entity_statement).and_raise(
        StandardError.new("Unexpected error")
      )

      Rake::Task["openid_federation:validate_entity_statement"].reenable
      expect {
        Rake::Task["openid_federation:validate_entity_statement"].invoke("/nonexistent/path.jwt", nil)
      }.to raise_error(SystemExit)
    end
  end

  describe "openid_federation:fetch_jwks" do
    it "fetches JWKS successfully" do
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      output_file = Tempfile.new(["jwks", ".json"]).path

      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      allow(OmniauthOpenidFederation::TasksHelper).to receive(:fetch_jwks).and_return({
        success: true,
        jwks: jwks,
        output_path: output_file
      })

      Rake::Task["openid_federation:fetch_jwks"].reenable
      Rake::Task["openid_federation:fetch_jwks"].invoke(jwks_uri, output_file)

      expect(OmniauthOpenidFederation::TasksHelper).to have_received(:fetch_jwks).with(
        jwks_uri: jwks_uri,
        output_file: output_file
      )
    end

    it "handles fetch errors" do
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"

      stub_request(:get, jwks_uri)
        .to_return(status: 500, body: "Internal Server Error")

      allow(OmniauthOpenidFederation::TasksHelper).to receive(:fetch_jwks).and_return({
        success: false,
        error: "Failed to fetch JWKS"
      })

      Rake::Task["openid_federation:fetch_jwks"].reenable
      Rake::Task["openid_federation:fetch_jwks"].invoke(jwks_uri, nil)

      expect(OmniauthOpenidFederation::TasksHelper).to have_received(:fetch_jwks).with(
        jwks_uri: jwks_uri,
        output_file: "config/provider-jwks.json"
      )
    end
  end

  describe "openid_federation:generate_keys" do
    it "generates keys successfully" do
      output_dir = Dir.mktmpdir
      begin
        allow(OmniauthOpenidFederation::TasksHelper).to receive(:prepare_client_keys).and_return({
          success: true,
          private_key_path: File.join(output_dir, "private_key.pem"),
          public_key_path: File.join(output_dir, "public_key.pem")
        })

        Rake::Task["openid_federation:prepare_client_keys"].reenable
        Rake::Task["openid_federation:prepare_client_keys"].invoke("single", output_dir)

        expect(OmniauthOpenidFederation::TasksHelper).to have_received(:prepare_client_keys).with(
          key_type: "single",
          output_dir: output_dir
        )
      ensure
        FileUtils.rm_rf(output_dir)
      end
    end

    it "handles generation errors" do
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:prepare_client_keys).and_return({
        success: false,
        error: "Failed to generate keys"
      })

      Rake::Task["openid_federation:prepare_client_keys"].reenable
      Rake::Task["openid_federation:prepare_client_keys"].invoke("single", "/tmp")

      expect(OmniauthOpenidFederation::TasksHelper).to have_received(:prepare_client_keys).with(
        key_type: "single",
        output_dir: "/tmp"
      )
    end
  end

  describe "openid_federation:parse_entity_statement" do
    it "parses entity statement successfully" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      allow(OmniauthOpenidFederation::TasksHelper).to receive(:parse_entity_statement).and_return({
        issuer: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      })

      Rake::Task["openid_federation:parse_entity_statement"].reenable
      Rake::Task["openid_federation:parse_entity_statement"].invoke(entity_statement_path)

      expect(OmniauthOpenidFederation::TasksHelper).to have_received(:parse_entity_statement).with(
        file_path: entity_statement_path
      )
    end

    it "handles configuration errors" do
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:parse_entity_statement).and_raise(
        OmniauthOpenidFederation::ConfigurationError.new("Configuration error")
      )

      Rake::Task["openid_federation:parse_entity_statement"].reenable
      expect {
        Rake::Task["openid_federation:parse_entity_statement"].invoke("/nonexistent/path.jwt")
      }.to raise_error(SystemExit)
    end

    it "handles validation errors" do
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:parse_entity_statement).and_raise(
        OmniauthOpenidFederation::ValidationError.new("Validation error")
      )

      Rake::Task["openid_federation:parse_entity_statement"].reenable
      expect {
        Rake::Task["openid_federation:parse_entity_statement"].invoke("/nonexistent/path.jwt")
      }.to raise_error(SystemExit)
    end

    it "handles unexpected errors" do
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:parse_entity_statement).and_raise(
        StandardError.new("Unexpected error")
      )

      Rake::Task["openid_federation:parse_entity_statement"].reenable
      expect {
        Rake::Task["openid_federation:parse_entity_statement"].invoke("/nonexistent/path.jwt")
      }.to raise_error(SystemExit)
    end
  end

  describe "openid_federation:prepare_client_keys" do
    it "prepares client keys successfully" do
      output_dir = Dir.mktmpdir
      begin
        allow(OmniauthOpenidFederation::TasksHelper).to receive(:prepare_client_keys).and_return({
          private_key_path: File.join(output_dir, "private_key.pem"),
          public_jwks_path: File.join(output_dir, "public_jwks.json")
        })

        Rake::Task["openid_federation:prepare_client_keys"].reenable
        Rake::Task["openid_federation:prepare_client_keys"].invoke("single", output_dir)

        expect(OmniauthOpenidFederation::TasksHelper).to have_received(:prepare_client_keys).with(
          key_type: "single",
          output_dir: output_dir
        )
      ensure
        FileUtils.rm_rf(output_dir)
      end
    end

    it "handles key preparation errors" do
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:prepare_client_keys).and_raise(
        StandardError.new("Key generation failed")
      )

      Rake::Task["openid_federation:prepare_client_keys"].reenable
      expect {
        Rake::Task["openid_federation:prepare_client_keys"].invoke("single", "/tmp")
      }.to raise_error(SystemExit)
    end
  end

  describe "openid_federation:test_local_endpoint" do
    it "tests local endpoint successfully" do
      base_url = "http://localhost:3000"
      {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token",
            userinfo_endpoint: "https://provider.example.com/oauth2/userinfo",
            jwks_uri: "https://provider.example.com/.well-known/jwks.json"
          }
        }
      }

      entity_statement_double = double(fingerprint: "test-fingerprint")
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:test_local_endpoint).and_return({
        entity_statement: entity_statement_double,
        metadata: {
          issuer: provider_issuer,
          sub: provider_issuer,
          exp: Time.now.to_i + 3600,
          iat: Time.now.to_i
        },
        results: {
          authorization_endpoint: {status: :success, code: 200},
          token_endpoint: {status: :success, code: 200},
          userinfo_endpoint: {status: :success, code: 200},
          jwks_uri: {status: :success, keys: 1}
        }
      })

      Rake::Task["openid_federation:test_local_endpoint"].reenable
      Rake::Task["openid_federation:test_local_endpoint"].invoke(base_url)

      expect(OmniauthOpenidFederation::TasksHelper).to have_received(:test_local_endpoint).with(
        base_url: base_url
      )
    end

    it "handles test_local_endpoint with warnings" do
      base_url = "http://localhost:3000"
      entity_statement_double = double(fingerprint: "test-fingerprint")
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:test_local_endpoint).and_return({
        entity_statement: entity_statement_double,
        metadata: {
          issuer: provider_issuer,
          sub: provider_issuer
        },
        results: {
          authorization_endpoint: {status: :warning, code: "404", body: "Not Found"}
        }
      })

      Rake::Task["openid_federation:test_local_endpoint"].reenable
      Rake::Task["openid_federation:test_local_endpoint"].invoke(base_url)

      expect(OmniauthOpenidFederation::TasksHelper).to have_received(:test_local_endpoint).with(
        base_url: base_url
      )
    end

    it "handles test_local_endpoint with errors" do
      base_url = "http://localhost:3000"
      entity_statement_double = double(fingerprint: "test-fingerprint")
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:test_local_endpoint).and_return({
        entity_statement: entity_statement_double,
        metadata: {
          issuer: provider_issuer,
          sub: provider_issuer
        },
        results: {
          authorization_endpoint: {status: :error, message: "Connection failed"}
        }
      })

      Rake::Task["openid_federation:test_local_endpoint"].reenable
      expect {
        Rake::Task["openid_federation:test_local_endpoint"].invoke(base_url)
      }.to raise_error(SystemExit)
    end

    it "handles fetch errors in test_local_endpoint" do
      base_url = "http://localhost:3000"
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:test_local_endpoint).and_raise(
        OmniauthOpenidFederation::Federation::EntityStatement::FetchError.new("Fetch failed")
      )

      Rake::Task["openid_federation:test_local_endpoint"].reenable
      expect {
        Rake::Task["openid_federation:test_local_endpoint"].invoke(base_url)
      }.to raise_error(SystemExit)
    end

    it "handles validation errors in test_local_endpoint" do
      base_url = "http://localhost:3000"
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:test_local_endpoint).and_raise(
        OmniauthOpenidFederation::Federation::EntityStatement::ValidationError.new("Validation failed")
      )

      Rake::Task["openid_federation:test_local_endpoint"].reenable
      expect {
        Rake::Task["openid_federation:test_local_endpoint"].invoke(base_url)
      }.to raise_error(SystemExit)
    end

    it "handles unexpected errors in test_local_endpoint" do
      base_url = "http://localhost:3000"
      allow(OmniauthOpenidFederation::TasksHelper).to receive(:test_local_endpoint).and_raise(
        StandardError.new("Unexpected error")
      )

      Rake::Task["openid_federation:test_local_endpoint"].reenable
      expect {
        Rake::Task["openid_federation:test_local_endpoint"].invoke(base_url)
      }.to raise_error(SystemExit)
    end
  end
end
# rubocop:enable RSpec/DescribeClass

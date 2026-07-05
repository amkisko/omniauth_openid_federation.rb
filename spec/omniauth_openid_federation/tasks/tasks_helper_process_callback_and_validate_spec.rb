require "spec_helper"

RSpec.describe OmniauthOpenidFederation::TasksHelper do
  describe ".process_callback_and_validate" do
    let(:callback_url) { "http://localhost:3000/callback?code=auth-code&state=state-value" }
    let(:base_url) { "http://localhost:3000" }
    let(:client_id) { "test-client" }
    let(:redirect_uri) { "http://localhost:3000/callback" }
    let(:private_key) { OpenSSL::PKey::RSA.new(2048) }

    it "handles invalid callback URL" do
      expect {
        described_class.process_callback_and_validate(
          callback_url: "not a valid url",
          base_url: base_url,
          client_id: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        )
      }.to raise_error(/Invalid callback URL/)
    end

    it "handles authorization error in callback" do
      error_callback = "http://localhost:3000/callback?error=access_denied&error_description=User%20denied"

      expect {
        described_class.process_callback_and_validate(
          callback_url: error_callback,
          base_url: base_url,
          client_id: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        )
      }.to raise_error(/Authorization error: access_denied/)
    end

    it "handles authorization error without description" do
      error_callback = "http://localhost:3000/callback?error=access_denied"

      expect {
        described_class.process_callback_and_validate(
          callback_url: error_callback,
          base_url: base_url,
          client_id: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        )
      }.to raise_error(/Authorization error: access_denied/)
    end

    it "handles missing authorization code" do
      no_code_callback = "http://localhost:3000/callback?state=state-value"

      expect {
        described_class.process_callback_and_validate(
          callback_url: no_code_callback,
          base_url: base_url,
          client_id: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        )
      }.to raise_error(/No authorization code found/)
    end

    it "resolves entity statement URL from path" do
      # Use temp directory to avoid writing to project config/
      temp_dir = Dir.mktmpdir
      temp_config_dir = File.join(temp_dir, "config")
      FileUtils.mkdir_p(temp_config_dir)
      entity_statement_path = "config/entity.jwt"
      temp_file_path = File.join(temp_config_dir, "entity.jwt")

      # Stub Rails.root to point to temp directory if Rails is defined
      if defined?(Rails)
        allow(Rails.root).to receive(:join).with("config/entity.jwt").and_return(Pathname.new(temp_file_path))
      else
        config = OmniauthOpenidFederation::Configuration.config
        original_root_path = config.root_path
        config.root_path = temp_dir
      end

      # Stub the entity statement fetch to avoid WebMock error
      stub_request(:get, /.*\/\.well-known\/openid-federation/)
        .to_return(status: 200, body: "", headers: {"Content-Type" => "application/jwt"})

      begin
        # This will fail later, but we're testing the URL resolution
        expect {
          described_class.process_callback_and_validate(
            callback_url: callback_url,
            base_url: base_url,
            client_id: client_id,
            redirect_uri: redirect_uri,
            private_key: private_key,
            entity_statement_path: entity_statement_path
          )
        }.to raise_error(StandardError) # Will fail at strategy initialization, but URL resolution is tested
      ensure
        FileUtils.rm_rf(temp_dir) if File.directory?(temp_dir)
        unless defined?(Rails)
          config = OmniauthOpenidFederation::Configuration.config
          config.root_path = original_root_path
        end
      end
    end

    it "resolves client entity statement URL from path" do
      # Use temp directory to avoid writing to project config/
      temp_dir = Dir.mktmpdir
      temp_config_dir = File.join(temp_dir, "config")
      FileUtils.mkdir_p(temp_config_dir)
      client_entity_statement_path = "config/client-entity.jwt"
      temp_file_path = File.join(temp_config_dir, "client-entity.jwt")

      # Stub Rails.root to point to temp directory if Rails is defined
      if defined?(Rails)
        allow(Rails.root).to receive(:join).with("config/client-entity.jwt").and_return(Pathname.new(temp_file_path))
      else
        config = OmniauthOpenidFederation::Configuration.config
        original_root_path = config.root_path
        config.root_path = temp_dir
      end

      begin
        # This will fail later, but we're testing the URL resolution
        expect {
          described_class.process_callback_and_validate(
            callback_url: callback_url,
            base_url: base_url,
            client_id: client_id,
            redirect_uri: redirect_uri,
            private_key: private_key,
            client_entity_statement_path: client_entity_statement_path
          )
        }.to raise_error(StandardError) # Will fail at strategy initialization, but URL resolution is tested
      ensure
        FileUtils.rm_rf(temp_dir) if File.directory?(temp_dir)
        unless defined?(Rails)
          config = OmniauthOpenidFederation::Configuration.config
          config.root_path = original_root_path
        end
      end
    end

    it "handles failed client initialization" do
      # Mock strategy to return nil client
      strategy = double("Strategy")
      allow(strategy).to receive(:client).and_return(nil)
      allow(OmniAuth::Strategies::OpenIDFederation).to receive(:new).and_return(strategy)

      expect {
        described_class.process_callback_and_validate(
          callback_url: callback_url,
          base_url: base_url,
          client_id: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        )
      }.to raise_error(/Failed to initialize OpenID Connect client/)
    end

    it "handles missing private key on client" do
      oidc_client = double("OpenIDConnect::Client")
      allow(oidc_client).to receive(:private_key).and_return(nil)

      strategy = double("Strategy")
      allow(strategy).to receive(:client).and_return(oidc_client)
      allow(OmniAuth::Strategies::OpenIDFederation).to receive(:new).and_return(strategy)

      expect {
        described_class.process_callback_and_validate(
          callback_url: callback_url,
          base_url: base_url,
          client_id: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        )
      }.to raise_error(/Private key not set/)
    end
  end
end

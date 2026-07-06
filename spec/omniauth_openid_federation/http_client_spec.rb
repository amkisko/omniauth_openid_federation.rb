require "spec_helper"

RSpec.describe OmniauthOpenidFederation::HttpClient do
  let(:uri) { "https://example.com/test" }

  before do
    # Reset configuration
    OmniauthOpenidFederation::Configuration.instance_variable_set(:@config, nil)
  end

  describe ".get" do
    context "with successful request" do
      it "returns HTTP response" do
        stub_request(:get, uri)
          .to_return(status: 200, body: "success")

        response = described_class.get(uri)
        aggregate_failures do
          expect(response.status).to eq(200)
          expect(response.body.to_s).to eq("success")
        end
      end
    end

    context "with retry logic" do
      it "retries on HTTP::Error" do
        call_count = 0
        stub_request(:get, uri).to_return do |_request|
          call_count += 1
          if call_count < 3
            raise HTTP::Error.new("Network error")
          else
            {status: 200, body: "success"}
          end
        end

        # Configure for faster retries in tests
        OmniauthOpenidFederation.configure do |config|
          config.max_retries = 2
          config.retry_delay = 0.1
        end

        response = described_class.get(uri)
        expect(response.status).to eq(200)
      end

      it "raises NetworkError after max retries" do
        stub_request(:get, uri)
          .to_raise(HTTP::Error.new("Network error"))

        OmniauthOpenidFederation.configure do |config|
          config.max_retries = 1
          config.retry_delay = 0.1
        end

        expect { described_class.get(uri) }
          .to raise_error(OmniauthOpenidFederation::NetworkError, /Failed to GET.*after 2 attempts/)
      end

      it "handles Timeout::Error" do
        stub_request(:get, uri)
          .to_raise(Timeout::Error.new("Timeout"))

        OmniauthOpenidFederation.configure do |config|
          config.max_retries = 1
          config.retry_delay = 0.1
        end

        expect { described_class.get(uri) }
          .to raise_error(OmniauthOpenidFederation::NetworkError)
      end

      it "handles connection refused errors" do
        stub_request(:get, uri)
          .to_raise(Errno::ECONNREFUSED.new)

        OmniauthOpenidFederation.configure do |config|
          config.max_retries = 1
          config.retry_delay = 0.1
        end

        expect { described_class.get(uri) }
          .to raise_error(OmniauthOpenidFederation::NetworkError)
      end

      it "handles ETIMEDOUT errors" do
        stub_request(:get, uri)
          .to_raise(Errno::ETIMEDOUT.new)

        OmniauthOpenidFederation.configure do |config|
          config.max_retries = 1
          config.retry_delay = 0.1
        end

        expect { described_class.get(uri) }
          .to raise_error(OmniauthOpenidFederation::NetworkError)
      end

      it "implements exponential backoff with max delay cap" do
        call_count = 0
        stub_request(:get, uri).to_return do |_request|
          call_count += 1
          raise HTTP::Error.new("Network error") if call_count < 3
          {status: 200, body: "success"}
        end

        OmniauthOpenidFederation.configure do |config|
          config.max_retries = 3
          config.retry_delay = 0.1
        end

        start_time = OmniauthOpenidFederation::TimeHelpers.now
        response = described_class.get(uri)
        elapsed = OmniauthOpenidFederation::TimeHelpers.now - start_time

        aggregate_failures do
          expect(response.status).to eq(200)
          # Should have retried with delays (at least some delay)
          expect(elapsed).to be > 0.1
        end
      end

      it "retries GET on transient HTTP 503" do
        call_count = 0
        stub_request(:get, uri).to_return do |_request|
          call_count += 1
          if call_count < 3
            {status: 503, body: "unavailable"}
          else
            {status: 200, body: "success"}
          end
        end

        OmniauthOpenidFederation.configure do |config|
          config.max_retries = 2
          config.retry_delay = 0.1
        end

        response = described_class.get(uri)
        aggregate_failures do
          expect(response.status).to eq(200)
          expect(call_count).to eq(3)
        end
      end

      it "returns the HTTP response when GET status retries are exhausted" do
        stub_request(:get, uri)
          .to_return(status: 503, body: "unavailable")

        OmniauthOpenidFederation.configure do |config|
          config.max_retries = 1
          config.retry_delay = 0.1
        end

        response = described_class.get(uri)
        aggregate_failures do
          expect(response.status.code).to eq(503)
          expect(response.body.to_s).to eq("unavailable")
        end
      end
    end

    context "with SSL verification" do
      def capture_http_options_during_get
        captured_hash = nil
        original_new = HTTP::Options.method(:new)
        allow(HTTP::Options).to receive(:new) do |options|
          captured_hash = options if options.is_a?(Hash)
          original_new.call(options)
        end

        stub_request(:get, uri).to_return(status: 200, body: "success")
        described_class.get(uri)
        captured_hash
      end

      it "uses SSL verification by default" do
        OmniauthOpenidFederation.configure do |config|
          config.verify_ssl = true
          config.http_options = nil
        end

        captured_options = capture_http_options_during_get
        expect(captured_options.dig(:ssl, :verify_mode)).to eq(OpenSSL::SSL::VERIFY_PEER)
      end

      it "skips SSL verification when configured" do
        OmniauthOpenidFederation.configure do |config|
          config.verify_ssl = false
          config.http_options = nil
        end

        captured_options = capture_http_options_during_get
        expect(captured_options.dig(:ssl, :verify_mode)).to eq(OpenSSL::SSL::VERIFY_NONE)
      end

      it "does not override explicit http_options ssl verify_mode" do
        OmniauthOpenidFederation.configure do |config|
          config.verify_ssl = true
          config.http_options = {ssl: {verify_mode: OpenSSL::SSL::VERIFY_NONE}}
        end

        captured_options = capture_http_options_during_get
        expect(captured_options.dig(:ssl, :verify_mode)).to eq(OpenSSL::SSL::VERIFY_NONE)
      end

      it "sets ca_file from SSL_CERT_FILE when verify_ssl is enabled" do
        cert_file = Tempfile.new(["cert", ".pem"])
        cert_file.write("cert content")
        cert_file.close

        original_ssl_cert_file = ENV["SSL_CERT_FILE"]
        ENV["SSL_CERT_FILE"] = cert_file.path

        OmniauthOpenidFederation.configure do |config|
          config.verify_ssl = true
          config.http_options = nil
        end

        captured_options = capture_http_options_during_get
        expect(captured_options.dig(:ssl, :ca_file)).to eq(cert_file.path)
      ensure
        if original_ssl_cert_file
          ENV["SSL_CERT_FILE"] = original_ssl_cert_file
        else
          ENV.delete("SSL_CERT_FILE")
        end
        cert_file.unlink
      end

      it "does not override explicit http_options ca_file" do
        custom_ca = "/custom/ca.pem"

        OmniauthOpenidFederation.configure do |config|
          config.verify_ssl = true
          config.http_options = {ssl: {ca_file: custom_ca}}
        end

        captured_options = capture_http_options_during_get
        expect(captured_options.dig(:ssl, :ca_file)).to eq(custom_ca)
      end
    end

    context "with custom options" do
      it "uses custom max_retries" do
        stub_request(:get, uri)
          .to_raise(HTTP::Error.new("Network error"))

        expect { described_class.get(uri, max_retries: 1, retry_delay: 0.1) }
          .to raise_error(OmniauthOpenidFederation::NetworkError, /after 2 attempts/)
      end

      it "uses custom timeout" do
        stub_request(:get, uri)
          .to_return(status: 200, body: "success")

        response = described_class.get(uri, timeout: 5)
        expect(response.status).to eq(200)
      end

      it "uses custom retry_delay" do
        call_count = 0
        stub_request(:get, uri).to_return do |_request|
          call_count += 1
          raise HTTP::Error.new("Network error") if call_count < 2
          {status: 200, body: "success"}
        end

        start_time = OmniauthOpenidFederation::TimeHelpers.now
        response = described_class.get(uri, max_retries: 2, retry_delay: 0.2)
        elapsed = OmniauthOpenidFederation::TimeHelpers.now - start_time

        aggregate_failures do
          expect(response.status).to eq(200)
          expect(elapsed).to be >= 0.2
        end
      end
    end

    context "with http_options configuration" do
      it "uses http_options hash when configured" do
        stub_request(:get, uri)
          .to_return(status: 200, body: "success")

        OmniauthOpenidFederation.configure do |config|
          config.http_options = {headers: {"Custom-Header" => "value"}}
        end

        response = described_class.get(uri)
        expect(response.status).to eq(200)
      end

      it "calls http_options Proc when configured" do
        stub_request(:get, uri)
          .to_return(status: 200, body: "success")

        options_proc = proc { {headers: {"From-Proc" => "value"}} }
        OmniauthOpenidFederation.configure do |config|
          config.http_options = options_proc
        end

        allow(options_proc).to receive(:call).and_call_original
        response = described_class.get(uri)
        aggregate_failures do
          expect(response.status).to eq(200)
          expect(options_proc).to have_received(:call)
        end
      end
    end
  end

  describe ".post" do
    it "returns HTTP response for form post" do
      stub_request(:post, uri)
        .with(body: {"acr_values" => "test"})
        .to_return(status: 302, headers: {"Location" => "https://provider.example.com"})

      response = described_class.post(uri, form: {acr_values: "test"}, max_retries: 0)
      aggregate_failures do
        expect(response.status.code).to eq(302)
        expect(response.headers["Location"]).to eq("https://provider.example.com")
      end
    end

    it "sends request headers" do
      stub_request(:post, uri)
        .with(headers: {"X-CSRF-Token" => "token"})
        .to_return(status: 200, body: "ok")

      response = described_class.post(uri, headers: {"X-CSRF-Token" => "token"}, max_retries: 0)
      expect(response.status).to eq(200)
    end

    it "uses separate connect and read timeouts" do
      captured_timeout = nil
      original_new = HTTP::Options.method(:new)
      allow(HTTP::Options).to receive(:new) do |options|
        original_new.call(options)
      end
      allow_any_instance_of(HTTP::Client).to receive(:timeout) do |client, timeout_config|
        captured_timeout = timeout_config
        client
      end

      stub_request(:post, uri).to_return(status: 200, body: "ok")

      described_class.post(uri, connect_timeout: 3, read_timeout: 7, max_retries: 0)
      expect(captured_timeout).to eq({connect: 3, read: 7})
    end

    it "does not retry POST on network errors by default" do
      stub_request(:post, uri)
        .to_raise(HTTP::Error.new("Network error"))

      expect { described_class.post(uri) }
        .to raise_error(OmniauthOpenidFederation::NetworkError, /after 1 attempts/)
    end

    it "retries POST when max_retries is set explicitly" do
      call_count = 0
      stub_request(:post, uri).to_return do |_request|
        call_count += 1
        if call_count < 2
          raise HTTP::Error.new("Network error")
        else
          {status: 200, body: "ok"}
        end
      end

      response = described_class.post(uri, max_retries: 1, retry_delay: 0.1)
      aggregate_failures do
        expect(response.status).to eq(200)
        expect(call_count).to eq(2)
      end
    end

    it "does not retry POST on HTTP 503" do
      call_count = 0
      stub_request(:post, uri).to_return do |_request|
        call_count += 1
        {status: 503, body: "unavailable"}
      end

      response = described_class.post(uri)
      aggregate_failures do
        expect(response.status.code).to eq(503)
        expect(call_count).to eq(1)
      end
    end
  end
end

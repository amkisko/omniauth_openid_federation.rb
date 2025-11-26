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
        expect(response.status).to eq(200)
        expect(response.body.to_s).to eq("success")
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
          .to raise_error(OmniauthOpenidFederation::NetworkError, /Failed to fetch.*after 1 retries/)
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

        start_time = Time.now
        response = described_class.get(uri)
        elapsed = Time.now - start_time

        expect(response.status).to eq(200)
        # Should have retried with delays (at least some delay)
        expect(elapsed).to be > 0.1
      end
    end

    context "with SSL verification" do
      it "uses SSL verification by default" do
        stub_request(:get, uri)
          .to_return(status: 200, body: "success")

        OmniauthOpenidFederation.configure do |config|
          config.verify_ssl = true
        end

        response = described_class.get(uri)
        expect(response.status).to eq(200)
      end

      it "skips SSL verification when configured" do
        stub_request(:get, uri)
          .to_return(status: 200, body: "success")

        OmniauthOpenidFederation.configure do |config|
          config.verify_ssl = false
        end

        response = described_class.get(uri)
        expect(response.status).to eq(200)
      end
    end

    context "with custom options" do
      it "uses custom max_retries" do
        stub_request(:get, uri)
          .to_raise(HTTP::Error.new("Network error"))

        expect { described_class.get(uri, max_retries: 1, retry_delay: 0.1) }
          .to raise_error(OmniauthOpenidFederation::NetworkError, /after 1 retries/)
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

        start_time = Time.now
        response = described_class.get(uri, max_retries: 2, retry_delay: 0.2)
        elapsed = Time.now - start_time

        expect(response.status).to eq(200)
        expect(elapsed).to be >= 0.2
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

        expect(options_proc).to receive(:call).and_call_original
        response = described_class.get(uri)
        expect(response.status).to eq(200)
      end
    end
  end
end

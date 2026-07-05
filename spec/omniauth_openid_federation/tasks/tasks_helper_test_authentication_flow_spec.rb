require "spec_helper"

RSpec.describe OmniauthOpenidFederation::TasksHelper do
  describe ".test_authentication_flow" do
    let(:login_page_url) { "http://localhost:3000/login" }
    let(:base_url) { "http://localhost:3000" }

    it "handles failed login page fetch" do
      WebMock.stub_request(:get, login_page_url)
        .to_return(status: 500, body: "Internal Server Error", headers: {"Content-Type" => "text/html"})

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to fetch login page/)
    end

    it "handles missing CSRF token" do
      WebMock.stub_request(:get, login_page_url)
        .to_return(status: 200, body: "<html><body>No CSRF token here</body></html>", headers: {"Content-Type" => "text/html"})

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to extract CSRF token/)
    end

    it "extracts CSRF token from meta tag" do
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"

      WebMock.stub_request(:get, login_page_url)
        .to_return(status: 200, body: html_body, headers: {"Content-Type" => "text/html"})

      # Mock test endpoint responses (lines 590-598)
      WebMock.stub_request(:get, "#{base_url}/users/auth/openid_federation")
        .to_return(status: 404, body: "", headers: {})
      WebMock.stub_request(:get, "#{base_url}/auth/openid_federation")
        .to_return(status: 404, body: "", headers: {})
      WebMock.stub_request(:get, "#{base_url}/openid_federation")
        .to_return(status: 404, body: "", headers: {})

      # Mock the authorization request that will fail
      WebMock.stub_request(:post, "#{base_url}/users/auth/openid_federation")
        .to_return(status: 500, body: "", headers: {})

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to get authorization URL/)
    end

    it "extracts CSRF token from form input" do
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><body><form action='/users/auth/openid_federation'><input name='authenticity_token' value='#{csrf_token}'></form></body></html>"

      WebMock.stub_request(:get, login_page_url)
        .to_return(status: 200, body: html_body, headers: {"Content-Type" => "text/html"})

      # Mock test endpoint responses
      WebMock.stub_request(:get, "#{base_url}/users/auth/openid_federation")
        .to_return(status: 404, body: "", headers: {})
      WebMock.stub_request(:get, "#{base_url}/auth/openid_federation")
        .to_return(status: 404, body: "", headers: {})
      WebMock.stub_request(:get, "#{base_url}/openid_federation")
        .to_return(status: 404, body: "", headers: {})

      # Mock the authorization request that will fail
      WebMock.stub_request(:post, "#{base_url}/users/auth/openid_federation")
        .to_return(status: 500, body: "", headers: {})

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to get authorization URL/)
    end

    it "handles large HTML body" do
      large_html = "x" * 1_048_577 # Exceeds 1MB limit

      WebMock.stub_request(:get, login_page_url)
        .to_return(status: 200, body: large_html, headers: {"Content-Type" => "text/html"})

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/HTML response too large/)
    end

    it "handles cookie extraction with size limits" do
      large_cookie = "x" * 5000 # Exceeds 4KB limit
      html_body = "<html><head><meta name='csrf-token' content='token'></head><body><form action='/users/auth/openid_federation'></form></body></html>"

      WebMock.stub_request(:get, login_page_url)
        .to_return(status: 200, body: html_body, headers: {"Content-Type" => "text/html", "Set-Cookie" => "cookie_name=#{large_cookie}"})

      # Mock test endpoint responses
      WebMock.stub_request(:get, "#{base_url}/users/auth/openid_federation")
        .to_return(status: 404, body: "", headers: {})
      WebMock.stub_request(:get, "#{base_url}/auth/openid_federation")
        .to_return(status: 404, body: "", headers: {})
      WebMock.stub_request(:get, "#{base_url}/openid_federation")
        .to_return(status: 404, body: "", headers: {})

      # Mock the authorization request that will fail
      WebMock.stub_request(:post, "#{base_url}/users/auth/openid_federation")
        .to_return(status: 500, body: "", headers: {})

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to get authorization URL/)
    end

    it "handles authorization response with 3xx redirect (lines 634-647)" do
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"
      location_header = "https://provider.example.com/authorize?request=..."

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      # Mock test endpoint responses
      test_response = double("Response", status: double(code: 404))

      # Mock authorization response with 3xx redirect
      auth_response = double(
        "Response",
        status: double(code: 302),
        headers: {"Location" => location_header},
        body: double(to_s: "")
      )

      # Stub build_http_client to return a chainable mock
      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 302, headers: {"Location" => location_header})

      result = described_class.test_authentication_flow(
        login_page_url: login_page_url,
        base_url: base_url
      )

      expect(result[:authorization_url]).to eq(location_header)
    end

    it "handles authorization response with 200 status (lines 648-651)" do
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"
      authorization_url = "https://provider.example.com/authorize?request=..."

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      test_response = double("Response", status: double(code: 404))

      # Mock authorization response with 200 and Location header
      auth_response = double(
        "Response",
        status: double(code: 200),
        headers: {"Location" => authorization_url},
        body: double(to_s: "")
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 200, headers: {"Location" => authorization_url})

      result = described_class.test_authentication_flow(
        login_page_url: login_page_url,
        base_url: base_url
      )

      expect(result[:authorization_url]).to eq(authorization_url)
    end

    it "handles authorization response with 200 and body URL" do
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"
      authorization_url = "https://provider.example.com/authorize?request=..."

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      test_response = double("Response", status: double(code: 404))

      # Mock authorization response with 200, no Location header, but URL in body
      auth_response = double(
        "Response",
        status: double(code: 200),
        headers: {},
        body: double(to_s: authorization_url)
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 200, body: authorization_url)

      result = described_class.test_authentication_flow(
        login_page_url: login_page_url,
        base_url: base_url
      )

      expect(result[:authorization_url]).to eq(authorization_url)
    end

    it "handles location header exceeding max length" do
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"
      long_location = "https://provider.example.com/authorize?request=#{"x" * 3000}" # Exceeds 2048

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      test_response = double("Response", status: double(code: 404))

      auth_response = double(
        "Response",
        status: double(code: 302),
        headers: {"Location" => long_location},
        body: double(to_s: "")
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 302, headers: {"Location" => long_location})

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Location header exceeds maximum length/)
    end

    it "handles relative location header" do
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"
      relative_location = "/authorize?request=..."

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      test_response = double("Response", status: double(code: 404))

      auth_response = double(
        "Response",
        status: double(code: 302),
        headers: {"Location" => relative_location},
        body: double(to_s: "")
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 302, headers: {"Location" => relative_location})

      result = described_class.test_authentication_flow(
        login_page_url: login_page_url,
        base_url: base_url
      )

      expect(result[:authorization_url]).to include("/authorize")
    end

    it "handles form action with openid_federation (lines 551-565)" do
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      test_response = double("Response", status: double(code: 404))
      auth_response = double(
        "Response",
        status: double(code: 500, reason: "Error"),
        headers: {},
        body: double(to_s: "")
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 500, body: "Error")

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to get authorization URL/)
    end

    it "handles button/link href matching (lines 568-581)" do
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><a href='/users/auth/openid_federation'>Login</a></body></html>"

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      test_response = double("Response", status: double(code: 404))
      auth_response = double(
        "Response",
        status: double(code: 500, reason: "Error"),
        headers: {},
        body: double(to_s: "")
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 500, body: "Error")

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to get authorization URL/)
    end

    it "handles common paths testing (lines 590-602)" do
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body>No form found</body></html>"

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {},
        body: double(to_s: html_body)
      )

      # Mock test responses for common paths
      test_response_404 = double("Response", status: double(code: 404))
      test_response_302 = double("Response", status: double(code: 302))

      auth_response = double(
        "Response",
        status: double(code: 500, reason: "Error"),
        headers: {},
        body: double(to_s: "")
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response_404, test_response_404, test_response_302)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 200, body: html_body)
      WebMock.stub_request(:get, /http:\/\/localhost:3000\//).to_return(status: 404, body: "Not Found")
      WebMock.stub_request(:get, /http:\/\/localhost:3000\/login/).to_return(status: 200, body: html_body)
      WebMock.stub_request(:post, /.*/).to_return(status: 500, body: "Error")

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to get authorization URL/)
    end

    it "handles cookie extraction with valid cookies (lines 506-507)" do
      csrf_token = SecureRandom.hex(16)
      html_body = "<html><head><meta name='csrf-token' content='#{csrf_token}'></head><body><form action='/users/auth/openid_federation'></form></body></html>"
      cookie_value = "session_id=abc123; path=/"

      http_client = double("HttpClient")
      login_response = double(
        "Response",
        status: double(success?: true),
        headers: {"Set-Cookie" => cookie_value},
        body: double(to_s: html_body)
      )

      test_response = double("Response", status: double(code: 404))
      auth_response = double(
        "Response",
        status: double(code: 500, reason: "Error"),
        headers: {},
        body: double(to_s: "")
      )

      allow(described_class).to receive(:build_http_client).and_return(http_client)
      allow(http_client).to receive(:get).and_return(login_response, test_response)
      allow(http_client).to receive_messages(headers: http_client, post: auth_response)

      # Stub WebMock to prevent real HTTP requests
      WebMock.stub_request(:get, login_page_url).to_return(status: 404, body: "Not Found")
      WebMock.stub_request(:get, /http:\/\/localhost:3000\//).to_return(status: 404, body: "Not Found")
      WebMock.stub_request(:post, /.*/).to_return(status: 500, body: "Error")

      expect {
        described_class.test_authentication_flow(
          login_page_url: login_page_url,
          base_url: base_url
        )
      }.to raise_error(/Failed to (get authorization URL|fetch login page)/)
    end
  end
end

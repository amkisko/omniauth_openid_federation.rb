require "spec_helper"

RSpec.describe OmniauthOpenidFederation::TasksHelper do
  describe ".test_local_endpoint error paths" do
    let(:base_url) { "http://localhost:3000" }

    it "handles ValidationError when fetching entity statement" do
      validation_error = OmniauthOpenidFederation::Federation::EntityStatement::ValidationError.new("Invalid signature")

      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_raise(validation_error)

      # Mock HttpClient.get to return a valid JWT body
      jwt_body = "header.payload.signature"
      http_response = double("Response", body: double(to_s: jwt_body), status: double(success?: true))
      allow(OmniauthOpenidFederation::HttpClient).to receive(:get).and_return(http_response)
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:new).and_return(
        double("EntityStatement", parse: {issuer: base_url, metadata: {}})
      )

      result = described_class.test_local_endpoint(base_url: base_url)

      aggregate_failures do
        expect(result[:validation_warnings]).to include("Invalid signature")
        expect(result[:success]).to be true
      end
    end

    it "handles ValidationError when parsing entity statement" do
      entity_statement = double("EntityStatement")
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_return(entity_statement)

      validation_error = OmniauthOpenidFederation::Federation::EntityStatement::ValidationError.new("Parse failed")
      allow(entity_statement).to receive(:parse).and_raise(validation_error)
      allow(entity_statement).to receive(:entity_statement).and_return("header.payload.signature")

      # Mock Base64 and JSON parsing
      allow(Base64).to receive(:urlsafe_decode64).with("payload").and_return('{"iss":"http://localhost:3000"}')
      allow(JSON).to receive(:parse).and_return({"iss" => base_url, "sub" => base_url, "exp" => Time.now.to_i + 3600, "iat" => Time.now.to_i})

      result = described_class.test_local_endpoint(base_url: base_url)

      aggregate_failures do
        expect(result[:validation_warnings]).to include("Parse failed")
        expect(result[:success]).to be true
        expect(result[:metadata]).to be_a(Hash)
      end
    end

    it "handles Relying Party metadata" do
      entity_statement = double("EntityStatement")
      metadata = {
        issuer: base_url,
        metadata: {
          openid_relying_party: {
            jwks_uri: "#{base_url}/.well-known/jwks.json",
            signed_jwks_uri: "#{base_url}/.well-known/signed-jwks.json"
          }
        }
      }
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_return(entity_statement)
      allow(entity_statement).to receive(:parse).and_return(metadata)

      WebMock.stub_request(:get, "#{base_url}/.well-known/openid-federation")
        .to_return(status: 200, body: "jwt", headers: {"Content-Type" => "application/jwt"})
      WebMock.stub_request(:get, "#{base_url}/.well-known/jwks.json")
        .to_return(status: 200, body: {keys: []}.to_json, headers: {"Content-Type" => "application/json"})
      WebMock.stub_request(:get, "#{base_url}/.well-known/signed-jwks.json")
        .to_return(status: 200, body: "jwt", headers: {"Content-Type" => "application/jwt"})

      result = described_class.test_local_endpoint(base_url: base_url)

      aggregate_failures do
        expect(result[:results]).to have_key("JWKS URI")
        expect(result[:results]["JWKS URI"][:status]).to eq(:success)
      end
    end

    it "handles InvalidURIError for endpoint URLs" do
      entity_statement = double("EntityStatement")
      metadata = {
        issuer: base_url,
        metadata: {
          openid_provider: {
            authorization_endpoint: "not a valid url://invalid"
          }
        }
      }
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_return(entity_statement)
      allow(entity_statement).to receive(:parse).and_return(metadata)

      result = described_class.test_local_endpoint(base_url: base_url)

      aggregate_failures do
        expect(result[:results]["Authorization Endpoint"][:status]).to eq(:error)
        expect(result[:results]["Authorization Endpoint"][:message]).to include("Invalid URL")
      end
    end

    it "handles HTTPS endpoints with SSL configuration" do
      entity_statement = double("EntityStatement")
      metadata = {
        issuer: "https://localhost:3000",
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://localhost:3000/authorize"
          }
        }
      }
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_return(entity_statement)
      allow(entity_statement).to receive(:parse).and_return(metadata)

      # Mock Net::HTTP
      http = double("HTTP")
      allow(Net::HTTP).to receive(:new).and_return(http)
      allow(http).to receive(:use_ssl=)
      allow(http).to receive(:verify_mode=)
      allow(http).to receive(:ca_file=)
      response = double("Response", code: "200")
      allow(http).to receive(:request).and_return(response)

      result = described_class.test_local_endpoint(base_url: "https://localhost:3000")

      aggregate_failures do
        expect(http).to have_received(:use_ssl=).with(true)
        expect(http).to have_received(:verify_mode=).with(OpenSSL::SSL::VERIFY_PEER)
      end
    end

    it "handles HTTPS with SSL_CERT_FILE environment variable" do
      entity_statement = double("EntityStatement")
      metadata = {
        issuer: "https://localhost:3000",
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://localhost:3000/authorize"
          }
        }
      }
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_return(entity_statement)
      allow(entity_statement).to receive(:parse).and_return(metadata)

      cert_file = Tempfile.new(["cert", ".pem"])
      cert_file.write("cert content")
      cert_file.close

      begin
        ENV["SSL_CERT_FILE"] = cert_file.path

        http = double("HTTP")
        allow(Net::HTTP).to receive(:new).and_return(http)
        allow(http).to receive(:use_ssl=)
        allow(http).to receive(:verify_mode=)
        allow(http).to receive(:ca_file=)
        response = double("Response", code: "200")
        allow(http).to receive(:request).and_return(response)

        result = described_class.test_local_endpoint(base_url: "https://localhost:3000")

        expect(http).to have_received(:ca_file=).with(cert_file.path)
      ensure
        ENV.delete("SSL_CERT_FILE")
        cert_file.unlink
      end
    end

    it "handles HTTPS with DEFAULT_CERT_FILE (lines 295-296)" do
      original_ssl_cert_file = ENV["SSL_CERT_FILE"]
      ENV.delete("SSL_CERT_FILE")

      entity_statement = double("EntityStatement")
      metadata = {
        issuer: "https://localhost:3000",
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://localhost:3000/authorize"
          }
        }
      }
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_return(entity_statement)
      allow(entity_statement).to receive(:parse).and_return(metadata)

      # Mock OpenSSL::X509::DEFAULT_CERT_FILE - use the actual constant value
      default_cert_file = begin
        OpenSSL::X509::DEFAULT_CERT_FILE
      rescue
        "/etc/ssl/certs/ca-certificates.crt"
      end
      allow(File).to receive(:exist?).and_call_original
      allow(File).to receive(:exist?).with(default_cert_file).and_return(true)

      http = double("HTTP")
      allow(Net::HTTP).to receive(:new).and_return(http)
      allow(http).to receive(:use_ssl=)
      allow(http).to receive(:verify_mode=)
      allow(http).to receive(:ca_file=)
      response = double("Response", code: "200")
      allow(http).to receive(:request).and_return(response)

      result = described_class.test_local_endpoint(base_url: "https://localhost:3000")

      expect(http).to have_received(:ca_file=).with(default_cert_file)
    ensure
      if original_ssl_cert_file
        ENV["SSL_CERT_FILE"] = original_ssl_cert_file
      else
        ENV.delete("SSL_CERT_FILE")
      end
    end
  end
end

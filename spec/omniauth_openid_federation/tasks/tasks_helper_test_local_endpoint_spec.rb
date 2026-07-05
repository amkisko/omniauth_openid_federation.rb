require "spec_helper"

RSpec.describe OmniauthOpenidFederation::TasksHelper do
  describe ".test_local_endpoint" do
    let(:base_url) { "http://localhost:3000" }
    let(:entity_statement) { double("EntityStatement") }
    let(:metadata) do
      {
        issuer: "https://localhost:3000",
        sub: "https://localhost:3000",
        exp: Time.now.to_i + 3600,
        iat: Time.now.to_i,
        metadata: {
          openid_provider: {
            authorization_endpoint: "http://localhost:3000/authorize",
            token_endpoint: "http://localhost:3000/token",
            jwks_uri: "http://localhost:3000/.well-known/jwks.json",
            signed_jwks_uri: "http://localhost:3000/.well-known/signed-jwks.json"
          }
        },
        jwks: {"keys" => []}
      }
    end

    before do
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!).and_return(entity_statement)
      allow(entity_statement).to receive(:parse).and_return(metadata)
    end

    it "fetches and tests entity statement endpoints" do
      allow(OmniauthOpenidFederation::Jwks::Fetch).to receive(:run).and_return({"keys" => [{"kid" => "key1"}]})
      allow(OmniauthOpenidFederation::Federation::SignedJWKS).to receive(:fetch!).and_return({"keys" => [{"kid" => "key2"}]})

      # Mock HTTP requests for other endpoints
      URI("http://localhost:3000/authorize")
      http = double("HTTP")
      response = double("Response", code: "200")
      allow(Net::HTTP).to receive(:new).and_return(http)
      allow(http).to receive(:use_ssl=)
      allow(http).to receive(:verify_mode=)
      allow(http).to receive(:request).and_return(response)

      result = described_class.test_local_endpoint(base_url: base_url)

      aggregate_failures do
        expect(result[:success]).to be true
        expect(result[:entity_statement]).to eq(entity_statement)
        expect(result[:metadata]).to eq(metadata)
        expect(result[:results]).to be_a(Hash)
      end
    end

    context "key status reporting" do
      before do
        allow(OmniauthOpenidFederation::Jwks::Fetch).to receive(:run).and_return({"keys" => []})
        allow(OmniauthOpenidFederation::Federation::SignedJWKS).to receive(:fetch!).and_return({"keys" => []})

        http = double("HTTP")
        response = double("Response", code: "200")
        allow(Net::HTTP).to receive(:new).and_return(http)
        allow(http).to receive(:use_ssl=)
        allow(http).to receive(:verify_mode=)
        allow(http).to receive(:request).and_return(response)
      end

      it "reports unknown when entity statement has no keys" do
        allow(entity_statement).to receive(:parse).and_return(metadata.merge(jwks: {"keys" => []}))

        result = described_class.test_local_endpoint(base_url: base_url)

        aggregate_failures do
          expect(result[:key_status][:type]).to eq(:unknown)
          expect(result[:key_status][:count]).to eq(0)
        end
      end

      it "reports separate keys when signing and encryption keys are present" do
        allow(entity_statement).to receive(:parse).and_return(
          metadata.merge(
            jwks: {
              "keys" => [
                {"kid" => "sig-kid", "use" => "sig"},
                {"kid" => "enc-kid", "use" => "enc"}
              ]
            }
          )
        )

        result = described_class.test_local_endpoint(base_url: base_url)

        aggregate_failures do
          expect(result[:key_status][:type]).to eq(:separate)
          expect(result[:key_status][:recommendation]).to include("Separate keys detected")
        end
      end

      it "reports single key when only one key is configured" do
        allow(entity_statement).to receive(:parse).and_return(
          metadata.merge(jwks: {keys: [{kid: "single-kid", use: "sig"}]})
        )

        result = described_class.test_local_endpoint(base_url: base_url)

        aggregate_failures do
          expect(result[:key_status][:type]).to eq(:single)
          expect(result[:key_status][:recommendation]).to include("Single key detected")
        end
      end
    end

    context "when endpoint returns error" do
      it "handles FetchError gracefully" do
        # Stub the entity statement endpoint first (required for metadata)
        entity_statement = {
          iss: base_url,
          sub: base_url,
          metadata: {
            openid_provider: {
              issuer: base_url,
              authorization_endpoint: "#{base_url}/authorize",
              token_endpoint: "#{base_url}/token",
              jwks_uri: "#{base_url}/.well-known/jwks.json"
            }
          }
        }
        entity_statement_jwt = JWT.encode(entity_statement, OpenSSL::PKey::RSA.new(2048), "RS256")
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/openid-federation")
          .to_return(status: 200, body: entity_statement_jwt, headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/jwks.json")
          .to_return(status: 200, body: {keys: []}.to_json, headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/signed-jwks.json")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/authorize")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "text/html"})
        WebMock.stub_request(:get, "http://localhost:3000/token")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/userinfo")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})

        allow(OmniauthOpenidFederation::Jwks::Fetch).to receive(:run).and_raise(OmniauthOpenidFederation::FetchError.new("Network error"))

        result = described_class.test_local_endpoint(base_url: base_url)

        aggregate_failures do
          expect(result[:results]["JWKS URI"][:status]).to eq(:error)
          expect(result[:results]["JWKS URI"][:message]).to eq("Network error")
        end
      end

      it "handles SignedJWKS::FetchError gracefully" do
        # Stub the entity statement endpoint first (required for metadata)
        entity_statement = {
          iss: base_url,
          sub: base_url,
          metadata: {
            openid_provider: {
              issuer: base_url,
              authorization_endpoint: "#{base_url}/authorize",
              token_endpoint: "#{base_url}/token",
              jwks_uri: "#{base_url}/.well-known/jwks.json",
              signed_jwks_uri: "#{base_url}/.well-known/signed-jwks.json"
            }
          }
        }
        entity_statement_jwt = JWT.encode(entity_statement, OpenSSL::PKey::RSA.new(2048), "RS256")
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/openid-federation")
          .to_return(status: 200, body: entity_statement_jwt, headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/jwks.json")
          .to_return(status: 200, body: {keys: []}.to_json, headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/signed-jwks.json")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/authorize")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "text/html"})
        WebMock.stub_request(:get, "http://localhost:3000/token")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/userinfo")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})

        allow(OmniauthOpenidFederation::Federation::SignedJWKS).to receive(:fetch!).and_raise(
          OmniauthOpenidFederation::Federation::SignedJWKS::FetchError.new("Fetch failed")
        )

        result = described_class.test_local_endpoint(base_url: base_url)

        aggregate_failures do
          expect(result[:results]["Signed JWKS URI"][:status]).to eq(:error)
          expect(result[:results]["Signed JWKS URI"][:message]).to eq("Fetch failed")
        end
      end

      it "handles SignedJWKS::ValidationError gracefully" do
        # Stub the entity statement endpoint first (required for metadata)
        entity_statement = {
          iss: base_url,
          sub: base_url,
          metadata: {
            openid_provider: {
              issuer: base_url,
              authorization_endpoint: "#{base_url}/authorize",
              token_endpoint: "#{base_url}/token",
              jwks_uri: "#{base_url}/.well-known/jwks.json",
              signed_jwks_uri: "#{base_url}/.well-known/signed-jwks.json"
            }
          }
        }
        entity_statement_jwt = JWT.encode(entity_statement, OpenSSL::PKey::RSA.new(2048), "RS256")
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/openid-federation")
          .to_return(status: 200, body: entity_statement_jwt, headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/jwks.json")
          .to_return(status: 200, body: {keys: []}.to_json, headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/signed-jwks.json")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/authorize")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "text/html"})
        WebMock.stub_request(:get, "http://localhost:3000/token")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/userinfo")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})

        allow(OmniauthOpenidFederation::Federation::SignedJWKS).to receive(:fetch!).and_raise(
          OmniauthOpenidFederation::Federation::SignedJWKS::ValidationError.new("Validation failed")
        )

        result = described_class.test_local_endpoint(base_url: base_url)

        aggregate_failures do
          expect(result[:results]["Signed JWKS URI"][:status]).to eq(:error)
          expect(result[:results]["Signed JWKS URI"][:message]).to eq("Validation failed")
        end
      end

      it "handles generic errors gracefully" do
        # Stub the entity statement endpoint first (required for metadata)
        entity_statement = {
          iss: base_url,
          sub: base_url,
          metadata: {
            openid_provider: {
              issuer: base_url,
              authorization_endpoint: "#{base_url}/authorize",
              token_endpoint: "#{base_url}/token",
              jwks_uri: "#{base_url}/.well-known/jwks.json"
            }
          }
        }
        entity_statement_jwt = JWT.encode(entity_statement, OpenSSL::PKey::RSA.new(2048), "RS256")
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/openid-federation")
          .to_return(status: 200, body: entity_statement_jwt, headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/jwks.json")
          .to_return(status: 200, body: {keys: []}.to_json, headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/signed-jwks.json")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/jwt"})
        # Stub all other endpoints that might be called
        WebMock.stub_request(:get, "http://localhost:3000/authorize")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "text/html"})
        WebMock.stub_request(:get, "http://localhost:3000/token")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/userinfo")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})

        allow(OmniauthOpenidFederation::Jwks::Fetch).to receive(:run).and_raise(StandardError.new("Unexpected error"))

        result = described_class.test_local_endpoint(base_url: base_url)

        aggregate_failures do
          expect(result[:results]["JWKS URI"][:status]).to eq(:error)
          expect(result[:results]["JWKS URI"][:message]).to eq("Unexpected error")
        end
      end

      it "handles HTTP endpoint errors with warning status" do
        # Stub the HTTP request using WebMock
        # First stub the entity statement endpoint (required for metadata)
        entity_statement = {
          iss: base_url,
          sub: base_url,
          metadata: {
            openid_provider: {
              issuer: base_url,
              authorization_endpoint: "#{base_url}/authorize",
              token_endpoint: "#{base_url}/token",
              jwks_uri: "#{base_url}/.well-known/jwks.json"
            }
          }
        }
        entity_statement_jwt = JWT.encode(entity_statement, OpenSSL::PKey::RSA.new(2048), "RS256")
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/openid-federation")
          .to_return(status: 200, body: entity_statement_jwt, headers: {"Content-Type" => "application/jwt"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/jwks.json")
          .to_return(status: 200, body: {keys: []}.to_json, headers: {"Content-Type" => "application/json"})
        WebMock.stub_request(:get, "http://localhost:3000/.well-known/signed-jwks.json")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/jwt"})
        # Stub the authorization endpoint
        # The code uses Net::HTTP which WebMock should intercept
        WebMock.stub_request(:get, "http://localhost:3000/authorize")
          .to_return(status: 404, body: "Not Found", headers: {"Content-Type" => "text/html"})

        # Also stub the token endpoint in case it's called
        WebMock.stub_request(:get, "http://localhost:3000/token")
          .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})

        result = described_class.test_local_endpoint(base_url: base_url)

        aggregate_failures do
          expect(result[:results]["Authorization Endpoint"][:status]).to eq(:warning)
          expect(result[:results]["Authorization Endpoint"][:code]).to eq("404")
        end
      end
    end
  end

end

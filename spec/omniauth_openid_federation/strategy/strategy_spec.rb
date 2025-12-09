require "spec_helper"

RSpec.describe OmniAuth::Strategies::OpenIDFederation do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:app) { lambda { |env| [200, {}, ["Hello"]] } }
  let(:strategy) do
    described_class.new(
      app,
      client_options: {
        identifier: "test-client",
        redirect_uri: "https://example.com/callback",
        host: "provider.example.com",
        authorization_endpoint: "/oauth2/authorize",
        token_endpoint: "/oauth2/token",
        userinfo_endpoint: "/oauth2/userinfo",
        jwks_uri: "/.well-known/jwks.json",
        private_key: private_key
      }
    )
  end

  # Stub all HTTP requests for tests that use relative paths
  before do
    stub_relative_path_endpoints(host: "provider.example.com")

    # Generate a valid entity statement JWT for tests that fetch from URL
    provider_issuer = "https://provider.example.com"
    jwk = JWT::JWK.new(public_key)
    jwk_export = jwk.export
    entity_statement_payload = {
      iss: provider_issuer,
      sub: provider_issuer,
      iat: Time.now.to_i,
      exp: Time.now.to_i + 3600,
      jwks: {
        keys: [jwk_export]
      },
      metadata: {
        openid_provider: {
          issuer: provider_issuer,
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token",
          jwks_uri: "https://provider.example.com/.well-known/jwks.json"
        }
      }
    }
    entity_statement_header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
    entity_statement_jwt = JWT.encode(entity_statement_payload, private_key, "RS256", entity_statement_header)

    # Stub entity statement endpoint
    WebMock.stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
      .to_return(
        status: 200,
        body: entity_statement_jwt,
        headers: {"Content-Type" => "application/jwt"}
      )
  end

  describe "options" do
    it "has default scope" do
      expect(strategy.options.scope).to eq("openid")
    end

    it "has default response_type" do
      expect(strategy.options.response_type).to eq("code")
    end

    it "has default fetch_userinfo" do
      expect(strategy.options.fetch_userinfo).to be true
    end

    it "allows setting fetch_userinfo to false" do
      strategy.options.fetch_userinfo = false
      expect(strategy.options.fetch_userinfo).to be false
    end
  end

  describe "#authorize_uri - Security Enforcement" do
    let(:audience) { "https://provider.example.com" }
    let(:issuer) { "https://provider.example.com" }

    before do
      strategy.options.issuer = issuer
      strategy.options.audience = audience
      allow(strategy).to receive_messages(request: double(params: {}), session: {})
    end

    context "when private key is missing" do
      let(:strategy_without_key) do
        described_class.new(
          app,
          client_options: {
            identifier: "test-client",
            redirect_uri: "https://example.com/callback",
            host: "provider.example.com",
            authorization_endpoint: "/oauth2/authorize",
            token_endpoint: "/oauth2/token",
            userinfo_endpoint: "/oauth2/userinfo",
            jwks_uri: "/.well-known/jwks.json"
            # private_key is intentionally missing
          }
        )
      end

      it "raises ConfigurationError when private key is missing" do
        strategy_without_key.options.issuer = issuer
        strategy_without_key.options.audience = audience
        allow(strategy_without_key).to receive_messages(request: double(params: {}), session: {})

        expect {
          strategy_without_key.authorize_uri
        }.to raise_error(
          OmniauthOpenidFederation::ConfigurationError,
          /Private key is required for signed request objects/
        )
      end
    end

    context "when building authorization URL" do
      it "always uses signed request objects (RFC 9101 compliance)" do
        uri_string = strategy.authorize_uri
        uri = URI.parse(uri_string)

        # Verify that the URL contains ONLY the 'request' parameter (signed JWT)
        query_params = URI.decode_www_form(uri.query || "").to_h

        # The 'request' parameter must be present (signed JWT)
        request_param = query_params["request"]

        # Verify it's a valid JWT (3 parts for signed, 5 parts if encrypted)
        parts = request_param.split(".")
        # Verify it's signed (decode header to check alg)
        header = JSON.parse(Base64.urlsafe_decode64(parts[0]))
        aggregate_failures do
          expect(query_params).to have_key("request")
          expect(parts.length).to be >= 3 # At least 3 parts (JWT) or 5 (JWE)
          expect(header["alg"]).to eq("RS256")
          # Request objects use typ: "JWT", not "entity-statement+jwt" (that's only for entity statements)
          expect(header["typ"]).to eq("JWT")
        end
      end

      it "does NOT include authorization parameters in query string (only in JWT)" do
        uri_string = strategy.authorize_uri
        uri = URI.parse(uri_string)
        query_params = URI.decode_www_form(uri.query || "").to_h

        # RFC 9101: All authorization parameters MUST be inside the JWT
        # Only 'request' parameter should be in query string (per RFC 9101)
        forbidden_params = %w[client_id redirect_uri scope state nonce response_type response_mode]
        # Decode the request JWT to verify all params are inside
        request_jwt = query_params["request"]
        parts = request_jwt.split(".")
        payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))

        # Verify all required params are in the JWT payload
        aggregate_failures do
          forbidden_params.each do |param|
            expect(query_params).not_to have_key(param), "Parameter '#{param}' should not be in query string (must be in JWT)"
          end
          expect(payload).to have_key("client_id")
          expect(payload).to have_key("redirect_uri")
          expect(payload).to have_key("scope")
          expect(payload).to have_key("state")
          expect(payload).to have_key("response_type")
        end
      end

      it "ensures request object is always signed (never unsigned)" do
        uri_string = strategy.authorize_uri
        uri = URI.parse(uri_string)
        query_params = URI.decode_www_form(uri.query || "").to_h

        request_param = query_params["request"]

        # Verify it's a JWT (not plain text parameters)
        parts = request_param.split(".")
        # Verify signature is present (3rd part for JWT, 5th part for JWE)
        aggregate_failures do
          expect(parts.length).to be >= 3 # JWT has at least 3 parts
          if parts.length == 3
            # Signed JWT: header.payload.signature
            expect(parts[2]).to be_present # Signature must be present
          elsif parts.length == 5
            # Encrypted JWT (JWE): header.encrypted_key.iv.ciphertext.tag
            # This is also valid - signed then encrypted
            expect(parts[4]).to be_present # Tag must be present
          end
        end
      end

      it "does not send unencrypted sensitive data in query string" do
        strategy.options.scope = "openid profile email"

        # Pass acr_values via request parameters (not config)
        allow(strategy).to receive(:request).and_return(double(params: {"acr_values" => "urn:example:oidc:acr:level4"}))

        uri_string = strategy.authorize_uri
        uri = URI.parse(uri_string)
        query_params = URI.decode_www_form(uri.query || "").to_h

        # Sensitive parameters should NOT be in query string
        sensitive_params = %w[scope acr_values login_hint]
        # But they should be in the JWT
        request_jwt = query_params["request"]
        parts = request_jwt.split(".")
        payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))

        aggregate_failures do
          sensitive_params.each do |param|
            expect(query_params).not_to have_key(param), "Sensitive parameter '#{param}' should not be in query string"
          end
          expect(payload["scope"]).to eq("openid profile email")
          expect(payload["acr_values"]).to eq("urn:example:oidc:acr:level4")
        end
      end
    end

    context "when provider requires request object encryption" do
      let(:provider_public_key) { OpenSSL::PKey::RSA.new(2048).public_key }
      let(:provider_jwk) do
        {
          "kty" => "RSA",
          "kid" => "provider-enc-key",
          "use" => "enc",
          "n" => Base64.urlsafe_encode64(provider_public_key.n.to_s(2)),
          "e" => Base64.urlsafe_encode64(provider_public_key.e.to_s(2))
        }
      end

      before do
        # Mock provider metadata that requires encryption
        allow(strategy).to receive(:load_provider_metadata_for_encryption).and_return({
          "request_object_encryption_alg" => "RSA-OAEP",
          "request_object_encryption_enc" => "A128CBC-HS256",
          "jwks" => {
            "keys" => [provider_jwk]
          }
        })
      end

      it "encrypts the signed request object when provider requires it" do
        uri_string = strategy.authorize_uri
        uri = URI.parse(uri_string)
        query_params = URI.decode_www_form(uri.query || "").to_h

        request_param = query_params["request"]

        # When encrypted, JWE has 5 parts
        parts = request_param.split(".")
        # Verify it's encrypted (JWE header)
        header = JSON.parse(Base64.urlsafe_decode64(parts[0]))
        aggregate_failures do
          expect(parts.length).to eq(5), "Encrypted request object should have 5 parts (JWE format)"
          expect(header["enc"]).to eq("A128CBC-HS256")
          expect(header["alg"]).to eq("RSA-OAEP")
        end
      end
    end
  end
end

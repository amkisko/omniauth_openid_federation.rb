require "spec_helper"

RSpec.describe "OpenID Connect behavioral contract" do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:provider_issuer) { "https://provider.example.com" }
  let(:client_id) { "test-client-id" }
  let(:redirect_uri) { "https://example.com/callback" }

  let(:client) do
    OmniauthOpenidFederation::OidcClient.new(
      identifier: client_id,
      secret: nil,
      redirect_uri: redirect_uri,
      authorization_endpoint: "#{provider_issuer}/oauth2/authorize",
      token_endpoint: "#{provider_issuer}/oauth2/token",
      userinfo_endpoint: "#{provider_issuer}/oauth2/userinfo",
      jwks_uri: "#{provider_issuer}/.well-known/jwks.json"
    )
  end

  before do
    client.private_key = private_key
  end

  describe "token endpoint client assertion (private_key_jwt)" do
    it "sends the same OAuth parameters openid_connect used for authorization_code + jwt_bearer" do
      captured_body = nil
      stub_request(:post, "#{provider_issuer}/oauth2/token")
        .with { |request| captured_body = URI.decode_www_form(request.body).to_h }
        .to_return(
          status: 200,
          body: {
            access_token: "token",
            token_type: "Bearer",
            expires_in: 3600,
            id_token: JWT.encode({sub: "user-123"}, private_key, "RS256")
          }.to_json,
          headers: {"Content-Type" => "application/json"}
        )

      client.authorization_code = "auth-code"
      client.redirect_uri = redirect_uri
      client.access_token!(:jwt_bearer)

      expect(captured_body["grant_type"]).to eq("authorization_code")
      expect(captured_body["code"]).to eq("auth-code")
      expect(captured_body["redirect_uri"]).to eq(redirect_uri)
      expect(captured_body["client_assertion_type"]).to eq(
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
      )
      expect(captured_body["client_assertion"]).to be_present

      assertion_payload, = JWT.decode(
        captured_body["client_assertion"],
        private_key.public_key,
        true,
        {algorithm: "RS256"}
      )

      expect(assertion_payload["iss"]).to eq(client_id)
      expect(assertion_payload["sub"]).to eq(client_id)
      expect(assertion_payload["aud"]).to eq("#{provider_issuer}/oauth2/token")
      expect(assertion_payload["jti"]).to match(/\A\h{32}\z/)
      expect(assertion_payload["exp"] - assertion_payload["iat"]).to eq(180)
    end
  end

  describe "access token response surface" do
    it "exposes token fields consumed by the OmniAuth strategy" do
      id_token = JWT.encode({sub: "user-123", iss: provider_issuer}, private_key, "RS256")
      stub_request(:post, "#{provider_issuer}/oauth2/token")
        .to_return(
          status: 200,
          body: {
            access_token: "access-token-value",
            refresh_token: "refresh-token-value",
            token_type: "Bearer",
            expires_in: 3600,
            id_token: id_token
          }.to_json,
          headers: {"Content-Type" => "application/json"}
        )

      client.authorization_code = "auth-code"
      token = client.access_token!(:jwt_bearer)

      expect(token.access_token).to eq("access-token-value")
      expect(token.refresh_token).to eq("refresh-token-value")
      expect(token.expires_in).to eq(3600)
      expect(token.id_token).to eq(id_token)
      expect(token.client).to eq(client)
    end
  end

  describe "userinfo response surface" do
    it "returns a UserInfo object with raw_attributes for strategy decoding" do
      id_token = JWT.encode({sub: "user-123"}, private_key, "RS256")
      stub_request(:post, "#{provider_issuer}/oauth2/token")
        .to_return(
          status: 200,
          body: {access_token: "access-token-value", token_type: "Bearer", id_token: id_token}.to_json,
          headers: {"Content-Type" => "application/json"}
        )
      stub_request(:get, "#{provider_issuer}/oauth2/userinfo")
        .to_return(
          status: 200,
          body: {sub: "user-123", email: "user@example.com", name: "Test User"}.to_json,
          headers: {"Content-Type" => "application/json"}
        )

      client.authorization_code = "auth-code"
      token = client.access_token!(:jwt_bearer)
      userinfo = token.userinfo!

      expect(userinfo).to be_a(OmniauthOpenidFederation::UserInfo)
      expect(userinfo.raw_attributes[:sub]).to eq("user-123")
      expect(userinfo.raw_attributes[:email]).to eq("user@example.com")
      expect(userinfo.as_json).to include("email" => "user@example.com")
    end

    it "decrypts and verifies encrypted nested JWT userinfo responses" do
      provider_key = private_key
      signed_userinfo = JWT.encode(
        {sub: "user-123", email: "user@example.com"},
        provider_key,
        "RS256",
        {kid: "provider-signing-key"}
      )
      encrypted_userinfo = OmniauthOpenidFederation::Jwe.encrypt(
        signed_userinfo,
        private_key.public_key,
        alg: "RSA-OAEP",
        enc: "A128GCM"
      )
      jwk = JWT::JWK.new(provider_key, kid: "provider-signing-key").export

      stub_request(:post, "#{provider_issuer}/oauth2/token")
        .to_return(
          status: 200,
          body: {
            access_token: "access-token-value",
            token_type: "Bearer",
            id_token: JWT.encode({sub: "user-123"}, provider_key, "RS256")
          }.to_json,
          headers: {"Content-Type" => "application/json"}
        )
      stub_request(:get, "#{provider_issuer}/.well-known/jwks.json")
        .to_return(status: 200, body: {keys: [jwk]}.to_json, headers: {"Content-Type" => "application/json"})
      stub_request(:get, "#{provider_issuer}/oauth2/userinfo")
        .to_return(status: 200, body: encrypted_userinfo, headers: {"Content-Type" => "application/jwt"})

      client.authorization_code = "auth-code"
      token = client.access_token!(:jwt_bearer)
      userinfo = token.userinfo!

      expect(userinfo.raw_attributes[:sub]).to eq("user-123")
      expect(userinfo.raw_attributes[:email]).to eq("user@example.com")
    end
  end

  describe "JWE nested JWT handling" do
    it "round-trips sign-then-encrypt ID token plaintext used by federation providers" do
      signed_jwt = JWT.encode({sub: "user-123", exp: Time.now.to_i + 3600}, private_key, "RS256")
      encrypted = OmniauthOpenidFederation::Jwe.encrypt(
        signed_jwt,
        private_key.public_key,
        alg: "RSA-OAEP",
        enc: "A128CBC-HS256"
      )

      expect(OmniauthOpenidFederation::Jwe.encrypted?(encrypted)).to be(true)
      expect(OmniauthOpenidFederation::Jwe.decrypt(encrypted, private_key)).to eq(signed_jwt)
    end
  end
end

require "spec_helper"

RSpec.describe OmniauthOpenidFederation::OidcClient do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:provider_issuer) { "https://provider.example.com" }
  let(:client) do
    described_class.new(
      identifier: "test-client-id",
      secret: nil,
      redirect_uri: "https://example.com/callback",
      authorization_endpoint: "#{provider_issuer}/oauth2/authorize",
      token_endpoint: "#{provider_issuer}/oauth2/token",
      userinfo_endpoint: "#{provider_issuer}/oauth2/userinfo",
      jwks_uri: "#{provider_issuer}/.well-known/jwks.json"
    )
  end

  before do
    client.private_key = private_key
    stub_provider_endpoints(provider_issuer: provider_issuer)
  end

  describe "#access_token!" do
    it "exchanges authorization code using private_key_jwt" do
      id_token = JWT.encode({sub: "user-123"}, private_key, "RS256")
      stub_request(:post, "#{provider_issuer}/oauth2/token")
        .to_return(
          status: 200,
          body: {
            access_token: "access-token-value",
            token_type: "Bearer",
            expires_in: 3600,
            id_token: id_token
          }.to_json,
          headers: {"Content-Type" => "application/json"}
        )

      client.authorization_code = "auth-code"
      client.redirect_uri = "https://example.com/callback"

      access_token = client.access_token!(:jwt_bearer)

      expect(access_token).to be_a(OmniauthOpenidFederation::AccessToken)
      expect(access_token.access_token).to eq("access-token-value")
      expect(access_token.id_token).to eq(id_token)
    end
  end
end

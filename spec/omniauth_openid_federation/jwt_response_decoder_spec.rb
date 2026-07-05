require "spec_helper"

RSpec.describe OmniauthOpenidFederation::JwtResponseDecoder do
  let(:provider_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:client_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:provider_issuer) { "https://provider.example.com" }
  let(:jwks_uri) { "#{provider_issuer}/.well-known/jwks.json" }

  let(:strategy_options) do
    {
      client_options: {
        private_key: client_key,
        jwks_uri: jwks_uri,
        host: URI.parse(provider_issuer).host
      }
    }
  end

  def encode_provider_jwt(payload)
    JWT.encode(payload, provider_key, "RS256", {kid: "provider-signing-key"})
  end

  before do
    WebMock.reset!
    jwk = JWT::JWK.new(provider_key, kid: "provider-signing-key").export
    stub_request(:get, jwks_uri)
      .to_return(status: 200, body: {keys: [jwk]}.to_json, headers: {"Content-Type" => "application/json"})
  end

  it "decrypts and verifies nested encrypted userinfo JWT responses" do
    signed_jwt = encode_provider_jwt(sub: "user-123", email: "user@example.com")
    encrypted = OmniauthOpenidFederation::Jwe.encrypt(
      signed_jwt,
      client_key.public_key,
      alg: "RSA-OAEP",
      enc: "A128GCM"
    )

    claims = described_class.new(strategy_options: strategy_options).decode(encrypted)

      expect(claims["sub"]).to eq("user-123")
      expect(claims["email"]).to eq("user@example.com")
  end

  it "verifies signed JWT responses without encryption" do
    signed_jwt = encode_provider_jwt(sub: "user-456")

    claims = described_class.new(strategy_options: strategy_options).decode(signed_jwt)

      expect(claims["sub"]).to eq("user-456")
  end

  it "parses plain JSON responses" do
    claims = described_class.new(strategy_options: strategy_options).decode(
      {sub: "user-789", name: "Plain JSON"}.to_json
    )

      expect(claims["sub"]).to eq("user-789")
      expect(claims["name"]).to eq("Plain JSON")
  end
end

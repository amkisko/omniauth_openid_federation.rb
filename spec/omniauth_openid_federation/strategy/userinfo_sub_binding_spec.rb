require "spec_helper"

RSpec.describe OmniAuth::Strategies::OpenIDFederation do
  include StrategyTestHelpers

  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:client_id) { "client-123" }
  let(:provider_issuer) { "https://op.example.com" }
  let(:redirect_uri) { "https://rp.example.com/callback" }

  def build_strategy
    described_class.new(nil, name: "openid_federation",
      client_options: {
        identifier: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key,
        host: "op.example.com",
        authorization_endpoint: "/oauth2/authorize",
        token_endpoint: "/oauth2/token",
        userinfo_endpoint: "/oauth2/userinfo"
      },
      issuer: provider_issuer,
      audience: provider_issuer,
      fetch_userinfo: true)
  end

  it "rejects userinfo whose sub differs from the ID token sub" do
    strategy = build_strategy
    attach_access_token(strategy, id_token: "id-token.jwt", userinfo: {"sub" => "user-b", "name" => "Other"})
    allow(strategy).to receive(:decode_id_token).and_return(
      OmniauthOpenidFederation::IdToken.new(iss: provider_issuer, sub: "user-a", aud: client_id)
    )
    allow(strategy).to receive(:decode_userinfo).and_return({"sub" => "user-b", "name" => "Other"})

    expect { strategy.send(:raw_info) }.to raise_error(
      OmniauthOpenidFederation::ValidationError,
      /UserInfo sub must match ID token sub/
    )
  end

  it "keeps ID token sub when userinfo matches" do
    strategy = build_strategy
    attach_access_token(strategy, id_token: "id-token.jwt", userinfo: {"sub" => "user-a", "name" => "Ada"})
    allow(strategy).to receive(:decode_id_token).and_return(
      OmniauthOpenidFederation::IdToken.new(iss: provider_issuer, sub: "user-a", aud: client_id, exp: Time.now.to_i + 60, iat: Time.now.to_i)
    )
    allow(strategy).to receive(:decode_userinfo).and_return({"sub" => "user-a", "name" => "Ada"})

    info = strategy.send(:raw_info)

    aggregate_failures do
      expect(info["sub"]).to eq("user-a")
      expect(info["name"]).to eq("Ada")
    end
  end
end

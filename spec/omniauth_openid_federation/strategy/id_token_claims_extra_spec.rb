require "spec_helper"

RSpec.describe OmniAuth::Strategies::OpenIDFederation do
  include StrategyTestHelpers

  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:client_id) { "client-123" }
  let(:provider_issuer) { "https://op.example.com" }
  let(:redirect_uri) { "https://rp.example.com/callback" }
  let(:signed_acr) { "urn:example:acr:substantial" }
  let(:userinfo_acr) { "urn:example:acr:low" }
  let(:signed_identity_claim) { "signed-subject-number" }
  let(:userinfo_identity_claim) { "userinfo-subject-number" }

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

  def diverging_userinfo_hash
    {
      "sub" => "user-a",
      "name" => "Ada",
      "acr" => userinfo_acr,
      "national_number" => userinfo_identity_claim
    }
  end

  def signed_id_token
    now = Time.now.to_i
    OmniauthOpenidFederation::IdToken.new(
      iss: provider_issuer,
      sub: "user-a",
      aud: client_id,
      exp: now + 60,
      iat: now,
      acr: signed_acr,
      national_number: signed_identity_claim
    )
  end

  def attach_diverging_userinfo(strategy)
    attach_access_token(strategy, id_token: "id-token.jwt", userinfo: diverging_userinfo_hash)
    allow(strategy).to receive(:decode_id_token).and_return(signed_id_token)
    allow(strategy).to receive(:decode_userinfo).and_return(diverging_userinfo_hash)
  end

  it "keeps signed authentication and identity claims on id_token_claims when UserInfo differs" do
    strategy = build_strategy
    attach_diverging_userinfo(strategy)

    raw_info = strategy.raw_info
    id_token_claims = strategy.extra[:id_token_claims]

    aggregate_failures do
      expect(raw_info["acr"]).to eq(userinfo_acr)
      expect(raw_info["national_number"]).to eq(userinfo_identity_claim)
      expect(raw_info["name"]).to eq("Ada")
      expect(raw_info["sub"]).to eq("user-a")

      expect(id_token_claims).to include(
        "acr" => signed_acr,
        "national_number" => signed_identity_claim,
        "sub" => "user-a",
        "iss" => provider_issuer
      )
      expect(id_token_claims).not_to have_key("name")
    end
  end

  it "exposes id_token_claims on auth_hash.extra" do
    strategy = build_strategy
    attach_diverging_userinfo(strategy)
    access_token = strategy.instance_variable_get(:@access_token)
    allow(access_token).to receive_messages(
      access_token: "access-token",
      refresh_token: nil,
      expires_in: nil
    )

    auth_hash = strategy.auth_hash

    expect(auth_hash.extra[:id_token_claims]["acr"]).to eq(signed_acr)
  end

  it "uses verified ID token claims when UserInfo fetching is disabled" do
    strategy = build_strategy
    strategy.options.fetch_userinfo = false
    now = Time.now.to_i
    id_token = OmniauthOpenidFederation::IdToken.new(
      iss: provider_issuer,
      sub: "user-a",
      aud: client_id,
      exp: now + 60,
      iat: now,
      acr: signed_acr
    )
    attach_access_token(strategy, id_token: "id-token.jwt")
    allow(strategy).to receive(:decode_id_token).and_return(id_token)

    aggregate_failures do
      expect(strategy.raw_info["acr"]).to eq(signed_acr)
      expect(strategy.extra[:id_token_claims]["acr"]).to eq(signed_acr)
    end
  end
end

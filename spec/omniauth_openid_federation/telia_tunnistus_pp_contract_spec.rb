require "spec_helper"

RSpec.describe "Telia Tunnistus PP provider contract" do
  let(:fixture_path) do
    File.expand_path("../fixtures/files/telia_tunnistus_pp_entity_statement.jwt", __dir__)
  end

  let(:entity_statement_content) { File.read(fixture_path).strip }

  it "loads the public Telia PP entity statement fixture" do
    expect(entity_statement_content).to match(/\A[\w\-.]+\z/)
  end

  it "exposes federation metadata required for RP integration" do
    entity_statement = OmniauthOpenidFederation::Federation::EntityStatement.new(entity_statement_content)
    parsed = entity_statement.parse

    aggregate_failures do
      expect(parsed[:issuer]).to eq("https://tunnistus-pp.telia.fi")
      expect(parsed[:sub]).to eq("https://tunnistus-pp.telia.fi")

      provider_metadata = parsed.dig(:metadata, :openid_provider) || parsed.dig("metadata", "openid_provider")
      expect(provider_metadata).to be_present
      expect(provider_metadata[:issuer] || provider_metadata["issuer"]).to eq("https://tunnistus-pp.telia.fi/uas")
      expect(provider_metadata[:token_endpoint] || provider_metadata["token_endpoint"])
        .to eq("https://tunnistus-pp.telia.fi/uas/oauth2/token")
      expect(provider_metadata[:signed_jwks_uri] || provider_metadata["signed_jwks_uri"])
        .to eq("https://tunnistus-pp.telia.fi/openid_provider/signed_jwks.jwt")
    end
  end

  it "round-trips nested JWT encryption for both Telia-supported content enc algorithms" do
    encryption_key = OpenSSL::PKey::RSA.new(2048)
    signed_jwt = JWT.encode({sub: "user-123", exp: Time.now.to_i + 3600}, encryption_key, "RS256")

    %w[A128GCM A128CBC-HS256].each do |content_encryption|
      encrypted = OmniauthOpenidFederation::Jwe.encrypt(
        signed_jwt,
        encryption_key.public_key,
        alg: "RSA-OAEP",
        enc: content_encryption
      )

      expect(OmniauthOpenidFederation::Jwe.decrypt(encrypted, encryption_key)).to eq(signed_jwt)
    end
  end
end

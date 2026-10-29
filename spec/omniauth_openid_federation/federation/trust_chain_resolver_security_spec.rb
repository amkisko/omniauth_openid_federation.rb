require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Federation::TrustChainResolver do
  let(:leaf_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:ta_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:leaf_jwk) { JWT::JWK.new(leaf_key.public_key).export }
  let(:ta_jwk) { JWT::JWK.new(ta_key.public_key).export }

  let(:leaf_entity_id) { "https://rp.example.com" }
  let(:trust_anchor_id) { "https://ta.example.com" }

  let(:trust_anchors) do
    [
      {
        entity_id: trust_anchor_id,
        jwks: {keys: [ta_jwk]}
      }
    ]
  end

  def sign_statement(iss:, sub:, private_key:, jwk_export:, authority_hints: nil, metadata: {})
    payload = {
      iss: iss,
      sub: sub,
      iat: Time.now.to_i,
      exp: Time.now.to_i + 3600,
      jwks: {keys: [jwk_export]},
      metadata: metadata
    }
    payload[:authority_hints] = authority_hints if authority_hints
    header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid] || jwk_export["kid"]}
    jwt = JWT.encode(payload, private_key, "RS256", header)
    OmniauthOpenidFederation::Federation::EntityStatement.new(jwt)
  end

  describe "entity id binding" do
    it "rejects a leaf configuration whose iss claims a trust anchor id" do
      forged = sign_statement(
        iss: trust_anchor_id,
        sub: trust_anchor_id,
        private_key: leaf_key,
        jwk_export: leaf_jwk
      )

      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!)
        .with("#{leaf_entity_id}/.well-known/openid-federation", timeout: 10)
        .and_return(forged)

      resolver = described_class.new(
        leaf_entity_id: leaf_entity_id,
        trust_anchors: trust_anchors
      )

      expect { resolver.resolve! }.to raise_error(
        OmniauthOpenidFederation::ValidationError,
        /iss\/sub must equal requested entity id/
      )
    end
  end

  describe "pinned trust anchor JWKS" do
    it "rejects a trust anchor configuration signed with a non-pinned key" do
      leaf = sign_statement(
        iss: leaf_entity_id,
        sub: leaf_entity_id,
        private_key: leaf_key,
        jwk_export: leaf_jwk,
        authority_hints: [trust_anchor_id]
      )

      attacker_key = OpenSSL::PKey::RSA.new(2048)
      attacker_jwk = JWT::JWK.new(attacker_key.public_key).export
      forged_ta = sign_statement(
        iss: trust_anchor_id,
        sub: trust_anchor_id,
        private_key: attacker_key,
        jwk_export: attacker_jwk
      )

      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!)
        .with("#{leaf_entity_id}/.well-known/openid-federation", timeout: 10)
        .and_return(leaf)
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!)
        .with("#{trust_anchor_id}/.well-known/openid-federation", timeout: 10)
        .and_return(forged_ta)

      resolver = described_class.new(
        leaf_entity_id: leaf_entity_id,
        trust_anchors: trust_anchors
      )

      expect { resolver.resolve! }.to raise_error(
        OmniauthOpenidFederation::ValidationError,
        /no valid authority found|signature/i
      )
    end

    it "resolves leaf to trust anchor when the anchor verifies under pinned JWKS" do
      leaf = sign_statement(
        iss: leaf_entity_id,
        sub: leaf_entity_id,
        private_key: leaf_key,
        jwk_export: leaf_jwk,
        authority_hints: [trust_anchor_id]
      )
      ta = sign_statement(
        iss: trust_anchor_id,
        sub: trust_anchor_id,
        private_key: ta_key,
        jwk_export: ta_jwk
      )
      subordinate = sign_statement(
        iss: trust_anchor_id,
        sub: leaf_entity_id,
        private_key: ta_key,
        jwk_export: ta_jwk
      )

      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!)
        .with("#{leaf_entity_id}/.well-known/openid-federation", timeout: 10)
        .and_return(leaf)
      allow(OmniauthOpenidFederation::Federation::EntityStatement).to receive(:fetch!)
        .with("#{trust_anchor_id}/.well-known/openid-federation", timeout: 10)
        .and_return(ta)

      http_response = instance_double(HTTP::Response, status: instance_double(HTTP::Response::Status, success?: true), body: subordinate.entity_statement)
      allow(OmniauthOpenidFederation::HttpClient).to receive(:get)
        .with("#{trust_anchor_id}/.well-known/openid-federation/fetch?iss=#{CGI.escape(trust_anchor_id)}&sub=#{CGI.escape(leaf_entity_id)}", timeout: 10)
        .and_return(http_response)

      resolver = described_class.new(
        leaf_entity_id: leaf_entity_id,
        trust_anchors: trust_anchors
      )

      chain = resolver.resolve!

      expect(chain.length).to eq(2)
      expect(chain.first).to eq(leaf)
    end
  end
end

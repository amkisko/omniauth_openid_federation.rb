# frozen_string_literal: true

require "spec_helper"
require "omniauth_openid_federation/rack_endpoint"

RSpec.describe OmniauthOpenidFederation::RackEndpoint do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:issuer) { "https://provider.example.com" }
  let(:jwks) do
    {"keys" => [JWT::JWK.new(private_key.public_key).export.transform_keys(&:to_s)]}
  end
  let(:metadata) do
    {
      "openid_provider" => {
        "issuer" => issuer,
        "authorization_endpoint" => "#{issuer}/oauth2/authorize",
        "token_endpoint" => "#{issuer}/oauth2/token",
        "jwks_uri" => "#{issuer}/.well-known/jwks.json",
        "signed_jwks_uri" => "#{issuer}/.well-known/signed-jwks.json"
      }
    }
  end

  before do
    OmniauthOpenidFederation::FederationEndpoint.instance_variable_set(:@configuration, nil)
    OmniauthOpenidFederation::FederationEndpoint.configure do |config|
      config.issuer = issuer
      config.subject = issuer
      config.private_key = private_key
      config.jwks = jwks
      config.metadata = metadata
    end
  end

  after do
    OmniauthOpenidFederation::FederationEndpoint.instance_variable_set(:@configuration, nil)
  end

  it "serves entity-statement content type from RackEndpoint" do
    endpoint = OmniauthOpenidFederation::RackEndpoint.new
    status, headers, = endpoint.call(Rack::MockRequest.env_for("/openid-federation"))
    expect(status).to eq(200)
    expect(headers["Content-Type"]).to eq(OmniauthOpenidFederation::Constants::CONTENT_TYPE_ENTITY_STATEMENT_JWT)
  end

  it "aliases signed-jwks.jwt and signed-jwks.jose to the signed JWKS handler" do
    endpoint = OmniauthOpenidFederation::RackEndpoint.new
    %w[/signed-jwks.json /signed-jwks.jwt /signed-jwks.jose].each do |path|
      status, headers, body = endpoint.call(Rack::MockRequest.env_for(path))
      aggregate_failures do
        expect(status).to eq(200)
        expect(headers["Content-Type"]).to eq(OmniauthOpenidFederation::Constants::CONTENT_TYPE_JWT)
        expect(body.first.split(".").length).to eq(3)
      end
    end
  end
end

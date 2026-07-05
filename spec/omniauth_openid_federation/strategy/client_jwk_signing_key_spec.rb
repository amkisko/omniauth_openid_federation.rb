require "spec_helper"

RSpec.describe OmniAuth::Strategies::OpenIDFederation, "#client_jwk_signing_key" do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:client_id) { "test-client-id" }
  let(:redirect_uri) { "https://example.com/users/auth/openid_federation/callback" }

  it "returns configured client_jwk_signing_key value when explicitly set" do
    jwks_json = '{"keys":[]}'
    strategy = described_class.new(
      nil,
      client_jwk_signing_key: jwks_json,
      client_options: {
        identifier: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      }
    )

    expect(strategy.options[:client_jwk_signing_key]).to eq(jwks_json)
  end

  it "extracts JWKS from client entity statement file when configured value is nil" do
    entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
    jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
    entity_statement = {
      iss: "https://client.example.com",
      sub: "https://client.example.com",
      iat: Time.now.to_i,
      exp: Time.now.to_i + 3600,
      jwks: {keys: [jwk]}
    }
    header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk[:kid]}
    jwt = JWT.encode(entity_statement, private_key, "RS256", header)
    File.write(entity_statement_path, jwt)

    strategy = described_class.new(
      nil,
      client_entity_statement_path: entity_statement_path,
      client_options: {
        identifier: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      }
    )

    result = strategy.options[:client_jwk_signing_key]
    parsed = JSON.parse(result)
    aggregate_failures do
      expect(result).to be_a(String)
      expect(parsed).to have_key("keys")
    end
  end

  it "returns nil when not available" do
    strategy = described_class.new(
      nil,
      client_options: {
        identifier: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      }
    )

    expect(strategy.options[:client_jwk_signing_key]).to be_nil
  end

  it "preserves empty configured client_jwk_signing_key in options" do
    strategy = described_class.new(
      nil,
      client_jwk_signing_key: "",
      client_options: {
        identifier: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      }
    )

    expect(strategy.options[:client_jwk_signing_key]).to eq("")
  end

  it "does not auto-extract JWKS when configured value is empty string" do
    entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
    jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
    entity_statement = {
      iss: "https://client.example.com",
      sub: "https://client.example.com",
      jwks: {keys: [jwk]}
    }
    jwt = JWT.encode(entity_statement, private_key, "RS256")
    File.write(entity_statement_path, jwt)

    strategy = described_class.new(
      nil,
      client_jwk_signing_key: "",
      client_entity_statement_path: entity_statement_path,
      client_options: {
        identifier: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      }
    )

    expect(strategy.options[:client_jwk_signing_key]).to eq("")
  end

  it "returns nil when entity statement has no JWKS" do
    entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
    entity_statement = {
      iss: "https://client.example.com",
      sub: "https://client.example.com"
    }
    jwt = JWT.encode(entity_statement, private_key, "RS256")
    File.write(entity_statement_path, jwt)

    strategy = described_class.new(
      nil,
      client_entity_statement_path: entity_statement_path,
      client_options: {
        identifier: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      }
    )

    expect(strategy.options[:client_jwk_signing_key]).to be_nil
  end

  it "dynamically sets client_jwk_signing_key from entity statement via options accessor" do
    entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
    jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
    entity_statement = {
      iss: "https://client.example.com",
      sub: "https://client.example.com",
      jwks: {keys: [jwk]}
    }
    jwt = JWT.encode(entity_statement, private_key, "RS256")
    File.write(entity_statement_path, jwt)

    strategy = described_class.new(
      nil,
      client_entity_statement_path: entity_statement_path,
      client_options: {
        identifier: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      }
    )

    expect(strategy.options[:client_jwk_signing_key]).to be_a(String)
  end

  it "preserves existing client_jwk_signing_key value in options accessor" do
    jwks_json = '{"keys":[]}'
    strategy = described_class.new(
      nil,
      client_jwk_signing_key: jwks_json,
      client_options: {
        identifier: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key
      }
    )

    expect(strategy.options[:client_jwk_signing_key]).to eq(jwks_json)
  end
end

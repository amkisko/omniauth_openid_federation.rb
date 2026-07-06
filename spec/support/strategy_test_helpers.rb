# frozen_string_literal: true

module StrategyTestHelpers
  CLIENT_ISSUER = "https://client.example.com"

  def provider_authorization_endpoint
    "#{provider_issuer}/oauth2/authorize"
  end

  def provider_token_endpoint
    "#{provider_issuer}/oauth2/token"
  end

  def provider_openid_metadata(overrides = {})
    {
      issuer: provider_issuer,
      authorization_endpoint: provider_authorization_endpoint,
      token_endpoint: provider_token_endpoint,
      jwks_uri: "#{provider_issuer}/.well-known/jwks.json"
    }.merge(overrides)
  end

  def provider_entity_statement_payload(overrides = {})
    jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
    {
      iss: provider_issuer,
      sub: provider_issuer,
      jwks: {keys: [jwk]},
      metadata: {openid_provider: provider_openid_metadata}
    }.merge(overrides) do |_key, left, right|
      (left.is_a?(Hash) && right.is_a?(Hash)) ? left.merge(right) : right
    end
  end

  def client_entity_statement_payload(overrides = {})
    {
      iss: CLIENT_ISSUER,
      sub: CLIENT_ISSUER,
      jwks: {keys: []}
    }.merge(overrides)
  end

  def write_entity_statement_jwt(path, payload, encoder: :simple)
    jwt =
      case encoder
      when :entity
        encode_entity_statement(payload)
      else
        JWT.encode(payload, private_key, "RS256")
      end
    File.write(path, jwt)
    path
  end

  def entity_statement_tempfile(payload, encoder: :simple, prefix: "entity")
    path = Tempfile.new([prefix, ".jwt"]).path
    write_entity_statement_jwt(path, payload, encoder: encoder)
    path
  end

  def write_provider_entity_statement_file(overrides = {}, encoder: :simple)
    entity_statement_tempfile(provider_entity_statement_payload(overrides), encoder: encoder, prefix: "provider_entity")
  end

  def write_client_entity_statement_file(overrides = {}, encoder: :simple)
    entity_statement_tempfile(client_entity_statement_payload(overrides), encoder: encoder, prefix: "entity")
  end

  def write_provider_jwks_entity_statement(overrides = {})
    path = entity_statement_path_under_config
    jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
    payload = {
      iss: provider_issuer,
      sub: provider_issuer,
      jwks: {keys: [jwk]},
      metadata: {
        openid_provider: {
          authorization_endpoint: provider_authorization_endpoint,
          token_endpoint: provider_token_endpoint
        }
      }
    }.merge(overrides) do |_key, left, right|
      (left.is_a?(Hash) && right.is_a?(Hash)) ? left.merge(right) : right
    end
    write_entity_statement_jwt(path, payload, encoder: :entity)
    {path: path, jwk: jwk}
  end

  def decode_client_options(overrides = {})
    {
      identifier: client_id,
      redirect_uri: redirect_uri,
      private_key: private_key
    }.merge(overrides)
  end

  def relative_path_client_options(overrides = {})
    decode_client_options(
      host: URI.parse(provider_issuer).host,
      authorization_endpoint: "/oauth2/authorize",
      token_endpoint: "/oauth2/token"
    ).merge(overrides)
  end

  def build_strategy(app = nil, **options)
    client_options = options.delete(:client_options)
    strategy = described_class.new(
      app,
      **options,
      client_options: decode_client_options(client_options || {})
    )
    stub_strategy_request_session(strategy)
    strategy
  end

  def build_decode_strategy(app = nil, **options)
    kwargs = {issuer: provider_issuer, send_nonce: false}.merge(options)
    client_options = kwargs.delete(:client_options)
    described_class.new(
      app,
      **kwargs,
      client_options: decode_client_options(client_options || {})
    )
  end

  def stub_strategy_request_session(strategy)
    allow(strategy).to receive_messages(request: double(params: {}), session: {})
  end

  def authorize_request_payload(uri)
    query_params = URI.decode_www_form(URI.parse(uri).query || "").to_h
    parts = query_params.fetch("request").split(".")
    JSON.parse(Base64.urlsafe_decode64(parts[1]))
  end

  def attach_access_token(strategy, id_token:, userinfo: nil)
    token_attrs = {id_token: id_token}
    token_attrs[:userinfo!] = userinfo unless userinfo.nil?
    strategy.instance_variable_set(:@access_token, double(token_attrs))
  end

  def encode_id_token_for_provider_jwk(jwk, payload = {}, header_extras: {})
    claims = {
      iss: provider_issuer,
      sub: "user-123",
      aud: client_id,
      exp: Time.now.to_i + 3600,
      iat: Time.now.to_i
    }.merge(payload)
    header = {alg: "RS256", typ: "JWT", kid: jwk[:kid]}.merge(header_extras)
    JWT.encode(claims, private_key, "RS256", header)
  end

  def build_decode_strategy_for_authorize(**options)
    strategy = build_decode_strategy(nil, **options)
    stub_strategy_request_session(strategy)
    strategy
  end

  def write_client_entity_statement_under_config(overrides = {})
    path = entity_statement_path_under_config
    write_entity_statement_jwt(path, client_entity_statement_payload(overrides), encoder: :entity)
    path
  end

  def configure_federation_endpoint_for_automatic_registration(client_issuer: CLIENT_ISSUER)
    jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
    OmniauthOpenidFederation::FederationEndpoint.configure do |config|
      config.issuer = client_issuer
      config.private_key = private_key
      config.jwks = {keys: [jwk]}
      config.metadata = {openid_client: {redirect_uris: ["https://example.com/callback"]}}
    end
  end

  def stub_provider_federation_entity_statement_endpoint
    entity_statement_jwt = encode_entity_statement(provider_entity_statement_payload)
    WebMock.stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
      .to_return(status: 200, body: entity_statement_jwt, headers: {"Content-Type" => "application/jwt"})
  end

  def write_simple_entity_statement_file(payload, prefix: "entity")
    entity_statement_tempfile(payload, encoder: :simple, prefix: prefix)
  end

  def build_automatic_strategy(**options)
    build_strategy(
      nil,
      entity_statement_path: provider_entity_statement_path,
      client_registration_type: :automatic,
      **options
    )
  end

  def stub_rails_cache_double(fetch: nil, read: nil, write: true, fetch_raises: nil)
    rails_cache = double(read: read, write: write)
    if fetch_raises
      allow(rails_cache).to receive(:fetch).and_raise(fetch_raises)
    else
      allow(rails_cache).to receive(:fetch).and_return(fetch)
    end
    stub_const("Rails", double(cache: rails_cache, root: nil))
    rails_cache
  end

  def write_provider_entity_statement_for_metadata(openid_provider_overrides = {}, **payload_overrides)
    write_provider_entity_statement_file(
      provider_entity_statement_payload(
        payload_overrides.merge(metadata: {openid_provider: provider_openid_metadata(openid_provider_overrides)})
      ),
      encoder: :entity
    )
  end

  def write_invalid_client_entity_statement_file(content = "dummy.jwt")
    path = Tempfile.new(["entity", ".jwt"]).path
    File.write(path, content)
    path
  end

  def attach_decoded_userinfo(strategy, jwk, payload = {})
    attach_access_token(
      strategy,
      id_token: encode_id_token_for_provider_jwk(jwk, payload),
      userinfo: double(raw_attributes: {sub: payload[:sub] || "user-123"})
    )
  end

  def automatic_registration_strategy(client_overrides: {}, strategy_options: {})
    build_strategy(
      nil,
      entity_statement_path: write_provider_entity_statement_file,
      client_entity_statement_path: write_client_entity_statement_file(client_overrides),
      client_registration_type: :automatic,
      **strategy_options
    )
  end
end

RSpec.shared_context "strategy helpers" do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:provider_issuer) { "https://provider.example.com" }
  let(:client_id) { "test-client-id" }
  let(:redirect_uri) { "https://example.com/users/auth/openid_federation/callback" }

  include StrategyTestHelpers

  before do
    stub_relative_path_endpoints(host: URI.parse(provider_issuer).host)
  end
end

RSpec.shared_context "decode with provider jwks" do
  let(:provider_jwks_setup) { write_provider_jwks_entity_statement }
  let(:entity_statement_path) { provider_jwks_setup[:path] }
  let(:provider_jwk) { provider_jwks_setup[:jwk] }
  let(:decode_strategy_options) { {} }
  let(:decode_strategy) do
    build_decode_strategy(nil, entity_statement_path: entity_statement_path, **decode_strategy_options)
  end
  let(:valid_id_token) { encode_id_token_for_provider_jwk(provider_jwk) }
end

RSpec.shared_context "automatic client registration" do
  let(:provider_entity_statement_path) { write_provider_entity_statement_file }

  before { configure_federation_endpoint_for_automatic_registration }
end

RSpec.shared_context "strategy federation endpoint stub" do
  before { stub_provider_federation_entity_statement_endpoint }
end

RSpec.configure do |config|
  config.include_context "strategy helpers", type: :strategy
end

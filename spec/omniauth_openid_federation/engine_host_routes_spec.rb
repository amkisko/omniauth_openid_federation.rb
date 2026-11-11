# frozen_string_literal: true

require "rails_helper"

begin
  require "rails"
  require "action_controller/railtie"
  require "action_dispatch/railtie"
  require "rack/test"
rescue LoadError
  return
end

RSpec.describe OmniauthOpenidFederation::WellKnownRoutes do
  include Rack::Test::Methods

  def app
    Rails.application
  end

  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:issuer) { "https://rp.example.com" }
  let(:well_known_paths) do
    %w[
      /.well-known/openid-federation
      /.well-known/jwks.json
      /.well-known/signed-jwks.json
      /.well-known/signed-jwks.jwt
      /.well-known/signed-jwks.jose
    ]
  end

  before do
    OmniauthOpenidFederation::FederationEndpoint.instance_variable_set(:@configuration, nil)
    OmniauthOpenidFederation::CacheAdapter.reset!
    OmniauthOpenidFederation::FederationEndpoint.configure do |config|
      config.issuer = issuer
      config.subject = issuer
      config.private_key = private_key
      config.jwks = {"keys" => [JWT::JWK.new(private_key.public_key).export.stringify_keys]}
      config.metadata = {
        openid_relying_party: {
          client_registration_types: ["automatic"]
        }
      }
    end
  end

  after do
    OmniauthOpenidFederation::FederationEndpoint.instance_variable_set(:@configuration, nil)
    OmniauthOpenidFederation::CacheAdapter.reset!
  end

  def redraw_host_routes(&block)
    Rails.application.routes.clear!
    Rails.application.routes.draw(&block)
  end

  it "serves well-known paths when the Engine is mounted at / in one draw block" do
    redraw_host_routes do
      get "/health", to: proc { [200, {}, ["ok"]] }
      mount OmniauthOpenidFederation::Engine => "/"
    end

    well_known_paths.each do |path|
      get path
      expect(last_response.status).to eq(200), "#{path} expected 200, got #{last_response.status}"
    end
    get "/health"
    expect(last_response.status).to eq(200)
  end

  it "serves well-known paths when drawn on the host mapper" do
    redraw_host_routes do
      OmniauthOpenidFederation.draw_well_known_routes(self)
      get "/health", to: proc { [200, {}, ["ok"]] }
    end

    well_known_paths.each do |path|
      get path
      expect(last_response.status).to eq(200), "#{path} expected 200, got #{last_response.status}"
    end
  end

  it "loses the Engine mount when config/routes.rb nests a second routes.draw" do
    redraw_host_routes do
      mount OmniauthOpenidFederation::Engine => "/"
      Rails.application.routes.draw do
        get "/health", to: proc { [200, {}, ["ok"]] }
      end
    end

    get "/.well-known/openid-federation"
    expect(last_response.status).to eq(404)
    get "/health"
    expect(last_response.status).to eq(200)
  end
end

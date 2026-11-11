# frozen_string_literal: true

module OmniauthOpenidFederation
  # Shared well-known route definitions for Engine mount and host draw.
  #
  # Supported host patterns (pick one):
  # 1. `mount OmniauthOpenidFederation::Engine => "/"` inside a single `routes.draw` block
  # 2. `OmniauthOpenidFederation.draw_well_known_routes(self)` inside the host `routes.draw`
  # 3. Rack: `map "/.well-known" { run RackEndpoint.new }`
  #
  # Do not call `Rails.application.routes.draw` again inside `config/routes.rb`; a second
  # draw clears routes already registered in that file, including an Engine mount.
  module WellKnownRoutes
    module_function

    # @param mapper [ActionDispatch::Routing::Mapper]
    def draw(mapper)
      mapper.instance_eval do
        get "/.well-known/openid-federation",
          to: "omniauth_openid_federation/federation#show",
          as: :openid_federation

        get "/.well-known/openid-federation/fetch",
          to: "omniauth_openid_federation/federation#fetch",
          as: :openid_federation_fetch

        get "/.well-known/jwks.json",
          to: "omniauth_openid_federation/federation#jwks",
          as: :openid_federation_jwks

        get "/.well-known/signed-jwks.json",
          to: "omniauth_openid_federation/federation#signed_jwks",
          as: :openid_federation_signed_jwks

        get "/.well-known/signed-jwks.jwt",
          to: "omniauth_openid_federation/federation#signed_jwks",
          as: :openid_federation_signed_jwks_jwt

        get "/.well-known/signed-jwks.jose",
          to: "omniauth_openid_federation/federation#signed_jwks",
          as: :openid_federation_signed_jwks_jose
      end
    end
  end

  # Draw absolute well-known routes on the host application mapper.
  #
  # @param mapper [ActionDispatch::Routing::Mapper]
  # @example
  #   Rails.application.routes.draw do
  #     OmniauthOpenidFederation.draw_well_known_routes(self) if ENV["OPENID_ENABLED"] == "true"
  #   end
  def self.draw_well_known_routes(mapper)
    WellKnownRoutes.draw(mapper)
  end
end

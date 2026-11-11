# Rails Engine for OpenID Federation endpoints
# Provides controllers and routes for well-known OpenID Federation endpoints
#
# Mount at site root inside a single host `routes.draw` block:
#   mount OmniauthOpenidFederation::Engine => "/"
# Or draw the same paths on the host:
#   OmniauthOpenidFederation.draw_well_known_routes(self)
#
# @see OmniauthOpenidFederation::WellKnownRoutes
# @see https://guides.rubyonrails.org/engines.html Rails Engines Guide
require_relative "well_known_routes"

module OmniauthOpenidFederation
  class Engine < ::Rails::Engine
    # Not isolated: well-known paths must stay at site root under mount "/".

    initializer "omniauth_openid_federation.append_controller_paths", before: :set_load_path do |app|
      controllers = root.join("app", "controllers")
      next unless controllers.exist?

      app.config.autoload_paths << controllers.to_s
      app.config.eager_load_paths << controllers.to_s
    end
  end
end

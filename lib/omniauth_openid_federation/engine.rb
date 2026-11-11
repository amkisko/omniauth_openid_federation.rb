# Rails Engine for OpenID Federation endpoints
# Provides controllers and routes for well-known OpenID Federation endpoints
#
# @see https://guides.rubyonrails.org/engines.html Rails Engines Guide
module OmniauthOpenidFederation
  class Engine < ::Rails::Engine
    # Don't isolate namespace because we need routes at specific well-known paths
    # (/.well-known/openid-federation) rather than under a mount point

    initializer "omniauth_openid_federation.append_controller_paths", before: :set_load_path do |app|
      controllers = root.join("app", "controllers")
      next unless controllers.exist?

      app.config.autoload_paths << controllers.to_s
      app.config.eager_load_paths << controllers.to_s
    end
  end
end

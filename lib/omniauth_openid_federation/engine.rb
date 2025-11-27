# Rails Engine for OpenID Federation endpoints
# Provides controllers and routes for well-known OpenID Federation endpoints
#
# @see https://guides.rubyonrails.org/engines.html Rails Engines Guide
module OmniauthOpenidFederation
  class Engine < ::Rails::Engine
    # Don't isolate namespace because we need routes at specific well-known paths
    # (/.well-known/openid-federation) rather than under a mount point
    # isolate_namespace OmniauthOpenidFederation

    # Add controllers to autoload_once_paths so Rails can autoload them
    # This ensures controllers are available for route matching in production with eager loading
    # Rails will automatically eager load classes in autoload_once_paths in production
    # Must be done in config block before paths are frozen
    # config.autoload_once_paths << root.join("app", "controllers").to_s if root.join("app", "controllers").exist?
  end
end

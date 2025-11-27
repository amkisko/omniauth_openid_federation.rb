# Rails Engine for OpenID Federation endpoints
# Provides controllers and routes for well-known OpenID Federation endpoints
#
# @see https://guides.rubyonrails.org/engines.html Rails Engines Guide
module OmniauthOpenidFederation
  class Engine < ::Rails::Engine
    # Don't isolate namespace because we need routes at specific well-known paths
    # (/.well-known/openid-federation) rather than under a mount point
    # isolate_namespace OmniauthOpenidFederation

    # Explicitly require the controller to avoid Zeitwerk conflicts
    # For local path gems, autoload_once_paths can cause conflicts with main app's loader
    # We require the controller explicitly in to_prepare to ensure it's available for routing
    config.to_prepare do
      # Use self.class to access Engine class methods (root is a class method)
      engine_root = OmniauthOpenidFederation::Engine.root
      controller_path = engine_root.join("app", "controllers", "omniauth_openid_federation", "federation_controller.rb")
      require controller_path.to_s if controller_path.exist?
    end
  end
end

# Routes for OpenID Federation well-known endpoints.
# Spec requires site-root paths; mount the Engine at "/" or draw these on the host.
# Guard to prevent double-loading routes (important for test isolation).
@_omniauth_openid_federation_routes_loaded ||= false
unless @_omniauth_openid_federation_routes_loaded
  @_omniauth_openid_federation_routes_loaded = true
  begin
    require_relative "../lib/omniauth_openid_federation/well_known_routes"
    OmniauthOpenidFederation::Engine.routes.draw do
      OmniauthOpenidFederation::WellKnownRoutes.draw(self)
    end
  rescue NameError, LoadError
    # Rails not available or not fully initialized - routes load when Engine initializes
  end
end

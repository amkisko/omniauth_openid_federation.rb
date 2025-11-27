# Routes for OpenID Federation well-known endpoints
# These routes are mounted at the root level (not namespaced) because
# OpenID Federation spec requires specific well-known paths
OmniauthOpenidFederation::Engine.routes.draw do
  # OpenID Federation 1.0 Section 9: Entity Configuration endpoint
  # MUST be at /.well-known/openid-federation
  get "/.well-known/openid-federation", to: "omniauth_openid_federation/federation#show", as: :openid_federation

  # Fetch endpoint for Subordinate Statements (Section 6.1)
  get "/.well-known/openid-federation/fetch", to: "omniauth_openid_federation/federation#fetch", as: :openid_federation_fetch

  # Standard JWKS endpoint
  get "/.well-known/jwks.json", to: "omniauth_openid_federation/federation#jwks", as: :openid_federation_jwks

  # Signed JWKS endpoint (OpenID Federation requirement)
  get "/.well-known/signed-jwks.json", to: "omniauth_openid_federation/federation#signed_jwks", as: :openid_federation_signed_jwks
end

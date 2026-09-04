# RFC 0002: Problem and positioning

- Feature Name: problem-and-positioning
- Type: Informational
- Status: Stable
- Created: 2026-08-17
- Updated: 2026-08-18
- Author: Andrei Makarov
- Relates: RFC 0003, RFC 0004, RFC 0005, RFC 0006

## Summary

omniauth_openid_federation is an OmniAuth strategy for OpenID Federation 1.0. A host adds the gem, configures the strategy, and may publish `/.well-known/openid-federation`.

## Motivation

A relying party must fetch and verify entity statements, send a signed request object, authenticate with private_key_jwt, and accept or reject ID tokens and access tokens. When those steps live as host glue around a generic OIDC client, trust-chain errors, algorithm policy, and callback checks become per-app code. Two hosts then disagree on what a failed federation lookup means.

Login is a security boundary. This gem owns: trust chain resolution errors fail closed instead of empty metadata; `alg: none` is rejected; RSA keys below 2048 bits are rejected; `callback_phase` validates `iss`, `aud`, and session `nonce`; unknown `crit` claims in entity statements are rejected. Relaxing any of those checks changes every host login.

The federation HTTP surface is an operator contract. The Rack endpoint, the rake tasks that fetch entity statements and prepare client keys, and options such as `require_entity_statement_fingerprint` and `allowed_acr_values` are what a provider and a host use to register each other.

OIDC client types live in this gem (`OidcClient`, `AccessToken`, `IdToken`) so algorithm policy stays next to the strategy. The federation endpoint loads via `require "omniauth_openid_federation/rack"` rather than an extra runtime dependency for hosts that never publish metadata.

## Guide-level explanation

Install the gem. Fetch the provider entity statement with `rake openid_federation:fetch_entity_statement`. Generate client keys with `rake openid_federation:prepare_client_keys`. Send `config/client-jwks.json` to the provider, or set `client_entity_statement_url` when automatic registration is in use.

Configure `OmniAuth::Strategies::OpenIDFederation` with client id, private key, and entity statement path. Load the federation endpoint with `require "omniauth_openid_federation/rack"` when the host publishes metadata. Production keys come from `OPENID_CLIENT_PRIVATE_KEY_BASE64` or a path; PEM files stay out of git.

## Drawbacks

Hosts take on federation metadata operations, not only OmniAuth configuration. Fail-closed trust resolution means a metadata outage fails login.

## Rationale and alternatives

Owning OIDC client types in this gem keeps algorithm policy and trust-chain failure next to the OmniAuth strategy. A second OIDC stack beside OmniAuth duplicates session and CSRF wiring. Automatic registration without a published entity statement only works when the provider already has the client JWKS.

## Prior art

OpenID Federation 1.0. OmniAuth OAuth2 and OpenID Connect strategies. OIDC Core token validation. Contract detail is RFC 0003 through RFC 0006.

## Unresolved questions

Whether `require_entity_statement_fingerprint` and trust-anchor JWKS shape should include test vectors (RFC 0004).

Whether `allowed_acr_values` should include fixture tokens (RFC 0005).

Whether federation endpoint Rack wiring stays in this gem or splits when a second host framework is added (RFC 0003, RFC 0006).

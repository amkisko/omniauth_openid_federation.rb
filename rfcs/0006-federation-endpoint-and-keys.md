# RFC 0006: Federation endpoint and client keys

- Feature Name: federation-endpoint-and-keys
- Type: Standards Track
- Status: Stable
- Created: 2026-08-18
- Author: Andrei Makarov
- Relates: RFC 0002, RFC 0004

## Summary

Hosts may publish `/.well-known/openid-federation` through Rack and prepare client keys with rake tasks. The endpoint loads via `require "omniauth_openid_federation/rack"`. Private keys stay out of git.

## Motivation

Automatic registration needs a published entity statement URL. Explicit registration needs a public JWKS the provider can store. Both are operator contracts: a path change or a key format change breaks provider onboarding even when OmniAuth still loads.

## Guide-level explanation

Generate keys with `rake openid_federation:prepare_client_keys` (private PEM and `config/client-jwks.json`). Production private keys come from `OPENID_CLIENT_PRIVATE_KEY_BASE64` or `OPENID_CLIENT_PRIVATE_KEY_PATH`.

Fetch the provider statement with `rake openid_federation:fetch_entity_statement[url, fingerprint, path]`.

Publish the client entity statement by requiring `omniauth_openid_federation/rack` and setting `client_entity_statement_url` when automatic registration is in use.

## Reference-level explanation

Federation HTTP GET retries on 429, 502, and 503. POST does not retry by default. When peer verification is on, the client uses an SSL CA file. Private-key validation from RFC 0005 applies to keys used for signed request objects and JWE. The well-known path publishes public metadata only.

## Security considerations

Private keys are operator secrets. Fingerprint pinning is RFC 0004.

## Registrar

Rake tasks: `openid_federation:prepare_client_keys`, `openid_federation:fetch_entity_statement`. Env: `OPENID_CLIENT_PRIVATE_KEY_BASE64`, `OPENID_CLIENT_PRIVATE_KEY_PATH`. Path: `/.well-known/openid-federation`.

## Drawbacks

Rack wiring stays in this gem until a second host framework appears. Operators must manage PEM or base64 secrets outside the repository.

## Rationale and alternatives

An explicit `rack` runtime dependency would force hosts that never publish metadata to install Rack twice. Skipping rake helpers would leave key format as tribal knowledge. Doing nothing leaves registration as emailing JWKS by hand with no published statement.

## Prior art

OpenID Federation 1.0 client registration and `/.well-known/openid-federation`. OmniAuth strategies that ship a Rack endpoint for metadata. RFC 0004 consumes the fetched provider statement.

## Unresolved questions

Whether federation endpoint Rack wiring stays in this gem or splits when a second host framework is added.

# RFC 0003: OmniAuth strategy and callback

- Feature Name: strategy-and-callback
- Type: Standards Track
- Status: Stable
- Created: 2026-08-18
- Author: Andrei Makarov
- Relates: RFC 0002, RFC 0005

## Summary

Expose OpenID Federation login as an OmniAuth strategy. Request phase builds a signed authorization request. Callback phase sanitizes params, checks CSRF state, exchanges the code, and builds `omniauth.auth`. Failures return the Rack response from `fail!`.

## Motivation

A relying party talks to OmniAuth, not to federation internals. The strategy must own CSRF, authorization errors, and token exchange failure so hosts do not invent a second callback. Returning `nil` from `callback_phase` produced a Rack etag error and HTTP 500 on auth failure.

## Guide-level explanation

Configure the strategy in the OmniAuth builder with client id, private key, and entity statement path. POST to the OmniAuth request path. The provider redirects to the callback with `code` and `state`.

On callback, sanitize `state`, `code`, `error`, and `error_description`. An `error` param fails with `:authorization_error`. Missing or mismatched `state` against `session["omniauth.state"]` fails with `:csrf_detected` using constant-time compare. Missing `code` fails with `:missing_code`. Code exchange uses private_key_jwt by default (`client_auth_method` `:jwt_bearer`).

## Reference-level explanation

State is a random hex stored in `session["omniauth.state"]`. Nonce is a random hex stored in `session["omniauth.nonce"]` when `send_nonce` is on. Token verification after exchange is RFC 0005. Federation metadata used to build the client is RFC 0004. `callback_phase` MUST return the Rack response from `fail!` on those failures, not `nil`.

## Security considerations

CSRF uses constant-time compare. Callback params are sanitized before use. Failures go through `fail!` so OmniAuth can render the failure app.

## Registrar

Failure keys: `:authorization_error`, `:csrf_detected`, `:missing_code`. Session keys: `omniauth.state`, `omniauth.nonce`. Default `client_auth_method`: `:jwt_bearer`.

## Drawbacks

Hosts must use OmniAuth session and failure app. A second host framework needs its own strategy RFC.

## Rationale and alternatives

A generic OIDC client beside OmniAuth duplicates CSRF and session wiring. Returning `nil` on failure looked smaller and broke Rack. Doing nothing leaves each host to invent callback error handling.

## Prior art

OmniAuth OAuth2 and OpenID Connect strategies. OpenID Federation 1.0 authorization with signed request objects. RFC 0002 positions this gem as the federation strategy, not a second OIDC stack.

## Unresolved questions

Whether a second host framework besides OmniAuth and Rack needs a separate strategy RFC.

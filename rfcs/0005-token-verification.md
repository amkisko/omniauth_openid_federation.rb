# RFC 0005: Token verification

- Feature Name: token-verification
- Type: Standards Track
- Status: Stable
- Created: 2026-08-18
- Author: Andrei Makarov
- Relates: RFC 0002, RFC 0003

## Summary

After code exchange, decode and check the ID token. Reject unsigned JWTs. Enforce a minimum RSA key size of 2048 bits. Check issuer, audience, and nonce. This gem owns those checks rather than delegating them to a generic OIDC stack.

## Motivation

Callback success without issuer, audience, and nonce checks accepts a token minted for someone else. `alg: none` accepts an unsigned JWT. Short RSA keys fail at a size a reviewer can name.

## Guide-level explanation

Decrypt an encrypted ID token with RSA-OAEP when needed, then verify the signed JWT against provider JWKS. Compare `iss` to the expected issuer. Require the client id in `aud`. When `send_nonce` is on, compare `nonce` to `session["omniauth.nonce"]`; mismatch raises a security error.

Private keys used for request objects and JWE MUST be RSA of at least 2048 bits. Optional `allowed_acr_values` is checked when configured.

## Reference-level explanation

Expected issuer comes from client options or federation metadata. Audience is the client id. JWT algorithm `none` (including a missing alg treated as unsigned) is rejected. Broad JWKS decode retry on non-signature errors is out of scope. Client authentication at the token endpoint defaults to `:jwt_bearer` (RFC 0003).

## Security considerations

Unsigned JWTs are rejected. RSA keys below 2048 bits are rejected. Nonce and audience mismatches are security errors, not skipped claims.

## Registrar

Minimum RSA size: 2048 bits. Session nonce key: `omniauth.nonce`.

## Drawbacks

Hosts cannot use short test keys without relaxing this RFC. Encryption algorithms beyond RSA-OAEP plus A128CBC-HS256 / A128GCM need a later registrar.

## Rationale and alternatives

Leaving ID token checks to a generic `openid_connect` client scattered algorithm policy across gems. Accepting `alg: none` for interop would accept unsigned tokens. Doing nothing leaves each host to copy issuer and nonce checks.

## Prior art

OpenID Connect Core ID token validation. JWT BCP (RFC 8725) on rejecting `none`. OmniAuth OIDC strategies that verify `iss`, `aud`, and `nonce`. RFC 0003 owns the callback that invokes this check.

## Unresolved questions

Whether `allowed_acr_values` and `required_request_object_claims` need fixture tokens in a follow-on RFC.

Whether ID token encryption algorithms beyond RSA-OAEP and A128CBC-HS256 / A128GCM need a registrar.

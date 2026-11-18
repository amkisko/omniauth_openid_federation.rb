# Verified ID token claims on auth.extra

## Decisions

- Publish `auth.extra.id_token_claims` as the verified ID token claim set after decode and validation.
- Keep `auth.extra.raw_info` as the UserInfo merge contract; do not pin `acr` inside the merge in this change.
- Stringify claim keys for both `raw_info` and `id_token_claims` so key type does not depend on whether UserInfo was fetched.

## Effects

- Strategy stores `@id_token_claims` when building `raw_info` and returns it from `id_token_claims` and `extra`.
- Specs cover diverging UserInfo `acr` / identity claims versus signed token values, auth hash exposure, and fetch_userinfo disabled.
- CHANGELOG section `2.3.0` documents the new extra field.

## Next

- Hosts that gate on authentication method should read `extra.id_token_claims` (for example `acr`) rather than the merged `raw_info`.
- Operator publishes `2.3.0` via `make release` after the release commit is clean.

## Source

- `docs/issues/20261118172357_verified-id-token-claims-in-auth-hash.md`
- `lib/omniauth_openid_federation/strategy.rb`
- `spec/omniauth_openid_federation/strategy/id_token_claims_extra_spec.rb`

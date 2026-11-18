# Keep verified ID token claims available after UserInfo merge

## Participants

Andrei Makarov

## Decisions

- Keep `extra.raw_info` as the merged profile contract (ID token claims plus UserInfo, with `iss` / `sub` / `aud` / `exp` / `iat` pinned from the ID token).
- Expose the verified ID token claim set separately on the OmniAuth result as `extra.id_token_claims`, including authentication-context claims such as `acr` and any other signed claims present in the token.
- Do not pin `acr` inside the merge for this change; consumers that need the signed authentication method read `extra.id_token_claims`.

## Effects

- `auth.extra.id_token_claims` added; `raw_info` merge unchanged for `acr`.
- Specs, Unreleased CHANGELOG, and `docs/reviews/20261118172445_verified-id-token-claims-engineering-audit.md` recorded.

## Next

- Optional: pin `acr` / `amr` / `auth_time` in the merge, or document assurance reads in README callback examples.
- Cut a release when packaging.

## Source

- Live-work note attached to this session (dependency symptom against lockfile 2.2.1)
- OpenID Connect Core 1.0 sections 2 (ID Token / `acr`) and 5.3.2 (UserInfo `sub` binding)
- `lib/omniauth_openid_federation/strategy/userinfo_decoding.rb` (`IDENTITY_CLAIM_KEYS`)
- `lib/omniauth_openid_federation/strategy.rb` (`raw_info`, `extra`)

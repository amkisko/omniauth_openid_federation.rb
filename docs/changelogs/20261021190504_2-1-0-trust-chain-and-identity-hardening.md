# 2.1.0 trust chain and identity hardening

## Participants

Andrei Makarov (@amkisko)

## Decisions

- Cut **2.1.0** after multi-model engineering audit: Ruby floor is already `>= 3.4` in the gemspec, so the release is minor rather than patch.
- Ship trust-anchor pinning, userinfo `sub` binding, signed-JWKS fail-closed, and callback `state`-before-`error` in the same release.

## Effects

- Trust chain resolution verifies pinned trust-anchor JWKS and binds `iss`/`sub` to the requested entity id.
- UserInfo can no longer replace the ID token subject used for `uid`.
- Signed JWKS failures no longer downgrade to unsigned JWKS; cache keys include verifying entity JWKS.
- Missing configured provider entity-statement files raise `ConfigurationError`.
- CHANGELOG and README requirements align with Ruby `>= 3.4`.

## Next

- Follow-on: SSRF URL allowlists, HttpClient retry budget/`Retry-After`, RBS surface for 2.0 types, dependency-audit of `gemfiles/*.gemfile.lock`.

## Source

- `docs/reviews/20261021190504_engineering-audit-multi-model.md`
- `CHANGELOG.md` section `2.1.0`

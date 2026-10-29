# Engineering audit (multi-model)

## Participants

Andrei Makarov (@amkisko)

## Decisions

- Treat trust-anchor JWKS pinning, entity-id binding, userinfo `sub` match, and signed-JWKS fail-closed as release blockers.
- Ship as **2.1.0**: gemspec already requires Ruby `>= 3.4`; README and CHANGELOG must match.
- Defer SSRF allowlists, full RBS rewrite, and HttpClient jitter/`Retry-After` to follow-on work unless they fit the same patch without scope creep.
- Base release notes on history after the rewritten `2.0.0` tag (`2aeeea3..HEAD` plus this fix set), not `git log 2.0.0..HEAD`.

## Effects

- Four read-only audits completed and fact-checked against `lib/`:
  - Security / HTTP-identity
  - Correctness / tests
  - Hot-path / resources
  - Release readiness
- Confirmed critical/high defects (observed in code):
  - `TrustChainResolver` stores `trust_anchors[].jwks` but never verifies with it; leaf `iss` equal to a configured anchor id can short-circuit the walk.
  - Resolver passes issuer config into `EntityStatementValidator` where authority_hints expects the subject; trust-chain specs stub the validator.
  - `raw_info` merges userinfo over ID token claims; `uid` prefers string `"sub"`, so userinfo can replace the verified subject.
  - Signed JWKS errors fall through to unsigned `jwks_uri`; signed-JWKS cache key is URI-only.
  - Callback handles OAuth `error` before `state` CSRF check.
  - `client_entity_statement_url` is accepted and documented but ignored by `load_client_entity_statement`.
  - `Utils.validate_file_path!` uses `start_with?(dir)` without a path separator boundary.
  - README still claims Ruby `>= 3.0` while gemspec requires `>= 3.4`.
- Hot-path (observed): uncapped trust-chain hint width, synchronous GET retries, uncapped response bodies, default `cache_ttl = nil`.

## Next

- Implement blocker fixes with failing specs first, then CHANGELOG / version / README for 2.1.0.
- Add one trust-chain spec with real validator and distinct leaf/TA keys.
- Open follow-ons for SSRF, RBS surface, dependency-audit of `*.gemfile.lock`, and HTTP retry budget.

## Source

- Multi-model audit session on `omniauth_openid_federation.rb` (2026-10-21)
- `rfcs/0004-trust-chain-and-entity-statements.md`
- OpenID Federation 1.0 §3.2.1 / §10; OIDC Core §5.3.2 (userinfo `sub`)

# Engineering audit: verified ID token claims versus UserInfo merge

## Participants

Andrei Makarov

## Decisions

- Treat the attached dependency symptom as confirmed against this tree at version 2.2.1.
- Smallest fix: expose verified ID token claims on `extra.id_token_claims`; leave merge pin list unchanged.
- Run security, contract, boundary, resource, and trace modes on the callback claim path; skip product-surface, privacy product UI, performance service, observability process, learned-systems, and lineage modes (library auth hash contract only; no person-facing presentation surface in this change).

## Effects

Finding 1: UserInfo can replace authentication-context claims in `raw_info`

- Severity: high
- Confidence: high
- Location: `Strategy::UserinfoDecoding#merge_userinfo_with_id_token_claims` (`IDENTITY_CLAIM_KEYS` = iss, sub, aud, exp, iat); `Strategy#raw_info`; `Strategy#extra`
- Pipeline stage: external API (UserInfo) into app logic (auth hash egress)
- Why it matters: a consumer that reads `acr` (or another signed assurance claim) from `raw_info` can accept a value that was not the verified ID token value
- Evidence kind: observed
- Security verdict: confirmed
- Kind: broken behavior / contract gap
- Smallest credible fix: add `extra.id_token_claims` from the validated ID token payload (done this episode)
- Deeper fix: optionally pin `acr` / `amr` / `auth_time` in the merge, or document that assurance must never read those from `raw_info`

Finding 2: missing coverage for diverging UserInfo authentication claims

- Severity: medium
- Confidence: high
- Location: strategy specs before this episode
- Why it matters: identity pin for `sub` was tested; `acr` overwrite was not
- Evidence kind: observed (missing coverage, not futile coverage)
- Smallest credible fix: specs that assert UserInfo may differ in `raw_info` while `id_token_claims` keeps the signed value (done)

Finding 3: `raw_info` key type depended on UserInfo fetch path

- Severity: low
- Confidence: high
- Location: `Strategy#raw_info` when `fetch_userinfo` is false or UserInfo fetch falls back
- Why it matters: symbol keys from `IdToken#raw_attributes` versus string keys after merge break string-key readers
- Evidence kind: observed
- Smallest credible fix: stringify verified claims before store and return (done with the same change)

Boundary mode: identity provider commands authentication claims; relying party must not treat unsigned or alternate UserInfo values as the signed authentication method without a separate contract. Intended (signed ID token) and reported (`raw_info` after merge) could diverge for `acr` without an alarm; `id_token_claims` restores a readable intended state.

Resource and budget: claim merge is O(claims); no budget change measured; cheaper/smaller claims stay inference.

Trace and identification: `extra` still carries subject and profile claims already present on the OmniAuth result; no new third-party observer. Quantity of fields in the auth hash grows by one nested hash of claims already decoded for `raw_info`.

Claims audit of the attached note:

- Gem constraint / lockfile 2.2.1 and direct runtime use on an identity-provider callback: supported for this repository version (`VERSION` = 2.2.1); consumer Gemfile constraint unverifiable here.
- Merge keeps signed iss, sub, aud, exp, iat and can replace acr: supported by `IDENTITY_CLAIM_KEYS` and a failing-then-passing diverging-acr spec.
- Consumers basing assurance on merged claim can misread authentication method: supported as causal risk when they read `raw_info["acr"]`; local synthetic prototype accept/reject scene: unverifiable testimony (not reproduced in this tree).
- Suggested separate verified claims contract: supported as the implemented fix path.
- OpenID Connect Core ID Token / UserInfo citations: supported for `acr` as ID Token claim and UserInfo `sub` binding; Core does not require RPs to discard UserInfo `acr`, so the defect is this library's merge contract, not a Core MUST violation.

## Next

- Optional follow-up: pin authentication-context claims in the merge, or README callback example showing `extra.id_token_claims` for assurance checks.
- Release notes already drafted under Unreleased; cut version when packaging.

## Source

- `docs/issues/20261118172357_verified-id-token-claims-in-auth-hash.md`
- `docs/changelogs/20261118172430_verified-id-token-claims-extra.md`
- OpenID Connect Core 1.0 sections 2 and 5.3.2
- Commands this episode: `bundle exec rspec` on id_token_claims_extra, userinfo_sub_binding, decode_id_token, and integration specs -> 52 examples, 0 failures; `bundle exec rbs validate` -> exit 0; `bundle exec rubocop --no-parallel --cache false` on `strategy.rb` and `id_token_claims_extra_spec.rb` -> 2 files, 0 offenses, exit 0

# Engineering audit and release preparation

## Participants

Andrei Makarov

## Decisions

- Cut release version `2.3.0` dated 2026-11-18 for verified ID token claims on `auth.extra.id_token_claims`, thinner gem packaging without `examples/`, and deferred tasks require via `omniauth_openid_federation/tasks`.
- Stay additive (minor): new auth-hash field and packaging/entrypoint contract; no intentional breaking OmniAuth API removal. Hosts that relied on the main gem entry to load rake helpers must `require "omniauth_openid_federation/tasks"`.
- Do not tag, push, or publish in this session; operator runs `make release` / `usr/bin/release.rb` after the release commit lands on a clean tree.

## Effects

- Version file and appraisal lockfiles set to `2.3.0`. CHANGELOG heading `## 2.3.0 (2026-11-18)` populated; `Unreleased` left empty.
- Required project checks: `bundle exec rubocop --no-parallel` on `lib/omniauth_openid_federation/version.rb` exit 0 (1 file, 0 offenses), `bundle exec rbs validate` exit 0, `POLYRUN_COVERAGE=1 bundle exec appraisal rails8 -- bundle exec polyrun parallel-rspec --workers 5 --merge-failures -c polyrun.yml` exit 0 (5 shards, 0 failures).
- Merged SimpleCov line coverage about 92.68 percent (4645 / 5012).
- `spec/release_spec.rb`: 2 examples, 0 failures (EOF refuses gem push; Enter accepts displayed default with system execution replaced).
- Gem build verified: `omniauth_openid_federation-2.3.0.gem` compressed 114688 bytes; source payload 527670 bytes across 85 packaged paths; `examples/` absent from the package; `du -sk` of unpacked payload 708. Compressed and uncompressed sizes are not interchangeable.
- Cold process measurement on macOS arm64 with `/usr/bin/time -l` and `bundle exec ruby -Ilib`: about 0.33 CPU seconds user, 0.61 elapsed seconds, 50397184 peak RSS bytes. Local smoke ceilings unchanged: 1 MiB compressed gem, 128 MiB RSS, 2 CPU seconds. Measured values fit those ceilings. CPU seconds are the energy proxy; electricity use was not measured.
- Workflow YAML files parse; `git diff --check` clean; own-gem lockfile entries at 2.3.0. Rubygems warn check for 2.3.0 did not report an existing published version in this session.

## Next

- Operator commits the release cut if not already committed, then runs `make release` (or `ruby usr/bin/release.rb`) to push the gem, tag `2.3.0`, and create the GitHub release.
- Hosted GitHub Actions and the full supported Ruby/framework matrix were not executed locally beyond the Rails 8 appraisal path used by `make test`.
- Scope limits: production traffic, production database size and query plans, external service retention, and co-located resource interference were not measured.

## Source

- AGENTS.md
- .agents/skills/engineering-audit/SKILL.md
- .agents/skills/changelog-update/SKILL.md
- CHANGELOG.md
- docs/changelogs/20261118172430_verified-id-token-claims-extra.md
- docs/changelogs/20261113123000_exclude-examples-defer-tasks-require.md
- docs/issues/20261118172357_verified-id-token-claims-in-auth-hash.md
- docs/reviews/20261118172445_verified-id-token-claims-engineering-audit.md
- docs/reviews/20261111205000_engineering-audit-release-preparation.md
- Makefile
- usr/bin/release.rb

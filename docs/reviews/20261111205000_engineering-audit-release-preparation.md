# Engineering audit and release preparation

## Decisions

- Cut release version `2.2.1` dated 2026-11-11 for Engine mount contract docs, shared well-known route drawer, and CacheStore encrypt/decrypt hooks.
- Stay additive (patch): no intentional breaking API removal.
- Do not tag, push, or publish in this session; operator runs `make release` / `usr/bin/release.rb` after the release commit lands on a clean tree.

## Effects

- Version file and appraisal lockfiles set to `2.2.1`. CHANGELOG heading `## 2.2.1 (2026-11-11)` populated; `Unreleased` left empty.
- Required project checks: `bundle exec rubocop --no-parallel` on the changed tree exit 0 (12 files, 0 offenses), `bundle exec rbs validate` exit 0, `POLYRUN_COVERAGE=1 bundle exec appraisal rails8 -- bundle exec polyrun parallel-rspec --workers 5 --merge-failures -c polyrun.yml` exit 0 (5 shards, 0 failures).
- Merged SimpleCov line coverage about 92.67 percent (4640 / 5007).
- `spec/release_spec.rb`: 2 examples, 0 failures (EOF refuses gem push; Enter accepts displayed default with system execution replaced).
- Gem build verified: `omniauth_openid_federation-2.2.1.gem` compressed 150016 bytes; source payload 690558 bytes across 103 packaged paths. Compressed and uncompressed sizes are not interchangeable.
- Cold process measurement on macOS arm64 with `/usr/bin/time -l` and `bundle exec ruby -Ilib`: about 0.38 CPU seconds user, 1.15 elapsed seconds, 51724288 peak RSS bytes. Local smoke ceilings unchanged: 1 MiB compressed gem, 128 MiB RSS, 2 CPU seconds. Measured values fit those ceilings. CPU seconds are the energy proxy; electricity use was not measured.
- Workflow YAML files parse; `git diff --check` clean; own-gem lockfile entries at 2.2.1. Rubygems warn check for 2.2.1 did not report an existing published version in this session.

## Next

- Operator runs `make release` (or `ruby usr/bin/release.rb`) to push the gem, tag `2.2.1`, and create the GitHub release.
- Hosted GitHub Actions and the full supported Ruby/framework matrix were not executed locally beyond the Rails 8 appraisal path used by `make test`.
- Scope limits: production traffic, production database size and query plans, external service retention, and co-located resource interference were not measured.

## Source

- AGENTS.md
- .agents/skills/engineering-audit/SKILL.md
- .agents/skills/changelog-update/SKILL.md
- CHANGELOG.md
- docs/changelogs/20261111204500_engine-mount-docs-and-cachestore-hooks.md
- docs/issues/20261111204500_engine-mount-and-cachestore-followups.md
- docs/reviews/20261111160744_engineering-audit-release-preparation.md
- Makefile
- usr/bin/release.rb

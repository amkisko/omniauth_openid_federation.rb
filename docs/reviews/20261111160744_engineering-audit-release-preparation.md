# Engineering audit and release preparation

## Decisions

- Cut release version `2.2.0` dated 2026-11-11 for host-compatibility, reloadable RP keys, and related contract fixes after the pressure-cooker episode.
- Stay additive (minor): new Rails entrypoint, injectable controller base, dual keys, key stores, and content-type alignment; no intentional breaking API removal.
- Do not tag, push, or publish in this session; operator runs `make release` / `usr/bin/release.rb` after the release commit lands on a clean tree.

## Effects

- Version file and appraisal lockfiles set to `2.2.0`. CHANGELOG heading `## 2.2.0 (2026-11-11)` populated; `Unreleased` left empty.
- Required project checks: `bundle exec rubocop` (target file list includes the changed tree; benchmarks excluded), `bundle exec rbs validate` exit 0, `POLYRUN_COVERAGE=1 bundle exec appraisal rails8 -- bundle exec polyrun parallel-rspec --workers 5 --merge-failures` exit 0 (about 1306 progress marks across shards, 0 failures after KeyResolver error-message alignment).
- Merged SimpleCov line coverage about 92.56 percent (4556 / 4922).
- `spec/release_spec.rb`: 2 examples, 0 failures (EOF refuses gem push; Enter accepts displayed default with system execution replaced).
- Gem build verified: `omniauth_openid_federation-2.2.0.gem` compressed 149504 bytes; source payload 688247 bytes across 102 packaged paths. Compressed and uncompressed sizes are not interchangeable.
- Cold process measurement on macOS arm64 with `/usr/bin/time -l` and `bundle exec ruby -Ilib`: about 0.33 CPU seconds user, 0.61 elapsed seconds, 52740096 peak RSS bytes. Local smoke ceilings unchanged: 1 MiB compressed gem, 128 MiB RSS, 2 CPU seconds. Measured values fit those ceilings. CPU seconds are the energy proxy; electricity use was not measured.
- Workflow YAML files parse; `git diff --check` clean; own-gem lockfile entries at 2.2.0. Rubygems warn check for 2.2.0 did not report an existing published version in this session.
- Pressure binding remains under `benchmarks/`; L1 gate stayed green during the feature episode.

## Next

- Commit the release tree, then run `make release` (or `ruby usr/bin/release.rb`) to push the gem, tag `2.2.0`, and create the GitHub release.
- Hosted GitHub Actions and the full supported Ruby/framework matrix were not executed locally beyond the Rails 8 appraisal path used by `make test`.
- Scope limits: production traffic, production database size and query plans, external service retention, and co-located resource interference were not measured.
- Downstream hosts can remove local well-known and thin key-store shims after upgrading to 2.2.0 when they adopt callables / Engine base / Rack mount as needed.

## Source

- AGENTS.md
- .agents/skills/engineering-audit/SKILL.md
- .agents/skills/changelog-update/SKILL.md
- .agents/skills/pressure-benchmarking/SKILL.md
- CHANGELOG.md
- docs/changelogs/20261111174000_host-compatibility-reloadable-keys.md
- docs/issues/20261111174000_post-migration-host-compatibility-pressure.md
- docs/reviews/20261029124326_engineering-audit-release-preparation.md
- Makefile
- usr/bin/release.rb

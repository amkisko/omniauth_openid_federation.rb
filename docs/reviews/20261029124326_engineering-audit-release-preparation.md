# Engineering audit and release preparation

## Participants

Andrei Makarov (@amkisko)

## Decisions

- Continue on main while preserving uncommitted work. Do not commit, tag, push, or publish.
- Keep release version 2.1.0. Set the CHANGELOG heading date to 2026-10-29. RubyGems still lists 2.0.0 as the latest published version.
- Re-check correctness, executable coverage, workflow triggers and permissions, package boundaries, resource cost, and identity/HTTP boundaries after the parallel-spec Tempfile flake.

## Effects

- Enable pull_request on the test workflow, keep token permissions at contents: read, and cancel superseded runs.
- Exclude gemfiles/vendor from RuboCop and ignore that path so a mistaken appraisal install under gemfiles/ cannot load third-party .rubocop.yml plugins.
- Replace Tempfile.new(...).path fixtures that must survive GC with durable_entity_statement_path in authorize_uri, resolve_endpoints_from_metadata, and client_jwk_signing_key specs. Mark the client JWKS examples as type: :strategy so the helper is available.
- Final serial JSON report: 1293 examples, 0 failures under the Rails 8 appraisal. Parallel polyrun with five workers: exit 0.
- Required project checks passed: rubocop (174 files, no offenses), rbs validate, appraisal rails8 polyrun parallel-rspec. Environment: Ruby 4.0.2, BUNDLE_PATH=vendor/bundle.
- release_spec: 2 examples, 0 failures (EOF refuses gem push; Enter accepts the displayed default with system execution replaced).
- Build the gem, verify it with Gem::Package#verify, and confirm the changelog heading matches version 2.1.0. Compressed package: 146432 bytes; source payload: 677088 bytes across 96 packaged paths. These are compressed versus uncompressed sizes, not interchangeable quantities.
- Cold process measurement on macOS arm64 with /usr/bin/time -l and bundle exec ruby -Ilib: 0.41 CPU seconds, 0.49 elapsed seconds, 50806784 peak RSS bytes. Local smoke ceilings: 1 MiB compressed gem, 128 MiB RSS, 2 CPU seconds. All measured values fit those ceilings. CPU seconds are the energy proxy; electricity use was not measured.
- Parse every workflow YAML, verify lockfile own-gem versions at 2.1.0, and run git diff --check. All passed.

## Next

- Commit, tag 2.1.0, push, and publish remain operator steps; this session did not run them.
- Hosted GitHub Actions and the complete supported Ruby/framework matrix were not executed locally beyond the Rails 8 appraisal path used by make test.
- Scope limits: production traffic, production database size and query plans, external service retention, and co-located resource interference were not measured. The local byte/RSS/CPU results do not establish those properties.
- Trace review follows local file/log and protocol emissions. No live customer identities or credentials were used. Data retention and deletion in embedding applications remain host contracts.
- Learned-system training/evaluation and cloud deployment modes do not apply to this library tree. HTTP/identity mode applies to trust-chain, UserInfo, signed JWKS, and callback state binding. The library has no independent production health endpoint to assess.

## Source

- AGENTS.md
- .agents/skills/engineering-audit/SKILL.md
- .agents/skills/changelog-update/SKILL.md
- CHANGELOG.md
- Makefile
- spec/README.md
- docs/reviews/20261028075216_engineering-audit-release-preparation.md
- docs/changelogs/20261021190504_2-1-0-trust-chain-and-identity-hardening.md

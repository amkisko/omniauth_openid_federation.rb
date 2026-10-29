# Engineering audit and release preparation

## Participants

Andrei Makarov (@amkisko)

## Decisions

- Continue on main while preserving the pre-existing uncommitted changes. Do not commit, tag, push, or publish.
- Retain release version 2.1.0. Reconcile root and appraisal PATH metadata without updating third-party dependency versions.
- Review correctness, executable coverage, workflow triggers and permissions, package boundaries, resource cost, and trace/identity boundaries. Re-audit the changed paths after corrections.

## Effects

- Enforce the response byte ceiling while reading HTTP::Response::Body chunks. Stop after the first excess chunk, close the connection, and return a normal readable response for bounded content.
- Extract trust-chain signature/key verification into a private module and remove a rescue that only reraised. Preserve issuer, subject, signature, and trust-anchor binding through the resolver contracts.
- Repair stale specs that expected fallback after invalid signed JWKS or supplied UserInfo without the required matching sub. Keep the failure-closed behavior; update the large-HTML expectation to the shared response-size error.
- Enable pull-request tests, limit test-workflow token permissions to contents: read, and cancel superseded runs.
- Fix the release confirmation guard in usr/bin/release.rb so EOF refuses publication. An explicit Enter still selects the displayed default. The process-boundary regression test executes the release script with command execution replaced at the operating-system boundary; no publication command runs against a real service. The shared regression was observed first in Favorites: 2 examples, 1 failure before correction and 2 examples, 0 failures after correction. The release specs pass in every repository.
- Final serial JSON report: 1293 examples, 0 failures under the Rails 8 appraisal.
- Required project checks passed: make test (Rails 8 appraisal). Environment: Ruby 4.0.2, BUNDLE_PATH=vendor/bundle; the installed native extensions require that Ruby build.
- Build the gem, verify it with Gem::Package#verify, and check that the changelog heading matches the gem version. Compressed package: 146432 bytes; source payload: 677088 bytes across 96 packaged paths. These are compressed versus uncompressed sizes, not interchangeable quantities.
- Cold process measurement on macOS arm64 with /usr/bin/time -l and bundle exec ruby -Ilib: 0.62 CPU seconds, 1.1 elapsed seconds, 52150272 peak RSS bytes. Favorites loads Rails before the engine. Local smoke ceilings: 1 MiB compressed gem, 128 MiB RSS, 2 CPU seconds. All measured values fit those ceilings. CPU seconds are the energy proxy; electricity use was not measured.
- Parse every workflow YAML, verify lockfile own-gem versions, and run git diff --check. All passed. All six assigned repositories remain on main.

## Next

- No confirmed correction remains in the reviewed changes. Hosted GitHub Actions and the complete supported Ruby/framework matrix were not executed locally.
- Scope limits: production traffic, production database size and query plans, external service retention, and co-located resource interference were not measured. The local byte/RSS/CPU results do not establish those properties.
- Trace review follows local file/log and protocol emissions. No live customer identities or credentials were used. Data retention and deletion in embedding applications remain host contracts.
- Learned-system training/evaluation and cloud deployment modes do not apply to these library trees. Native memory-boundary mode applies to Polyrun's extension; browser presentation applies to Favorites; HTTP/identity and message companions apply only to repositories that expose those boundaries. Libraries have no independent production health endpoint to assess.

## Source

- AGENTS.md
- .agents/skills/engineering-audit/SKILL.md
- .agents/skills/changelog-update/SKILL.md
- CHANGELOG.md
- Makefile
- spec/README.md

Test CI ran bundler-audit before specs. Quality was blocked by advisory freshness, and one rails8 example failed when a Tempfile entity statement was collected before the strategy read it.

## Participants

- amkisko

## Decisions

- Drop the audit job from test.yml so tests no longer wait on advisory freshness.
- Disable osv-scanner in Trunk Check.
- Disable markdownlint MD013 in .markdownlint.yaml. Keep AGENTS.md in Trunk so other markdownlint rules still run.
- Keep entity-statement fixtures on a durable tmp path. Do not use Tempfile.new(...).path in helpers.
- Add dependency-audit.yml with workflow_dispatch only.

## Effects

- Test and integration jobs run without an advisory gate.
- Specs that write an entity statement and then build a client keep the file after GC.start.
- On-demand bundler-audit of every Gemfile.lock is available through workflow_dispatch.

## Next

- Run dependency audit on demand when a release or a known advisory needs it.
- Do not reintroduce advisory scanners into test.yml.

## Source

- GitHub Actions test failures on 2026-09-17

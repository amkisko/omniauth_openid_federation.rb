## Participants

Andrei Makarov (@amkisko)

## Decisions

- Close the post-upgrade bundler-audit queue by upgrading hot-path and appraisal packages in one follow-up change.
- Raise published gemspec floors for omniauth / omniauth-oauth2 so consumers cannot resolve the vulnerable OmniAuth 2.1.x line.
- Document host `allowed_hosts` / `full_host` configuration as required companion to the OmniAuth security fix.
- Fix Tempfile GC races in specs that called `Tempfile.new(...).path` without retaining the handle (parallel shard flake).
- Map the original Next bullets as done:
  1. omniauth + omniauth-oauth2 assessed and upgraded first on the auth boundary;
  2. rack + addressable upgraded with focused OmniAuth coupling specs and a second cooker resource compare;
  3. appraisal-only activesupport / rodauth bumped after the hot-path packages (no pin exception needed).

## Effects

- omniauth 2.4.2, omniauth-oauth2 1.10.1, rack 3.2.8, addressable 2.9.2 across root and appraisal locks.
- activesupport 8.1.4.1 (root / ruby / rails8*) and 7.2.3.2 (rails72); rodauth 2.51.0 with gemspec floor `>= 2.50.0`.
- `bundle exec bundle audit check` reports no vulnerabilities on root, ruby, rails72, rails8, and rails8_ruby4 lockfiles.
- README and Devise example set `OmniAuth.config.allowed_hosts`.
- Dependency records under `docs/dependencies/20261119071821_*` and `docs/dependencies/20261119072029_*`.
- Second resource compare recorded in `docs/reviews/20261119072029_bundler-audit-queue-resource-compare.md` (L1 gate pass; allocated_objects 12245 unchanged vs Ruby 4.0.10 head).
- Focused OmniAuth coupling specs: 77 examples, 0 failures.

## Next

- None for this queue.

## Source

- `docs/changelogs/20261119070458_ruby-4-0-10-toolchain.md`
- `docs/reviews/20261119072029_bundler-audit-queue-resource-compare.md`
- `docs/dependencies/20261119071821_omniauth-cve-2026-63183.md`
- `docs/dependencies/20261119071821_rack-3-2-8-security.md`
- `docs/dependencies/20261119071821_addressable-2-9-2-security.md`
- `docs/dependencies/20261119072029_activesupport-8-1-4-1-and-7-2-3-2.md`
- `docs/dependencies/20261119072029_rodauth-2-51-0.md`

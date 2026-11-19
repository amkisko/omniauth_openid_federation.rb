## Dependency

- addressable (was 2.9.0, now 2.9.2)
- Transitive via webmock (development) and related HTTP test tooling. Not a direct gemspec runtime dependency.

## Symptom

bundler-audit matches addressable 2.9.0 against ReDoS and path-normalization advisories fixed in 2.9.1+.

## Evidence

- Addressable 2.9.1 changelog lists GHSA fixes for template matching ReDoS and `normalize_path` issues.
- 2.9.2 is a follow-on bugfix release on the same line.

## Suggested fix

Upgrade lockfiles to addressable 2.9.2. Stay off unreleased 2.10 breaking changes.

## Trigger

- Post Ruby-upgrade bundler-audit queue.

## Assessment target

- Development and CI graphs.

## Advisory

- GHSA-qq38-m9mg-xjj5
- GHSA-8gmh-2hhj-2hv9
- GHSA-4w5q-wg7v-w6gp
- GHSA-j82w-28jv-3pmj
- GHSA-9f42-57jx-vpp3
- GHSA-539f-xcgw-2gjg
- GHSA-9crm-g4mf-wc5j

## Status

- Lockfile graphs: fixed at 2.9.2.
- Published gem runtime: not_affected for a direct addressable pin (`http` 6.x does not require addressable).

## Applicability

- Vulnerable component present in test graphs via webmock. Production gem path does not require addressable.

## Priority

- Medium for CI; low for published gem runtime.

## Disposition

- Upgrade lockfiles.

## Next

- None for addressable after 2.9.2 lands in all appraisal locks.

## Source

- https://github.com/sporkmonger/addressable/blob/main/CHANGELOG.md (2.9.1 / 2.9.2)
- `docs/issues/20261119070458_post-ruby-upgrade-bundler-audit-queue.md`

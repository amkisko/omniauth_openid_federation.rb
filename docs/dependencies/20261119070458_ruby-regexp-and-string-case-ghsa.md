## Dependency

- Ruby runtime (MRI)
- Local toolchain pin was `.ruby-version` `4.0.2`; now `4.0.10`
- Gemspec floor unchanged: `required_ruby_version >= 3.4`
- CI matrix still requests series `"3.4"` and `"4.0"` via `ruby/setup-ruby` (latest patch of each series)

## Symptom

Host and local checkouts on Ruby 4.0.0 through 4.0.9 (and 3.4.0 through 3.4.12) remain on builds that include multiple Regexp and String case-conversion memory-corruption bugs. Upstream published RCE PoCs for several of them.

## Evidence

- Advisory post 2026-11-18: seven GHSA identifiers for Regexp engine and String case conversion; fixes in Ruby 4.0.10, 3.4.13, and 3.3.14.
- Earlier 2026-10-23 note: GitLab-linked Regexp compilation bugs fixed by Ruby 4.0.9 / 3.4.12 / 3.3.13 (CVE-2026-89078, CVE-2026-93577, CVE-2026-97229, CVE-2026-110264 and related Ruby GHSA ids).
- Affected for the 2026-11-18 set: Ruby 4.0.0 through 4.0.9; 3.4.0 through 3.4.12; 3.3.13 and earlier.
- This library uses String case helpers on algorithm names, URI schemes, and fingerprints. It does not compile attacker-controlled regular expression patterns via `Regexp.new` / interpolation on the auth hot path observed in this pass.

## Suggested fix

Upgrade host and toolchain Ruby to 4.0.10 or later (or 3.4.13 / 3.3.14 on those series). Keep gemspec floor at `>= 3.4` and document the security patch floor for operators.

## Trigger

- Operator request to upgrade Ruby to latest and check changelog and vulnerabilities (2026-11-19).

## Assessment target

- Local toolchain: `.ruby-version` in this repository.
- Published gem runtime: whatever MRI the host process loads.
- CI: `ruby/setup-ruby` series pins `"3.4"` and `"4.0"`.

## Advisory

- GHSA-34m4-m9fh-gqp5, GHSA-7x2q-68qv-6p8x, GHSA-87fm-7w84-j2px, GHSA-wpqw-5qxg-m68r, GHSA-3p8q-wmhx-vm2w, GHSA-7whj-cfh7-xgm4, GHSA-pvgc-g7gj-pv6h (2026-11-18 set; CVE ids requested, not assigned at advisory publish time)
- Prior Regexp set: GHSA-gfj3-8wj9-qx8p, GHSA-22mf-ggw7-pxfx, GHSA-qm4g-8pfh-6996 plus GitLab CVE-2026-89078, CVE-2026-93577, CVE-2026-97229, CVE-2026-110264

## Status

- Local toolchain: fixed after `.ruby-version` -> `4.0.10`.
- Published gem execute path: affected until the host upgrades MRI; disposition is host upgrade, not a gem code change.
- Case-conversion RCE paths: under_investigation for host exposure; this gem calls `downcase` / `upcase` / `capitalize` on protocol and fingerprint strings, not on arbitrary attacker blob case conversion at scale.
- Attacker-controlled Regexp compilation: not_affected for this library's observed hot path.

## Applicability

- Vulnerable component is the MRI process, not a RubyGems package in the lockfile.
- Exploit conditions for Regexp compilation require compiling untrusted patterns. Exploit conditions for case conversion require crafted strings through case-conversion APIs.

## Priority

- Toolchain and host MRI: high. Upstream states PoCs for RCE on several advisories.
- This gem's own Regexp-compile surface: low on the observed hot path.

## Disposition

- Upgrade. Pin `.ruby-version` to `4.0.10`. Advise operators to run 4.0.10+ or 3.4.13+.

## Next

- Confirm CI runners resolve `"4.0"` to at least 4.0.10 and `"3.4"` to at least 3.4.13 after `ruby/setup-ruby` indexes the releases.
- Host products that embed this gem should bump their own Ruby patch pin even when the gemspec floor stays `>= 3.4`.

## Source

- https://www.ruby-lang.org/en/news/2026/11/18/multiple-vulnerabilities-in-regexp-and-string/
- https://www.ruby-lang.org/en/news/2026/11/18/ruby-4-0-10-released/
- https://www.ruby-lang.org/en/news/2026/10/23/regexp-fixes-for-gitlab-cves/
- https://www.ruby-lang.org/en/news/2026/10/23/ruby-4-0-9-released/
- `docs/reviews/20261119070458_ruby-4-0-10-upgrade-resource-compare.md`

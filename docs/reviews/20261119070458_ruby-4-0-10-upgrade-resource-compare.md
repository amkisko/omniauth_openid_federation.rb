## Participants

Andrei Makarov (@amkisko)

## Decisions

- Upgrade local toolchain `.ruby-version` from `4.0.2` to `4.0.10` (latest stable MRI on 2026-11-19; not 4.1.0-preview1).
- Keep gemspec `required_ruby_version >= 3.4`.
- Treat the upgrade as a dependency resource compare (base 4.0.2 vs head 4.0.10) using `benchmarks/cooker.rb`, not a full pressure-cooker optimize episode.
- Raise development sqlite3 floor to `>= 2.10.2` after bundler-audit flagged GHSA-4fqr-96q8-xrfx during the same pass.

## Effects

- `.ruby-version` is `4.0.10`.
- Development gemspec and appraisal locks pin sqlite3 `2.10.2`.
- Focused validation on Ruby 4.0.10: `bundle exec rubocop` (193 files, no offenses), `bundle exec rbs validate` exit 0, `BUNDLE_GEMFILE=gemfiles/rails8_ruby4.gemfile bundle exec polyrun parallel-rspec --workers 5 --merge-failures -c polyrun.yml` exit 0.
- Cooker calibrate PASS on both base and head.
- L1 measure (200 ops, n=3, median basis), macOS arm64, `BUNDLE_PATH=vendor/bundle`:
  - base 4.0.2: wall 1.4346 s, cpu 0.5391 s, rss_delta 688128 B, heap_delta 2423065 B, allocated_objects 12245, ops/s 139.4
  - head 4.0.10: wall 0.5268 s, cpu 0.4844 s, rss_delta 671744 B, heap_delta 2423081 B, allocated_objects 12245, ops/s 379.6
  - head replicate: wall 0.4194 s, cpu 0.4209 s, rss_delta 278528 B, heap_delta 2423081 B, allocated_objects 12245, ops/s 476.9
- L1 gate against `benchmarks/ceilings.json`: base failed wall_s and cpu_s on a noisy sample; head passed (gate metrics wall 0.4511 s, cpu 0.4436 s).
- Cold require `/usr/bin/time -l bundle exec ruby -Ilib -e 'require "omniauth_openid_federation"'`:
  - base: 0.49 real, 0.33 user, peak RSS 53805056 B
  - head: 1.20 real, 0.44 user, peak RSS 49496064 B (first run after native rebuild; wall noisy)
- Wall deltas are host-noise heavy; cpu_s and allocated_objects are the stabler compare signals. allocated_objects unchanged. cpu_s median improved about 10% base to first head sample; replicate was lower still.
- bundler-audit after advisory DB refresh initially reported omniauth, rack, addressable, activesupport, and rodauth. Those were closed in `docs/issues/20261119070458_post-ruby-upgrade-bundler-audit-queue.md` with a second resource compare in `docs/reviews/20261119072029_bundler-audit-queue-resource-compare.md`.

## Next

- Confirm CI `"3.4"` / `"4.0"` series pins resolve to 3.4.13+ / 4.0.10+ once setup-ruby indexes those builds.

## Source

- `docs/dependencies/20261119070458_ruby-regexp-and-string-case-ghsa.md`
- `docs/dependencies/20261119070458_sqlite3-ghsa-4fqr-96q8-xrfx.md`
- https://www.ruby-lang.org/en/news/2026/11/18/ruby-4-0-10-released/
- `benchmarks/cooker.rb`, `benchmarks/ceilings.json`

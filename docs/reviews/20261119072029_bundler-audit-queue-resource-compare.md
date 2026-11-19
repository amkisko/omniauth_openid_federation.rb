## Participants

Andrei Makarov (@amkisko)

## Decisions

- Treat the post-Ruby bundler-audit lockfile bumps (omniauth, omniauth-oauth2, rack, addressable, activesupport, rodauth) as a second dependency resource compare against the same cooker ceilings, not a pressure-cooker optimize episode.
- Keep ceilings in `benchmarks/ceilings.json` unchanged when L1 gate stays green and allocated_objects stay flat.

## Effects

- Focused OmniAuth coupling specs on `rails8_ruby4`: callback_phase, client, integration, rodauth_integration -> 77 examples, 0 failures (coverage floor skipped for the subset run).
- Cooker calibrate PASS.
- L1 measure (200 ops, n=3, median), macOS arm64, Ruby 4.0.10, `BUNDLE_PATH=vendor/bundle`, after the lockfile bumps:
  - measure: wall 0.4801 s, cpu 0.4782 s, rss_delta 851968 B, heap_delta 2423081 B, allocated_objects 12245, ops/s 416.6
  - replicate: wall 0.4514 s, cpu 0.4479 s, rss_delta 704512 B, heap_delta 2423081 B, allocated_objects 12245, ops/s 443.0
  - gate: pass (wall 0.4412 s, cpu 0.4415 s under ceilings)
- Compared with the Ruby 4.0.10 head sample from `docs/reviews/20261119070458_ruby-4-0-10-upgrade-resource-compare.md` (wall 0.5268 s, cpu 0.4844 s, alloc 12245): allocated_objects unchanged; cpu and wall within host noise of the earlier head/replicate band.
- All five lockfile graphs still report `bundle audit check` clean.

## Next

- None for this compare. CI series pin confirmation remains on the Ruby upgrade review.

## Source

- `docs/issues/20261119070458_post-ruby-upgrade-bundler-audit-queue.md`
- `docs/reviews/20261119070458_ruby-4-0-10-upgrade-resource-compare.md`
- `benchmarks/cooker.rb`, `benchmarks/ceilings.json`

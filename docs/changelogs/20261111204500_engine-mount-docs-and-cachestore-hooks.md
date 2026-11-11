# Engine mount docs and CacheStore hooks

## Decisions

- Document Engine mount and host `draw_well_known_routes` as supported Rails contracts; keep Rack as the filter-free path.
- Keep CacheStore default plaintext; optional encrypt/decrypt callables for shared caches.

## Effects

- README Step 6 no longer nests a second `routes.draw` around other host routes.
- Unreleased CHANGELOG lists mount docs fix, shared well-known drawer, and CacheStore hooks.

## Next

- Operator runs `make release` / `usr/bin/release.rb` to publish, tag, and create the GitHub release for `2.2.1`.

## Source

- `docs/issues/20261111204500_engine-mount-and-cachestore-followups.md`
- `CHANGELOG.md` section `2.2.1`

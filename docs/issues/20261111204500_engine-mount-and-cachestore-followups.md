# Engine mount contract and CacheStore confidentiality

## Decisions

- Treat README nested `Rails.application.routes.draw` as the documented failure mode for claim "mount at / returns 404". Plain `mount Engine => "/"` inside one draw block serves well-known paths.
- Public contract for Rails hosts in 2.x: one of Engine mount at `/`, `draw_well_known_routes` on the host mapper, or Rack under `/.well-known`.
- Add optional `encrypt` / `decrypt` hooks on `RelyingPartyKeyStore::CacheStore`; default stays plaintext passthrough. Cipher and KMS remain host concerns.

## Effects

- Shared `WellKnownRoutes` used by Engine `config/routes.rb` and `OmniauthOpenidFederation.draw_well_known_routes`.
- Host integration specs cover mount-in-one-draw, host-draw, and nested-second-draw 404 regression.
- CacheStore accepts `encrypt:` / `decrypt:`; specs cover plaintext default and transform round-trip.
- README Step 6 and Unreleased CHANGELOG updated.

## Next

- Operator publish of `2.2.1` via `make release` when the tree is clean.
- Optional later: cache key suffix migration helpers when renaming prefixes.

## Source

- Host report against `omniauth_openid_federation` 2.2.0 (`require: false`, Rails API-style base controller)
- Local reproduction: nested second `routes.draw` clears mount; single-draw mount returns 200 for all well-known paths

# Host compatibility and reloadable RP keys

## Participants

Andrei Makarov (@amkisko)

## Decisions

- Ship Rack and Rails entity-statement content types aligned to OpenID Federation 1.0 §9.2.
- Support API hosts via injectable FederationController base and Rack-only mount docs.
- Resolve RP signing and encryption keys at use time (callable allowed) so rotation does not require process restart.
- Offer optional RelyingPartyKeyStore file, ENV, and cache adapters without forcing them on every host.

## Effects

- `RackEndpoint` entity configuration uses `application/entity-statement+jwt`.
- `omniauth_openid_federation/rails` loads Engine, Railtie, and FederationController for `require: false` consumers.
- `OmniauthOpenidFederation.base_controller` selects the parent class; well-known actions skip `verify_authorized` / `verify_policy_scoped` when present.
- Signed JWKS aliases: `/.well-known/signed-jwks.jwt` and `.jose`.
- `KeyResolver`, `ClientKeys`, `OidcClient` resolve-on-use, strategy `signing_key` / `encryption_key`, `reset_client!`.
- `RelyingPartyKeyStore::{FileStore,EnvStore,CacheStore}` plus rotation example.
- JWKS Normalizer no longer calls ActiveSupport `stringify_keys`.
- Pressure binding and ceilings under `benchmarks/`.

## Next

- Cut `2.2.0` from this work (version and CHANGELOG heading prepared for 2026-11-11).
- Downstream deletion of host well-known and thin key-store shims after upgrade.

## Source

- `docs/issues/20261111174000_post-migration-host-compatibility-pressure.md`
- Focused rspec pack listed in that issue Effects
- `CHANGELOG.md` section `2.2.0`

# Post-migration host compatibility pressure episode

## Participants

Andrei Makarov (@amkisko)

## Decisions

- Install `amkisko/pressure-benchmarking` `~> 1.1` under `.agents/skills` before optimize cycles.
- Primary series for the cooker: `wall_s` on L1 (200 ops of callable key resolve + Rack entity statement).
- Propose basis: median times headroom 1.15. Memory probe class: `process_lifetime`. Network: `not_in_scope`.
- Apply fix packs A-E as optimize cycles against the measured gate, then re-prove.

## Effects

- Prayfile trees `amkisko/pressure-benchmarking` 1.1.0; skill provisioned under `.agents/skills/pressure-benchmarking/`.
- Binding: `benchmarks/cooker.rb`, ceilings `benchmarks/ceilings.json`.
- Calibrate self-test: PASS (noop / sleep_2ms / sleep_6ms / sleep_12ms distinct wall order).
- Baseline L0 (ops=50, n=3): wall_s median about 0.112 s.
- Stress L1 (ops=200, n=3): wall_s median about 0.455 s; ceilings written (wall_s about 0.491 s).
- Gate after ceiling write: pass.
- Focused specs (rails8 appraisal): 44 examples, 0 failures for key resolver, reloadable OIDC client, RP key store, rails entrypoint, content-type contract, Rack endpoint, FederationController.

### Cooker iteration log (N=10)

1. primary `wall_s` - hypothesis Rack entity CT wrong - change RackEndpoint entity CT to `CONTENT_TYPE_ENTITY_STATEMENT_JWT` - prove gate green
2. primary `wall_s` - hypothesis CT drift across surfaces - change Constants content-type module used by Rack and Rails - prove green
3. primary `allocated_objects` - hypothesis ActiveSupport stringify on JWKS hot path - change Normalizer to stdlib key stringify - prove green
4. primary `wall_s` - hypothesis require:false miss - add `omniauth_openid_federation/rails` + Engine autoload paths - prove green
5. primary `wall_s` - hypothesis host authorize blocks well-known - injectable `base_controller` + skip verify_authorized - prove green
6. primary `wall_s` - hypothesis missing signed-jwks aliases - add `.jwt` / `.jose` Rack and Engine routes - prove green
7. primary `wall_s` - hypothesis stale RP key snapshot - KeyResolver + OidcClient resolve-on-use - prove green (callable PEM resolve stays under about 2 ms in prior smoke)
8. primary `wall_s` - hypothesis dual keys missing on Strategy - add `signing_key` / `encryption_key` + ClientKeys - prove green
9. primary `wall_s` - hypothesis no RP key store - add File/Env/Cache RelyingPartyKeyStore + rotation example - prove green
10. primary `wall_s` - hypothesis public JWK helper can leak `d` - `rsa_key_to_jwk(include_private:)` default false - prove green

## Next

- Broader suite / coverage job as part of `2.2.0` release prep.
- Downstream hosts can drop local well-known shims after upgrading to `2.2.0`.
- Keep rolling-restart notes only where callables are not yet wired.

## Source

- `benchmarks/cooker.rb`
- `benchmarks/ceilings.json`
- OpenID Federation 1.0 §9.2 entity configuration content type

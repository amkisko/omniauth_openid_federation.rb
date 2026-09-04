# RFC 0004: Trust chain and entity statements

- Feature Name: trust-chain-and-entity-statements
- Type: Standards Track
- Status: Stable
- Created: 2026-08-18
- Author: Andrei Makarov
- Relates: RFC 0002, RFC 0006

## Summary

Fetch and validate OpenID Federation entity statements. When `trust_anchors` are configured, resolve a trust chain toward an anchor and apply metadata policy. Resolution errors fail closed. Empty metadata is not a success path.

## Motivation

Federation login is only as strong as the metadata the client trusts. Returning empty metadata on a failed lookup lets the host continue with stale or missing endpoints. Unsigned entity statements, unknown `crit` claims, and `alg: none` are not acceptable on this path.

## Guide-level explanation

Fetch the provider entity statement with `rake openid_federation:fetch_entity_statement` and pin a fingerprint when the host requires it (`require_entity_statement_fingerprint`). Set `trust_anchors` to an array of `{entity_id, jwks}` hashes and leave `enable_trust_chain_resolution` true (the default) when the issuer or client_id is an Entity ID.

Resolution walks from the leaf toward a configured trust anchor, then applies metadata policies from that chain.

## Reference-level explanation

Entity statement JWT `alg` MUST NOT be `none`. Unknown `crit` claims are rejected. Subordinate statements (`iss` != `sub`) have signatures verified during resolution. Cache keys for federation JWKS and signed JWKS are issuer-scoped. Fingerprint mismatch is a configuration error when fingerprint is required.

Trust marks are parsed and not validated. That is a recorded gap, not a host workaround.

## Security considerations

Fail closed on resolution errors. Fingerprint pinning is opt-in and fail-closed when required.

## Drawbacks

Hosts must configure trust anchors or accept a pinned entity statement. Fail-closed lookup means a metadata outage fails login instead of degrading.

## Rationale and alternatives

Returning empty metadata on error would keep login up and would accept missing endpoints. Skipping subordinate signature checks would shorten the walk and would trust a leaf the anchor did not sign. Doing nothing leaves trust-chain policy as per-app glue.

## Prior art

OpenID Federation 1.0 entity statements, trust chains, and metadata policy. OIDC discovery without a federation walk is weaker when the issuer is an Entity ID. RFC 0006 covers publishing the client statement.

## Unresolved questions

Whether `require_entity_statement_fingerprint` and trust-anchor JWKS shape need test vectors in a follow-on RFC.

Whether trust marks (OpenID Federation Section 7) stay unvalidated.

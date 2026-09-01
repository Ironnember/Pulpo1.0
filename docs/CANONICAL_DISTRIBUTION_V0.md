# Canonical Distribution V0

`authority_effect=none`

## Purpose

Recover useful mobile/PWA distribution work from the divergent `experiment/local-lab-workspace-v0` lineage without importing that lineage's authority or source-of-truth drift.

## Canonical source rule

A Pulpo distribution may be called **canonical** only when the exact distributed source commit is reachable from protected `main` after normal admission. A tag, artifact, successful build, approval, or deployment does not create canonicality by itself.

The historical `v0.1.1` tag is therefore treated as an experimental distribution artifact. It resolves to `611e46261c416c51993e50ae79d18125122b79a4`, which is not the current protected-main lineage. This document does not delete, rewrite, or republish that tag.

## Constitutional correction

The first recovery candidate correctly removed permit issuance from the mobile UI, but it still exposed authenticated `/api/propose`, which called the canonical projection's target-locking path. A holder of the shared bearer token could therefore choose target/action/resource/session/version values and append canonical target/audit state without an individually governed identity, namespace ownership, quota, revocation, or rate/size boundary.

That is too much capability for a distribution V0.

The corrected invariant is:

`NO_PERMIT != NO_GOVERNED_EFFECT`

`CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`

`DISTRIBUTION_SURFACE != CANONICAL_STATE_WRITER`

A component does not become harmless merely because it cannot mint a permit. Creating durable canonical intent/evidence state is itself a governed capability and must enter through a separately controlled ingress.

## V0 mobile boundary

The V0 mobile surface is read-only:

- it receives an existing `PulpoMCPProjection` bound to the canonical `PulpoOrchestrator`;
- it may read the existing canonical audit-integrity evidence snapshot;
- it exposes **no** proposal, target-lock, decision, approval, authorization, execution, or permit-consumption endpoint;
- it creates no target, audit event, kernel, policy, authority client, trusted clock, state store, executor, or evidence ledger;
- repeated evidence reads must leave canonical audit length unchanged;
- its bearer token gates read access only and must not be represented as an individual identity or authority credential;
- API responses are excluded from the PWA cache.

Any future write-capable distribution surface must first establish a separately governed ingress with explicit caller identity, owned namespace/scope, revocation, resource/rate/size limits, and policy appropriate to the exact canonical mutation. That is outside V0.

## Admission rule

Passing CI, a GitHub approval, or GitHub mergeability does not authorize admission. The exact candidate must receive substantive review against its canonical-state and distribution boundaries, fresh exact-head proof, and normal repository admission.

Repository-level admission remains incomplete while `admission-hold` is not a required protected-main context and bypass posture is not independently established. Issue #115 remains the governing open control for that gap.

## Release rule

Do not publish a new canonical GitHub Release from this PR. Release publication is a separate external consequence and must be bound to an admitted protected-main commit after distribution tests pass.

A later release proof should establish at minimum:

1. exact protected-main source SHA;
2. reproducible build workflow pinned to that source;
3. artifact hashes for each published platform artifact;
4. release/tag binding to the exact admitted SHA;
5. no hidden authority, canonical-write, or execution path added by packaging;
6. post-publication readback showing the expected release and assets.

## Nonclaims

This V0 does not prove a production deployment, desktop executable, App Store distribution, native iOS admission, external individual-user authentication, production session management, write-capable mobile governance, or canonical public release. Passing CI proves only the repository-level read-only distribution boundary tested here.

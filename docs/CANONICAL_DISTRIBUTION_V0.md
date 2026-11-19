# Canonical Distribution V0

`authority_effect=none`

## Purpose

Recover useful mobile/PWA distribution work from the divergent `experiment/local-lab-workspace-v0` lineage without importing that lineage's authority or source-of-truth drift.

## Canonical source rule

A Pulpo distribution may be called **canonical** only when the exact distributed source commit is reachable from protected `main` after normal admission. A tag, artifact, successful build, approval, or deployment does not create canonicality by itself.

The historical `v0.1.1` tag is therefore treated as an experimental distribution artifact. It resolves to `611e46261c416c51993e50ae79d18125122b79a4`, which is not the current protected-main lineage. This document does not delete, rewrite, or republish that tag.

## Constitutional correction

The first recovery candidate correctly removed permit issuance from the mobile UI, but it still exposed authenticated `/api/propose`, which called the canonical projection's target-locking path. A holder of the shared bearer token could therefore choose target/action/resource/session/version values and append canonical target/audit state without an individually governed identity, namespace ownership, quota, revocation, or rate/size boundary.

A second review then found a deeper trust-domain issue: even after the `/api/propose` route was removed, the web application still received the full `PulpoMCPProjection`. That object retained `propose_intent()` and a reference to the canonical orchestrator, so the distribution process still possessed canonical-state write capability even though the declared HTTP routes did not expose it.

The corrected invariant is:

`NO_PERMIT != NO_GOVERNED_EFFECT`

`NO_WRITE_ROUTE != NO_WRITE_CAPABILITY`

`CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`

`DISTRIBUTION_SURFACE != CANONICAL_STATE_WRITER`

A component does not become harmless merely because it cannot mint a permit or because a particular route is absent. Capability possession itself matters at the trust boundary.

## V0 mobile boundary

The V0 mobile surface is a frozen read-only evidence snapshot viewer:

- the application module imports no Pulpo kernel, orchestrator, or MCP projection type;
- the application receives no kernel, orchestrator, MCP projection, authority client, state backend, executor, or ledger reference;
- it accepts only `FrozenEvidenceSource`, which copies a narrow validated primitive evidence mapping and retains no reference to the originating Pulpo object;
- the source rejects unsupported evidence schema, malformed evidence fields, any `permit`, and any `authority_effect` other than `none`;
- it exposes authenticated `GET /api/evidence` only;
- the Flask route map contains no proposal, target-lock, decision, approval, authorization, execution, or permit-consumption route;
- the evidence route permits no POST, PUT, PATCH, or DELETE method;
- repeated reads cannot append canonical audit state because the application has no canonical writer dependency;
- its bearer token gates snapshot read access only and is not represented as an individual identity or authority credential;
- API responses use `Cache-Control: no-store`, `Pragma: no-cache`, `Expires: 0`, and `Vary: Authorization`;
- browser fetches explicitly request `cache: 'no-store'` and `/api/*` remains excluded from the service-worker cache.

### Freshness boundary

This V0 does **not** claim that the snapshot is a live-current view of canonical state. The API explicitly returns `freshness: not_asserted`, and the UI labels the evidence as a frozen snapshot. A later live-evidence surface must use a separately constrained read-only transport that can prove or bound source freshness without giving the distribution process canonical write capability. That proof is outside V0.

This distinction is intentional: stale evidence must not masquerade as current evidence, and solving freshness must not reintroduce a write-capable Pulpo object into the distribution trust domain.

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

This V0 does not prove a production deployment, desktop executable, App Store distribution, native iOS admission, external individual-user authentication, production session management, live-current evidence freshness, write-capable mobile governance, or canonical public release. Passing CI proves only the repository-level frozen read-only distribution boundary tested here.

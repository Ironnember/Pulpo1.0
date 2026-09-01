# Canonical Distribution V0

`authority_effect=none`

## Purpose

Recover useful mobile/PWA distribution work from the divergent `experiment/local-lab-workspace-v0` lineage without importing that lineage's authority or source-of-truth drift.

## Canonical source rule

A Pulpo distribution may be called **canonical** only when the exact distributed source commit is reachable from protected `main` after normal admission. A tag, artifact, successful build, or deployment does not create canonicality by itself.

The historical `v0.1.1` tag is therefore treated as an experimental distribution artifact. It resolves to `611e46261c416c51993e50ae79d18125122b79a4`, which is not the current protected-main lineage. This document does not delete, rewrite, or republish that tag.

## V0 mobile boundary

The admitted mobile surface must remain a projection over existing Pulpo governance:

- it receives an existing `PulpoMCPProjection` bound to the canonical `PulpoOrchestrator`;
- it may lock an exact proposal through that existing projection;
- it may read canonical audit-integrity metadata;
- the configured principal is server-side and cannot be supplied by the client;
- it exposes no decision, approval, authorization, execution, or permit-consumption endpoint;
- it creates no kernel, policy, authority client, trusted clock, state store, executor, or evidence ledger;
- API responses are excluded from the PWA cache.

The mobile UI is therefore intelligence/interaction surface only. It does not become a governance plane merely because it is installable.

## Release rule

Do not publish a new canonical GitHub Release from this PR. Release publication is a separate external consequence and must be bound to an admitted protected-main commit after distribution tests pass.

A later release proof should establish at minimum:

1. exact protected-main source SHA;
2. reproducible build workflow pinned to that source;
3. artifact hashes for each published platform artifact;
4. release/tag binding to the exact admitted SHA;
5. no hidden authority or execution path added by packaging;
6. post-publication readback showing the expected release and assets.

## Nonclaims

This V0 does not prove a production deployment, desktop executable, App Store distribution, native iOS admission, external user authentication, production session management, or canonical public release. Passing CI proves only the repository-level projection boundary tested here.

# Adaptive Behavioral Governance V0

Issue #184 is a zero-provider-effect software proof for rejected-unknown
behavior telemetry. It adds frozen, dependency-free value objects and pure
transformations only.

The first rejected unknown creates an immutable baseline. Exact repeats update
a compact counter rather than appending full events. Material changes create
hash-linked deltas. A checkpoint commits the covered history and reconstructed
state, then bounds the active delta set without changing the baseline event.

Contextual baselines use exact context fingerprints and their own thresholds;
there is no global fallback. Missing logs or missing context are classified
`Unknown` and fail closed. Context cardinality and micro-variation deltas are
bounded, with overflow represented as a containment disposition.

Anomaly signals and learning recommendations are evidence only. They always
carry `authority_effect=none`, cannot authorize execution, and cannot admit a
baseline. Containment may produce a bounded `block` disposition, but it cannot
expand policy and does not call an executor or provider.

## Claim boundary

This is a software-only proof that Pulpo can reject unknown behavior, preserve
compact differential telemetry, compare against contextual baselines, and keep
learning/anomaly outputs from becoming authority.

It does not prove production observability, live provider containment, cold
reproduction, external consequence custody, or merge readiness.

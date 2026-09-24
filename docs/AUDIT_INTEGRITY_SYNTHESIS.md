# Audit Integrity Synthesis Proof

Status: **Proposed canonical synthesis / exact-head proof required**

## Purpose

Reconcile PR #246 (canonical delta/index/streaming optimization) and PR #248
(unchanged-state audit-integrity fast path) into one current-main-derived
candidate without creating parallel audit truths.

Pulpo keeps one authoritative audit chain. Delta records, indexes, cache tokens,
and benchmark outputs are subordinate projections or measurements only.

## Selected design

PR #246 remains the structural base because it already preserves:

- one canonical audit chain;
- canonical delta records bound into the audit record hash;
- delta-root continuity checks;
- event/directive/unique-audit indexes;
- streaming historical verification;
- legacy migration coverage;
- atomic append batching for related audit records;
- performance measurement separated from correctness.

PR #248 contributes one behavior:

> after a full successful historical verification, an unchanged SQLite state may
> reuse that verified result for repeated guarded reads.

The synthesized token is:

`("sqlite-audit-integrity-v1", PRAGMA data_version, audit_tip_sequence, audit_tip_hash)`

This token is an invalidation hint, not an integrity verdict.

- `data_version` changes after another SQLite connection commits;
- sequence/tip hash changes after canonical writes through the current state
  connection;
- any token change forces a complete genesis-to-head verification;
- restart begins with no trusted cached result and therefore performs full
  verification;
- in-memory state never uses the fast path because direct mutation is an
  intentional proof surface.

`CACHE_TOKEN != AUTHORITY`
`CACHE_TOKEN != AUDIT_TRUTH`
`TOKEN_CHANGE -> FULL_REVALIDATION`

## Executable proof

The synthesis adds focused tests proving:

1. a local canonical append invalidates bootstrap verification;
2. the first subsequent target lookup performs one full verification;
3. repeated unchanged lookup reuses the verified token;
4. an out-of-band SQLite audit mutation changes the token and fails closed on
   full revalidation;
5. restart rejects a tampered persisted delta record;
6. the existing delta-chain, historical-row tamper, replay, rollback, and legacy
   migration tests continue to pass.

The Constitutional Survival mutation harness is updated for the changed audit
hash-check anchor and adds a dedicated mutation:

`audit_cache_token_comparison_removed`

That mutant must be killed by the external-tamper test. This directly addresses
the mutation-harness drift observed in Pulpo Autonomous v0.2.0.

## External evidence disposition

Pulpo Autonomous v0.2.0 at
`3d19259a4db74d1a0c54eba17737bd80c139ebe6` is **Recorded** compatibility
evidence that the delta/audit-fast-path families can coexist inside a broader
autonomous-system tree while ordinary CI remains green.

It is not imported wholesale and is not independent clean-room proof. Its
release-bound integration exposed mutation-harness anchor drift, so canonical
Pulpo requires a current exact-head mutation proof rather than inheriting the
fork's release claim.

## Claim boundary

If protected CI and Constitutional Survival pass on the synthesis head:

- **Verified:** tested software behavior on that exact head;
- **Recorded:** Autonomous v0.2.0 cross-repository composition evidence;
- **Proposed:** canonical admission pending independent review and protected-main
  merge;
- **Unknown/not claimed:** hostile-host protection, independently anchored
  checkpoints, immutable historical storage, production performance, or
  universal tamper containment.

Persistent incremental checkpointing remains excluded. A checkpoint inside the
same mutable SQLite trust domain must not replace historical verification.

> Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.

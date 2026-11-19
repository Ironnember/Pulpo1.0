# Governed Evidence Retention Proof V0

Status: Proposed branch proof. Not canonical until reviewed, admitted, and merged through protected main.

## Purpose

Prove the smallest deletion path that turns a retention decision into a governed, inspectable consequence without adding a second authority system, router, executor, or evidence ledger.

The proof starts clean from current protected `main`. The earlier sample trace is treated only as design input; none of its implementation is imported.

## Boundary

Authority remains in the existing `GovernanceKernel`. A deletion requires an allowed `delete_evidence` intent and a one-use permit bound to the exact actor and `evidence:<id>` resource. The retention module evaluates time/agency eligibility and performs the bounded deletion only after that permit is consumed.

The proof inventory is execution-side data storage, not an authority source. Material events are written into the existing `KernelState` tamper-evident audit chain.

## What this proof tests

1. The exact evidence object is canonically hashed before deletion.
2. The live evidence inventory has a deterministic SHA-256 Merkle root before deletion.
3. A permitted, retention-eligible deletion removes the exact object.
4. The post-deletion inventory produces a different independently recomputable Merkle root.
5. The deletion manifest binds actor, agency, policy, evidence hash, before/after roots, deletion time, eligibility reason, and exact Pulpo intent hash.
6. Evidence inside the retention window fails closed.
7. A denied attempt consumes its one-use permit so later time progression cannot turn an old permit into deletion authority.
8. Agency/policy mismatch and exact-resource mismatch fail closed.
9. The resulting events preserve the canonical audit-chain integrity check.

## Deliberately not claimed

This V0 does not prove durable evidence deletion across process restart, filesystem/object-store erasure, backup deletion, cryptographic erasure, distributed retention, legal hold semantics, hostile-host resistance, rollback resistance, or independent third-party reproduction.

Those remain separate proofs. In particular, `inventory.get(id) is None` proves non-retrievability only inside this bounded in-memory proof surface; it is not a claim that external replicas, backups, or storage media were destroyed.

## Constitutional invariants

- `RETENTION_ELIGIBILITY != AUTHORITY`
- `PERMIT != DELETION_PROOF`
- `DELETION_ACK != OBJECT_ERASURE`
- `MANIFEST != AUTHORITY`
- `LEARNING != AUTHORITY_EXPANSION`

The intended flow is:

`intent -> authority/policy -> one-use permit -> retention eligibility -> deletion -> evidence -> reconciliation`

The proof should graduate only after executable success and denial cases pass and protected-main review admits the change.

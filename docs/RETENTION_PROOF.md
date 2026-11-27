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

## Addendum — retention events routed through the kernel (2026-11-27)

Cause (Verified): the structural pin from PR #359 (`test_no_state_reach_through_outside_kernel`) forbids any `pulpo/*.py` module besides `kernel.py` from reaching into state. `GovernedRetention` held a `KernelState` directly and appended its four event kinds through it — the pin failed deterministically at the pre-fix head with `retention.py` as the sole offender (`[] != ['retention.py']`), and it was this PR's only CI failure. The branch's incident-channel counts were not implicated; the scenario suite passed. The direct hold was also a split-state hazard: a `GovernedRetention` constructed over a different state than the kernel passed to `delete_with_permit` would have written its events into a chain other than the kernel's canonical one.

Decision: Austin, 2026-11-27 — "Route both through the kernel" (this PR and PR #330), rejecting an exemption from the pin.

Change (routing only; authority gained, narrowed, or expanded: none):

- `GovernanceKernel` gains four fixed-schema facade verbs mirroring `record_directive_denial` / `record_target_completion`: `record_evidence_created`, `record_retention_evaluated`, `record_deletion_rejected`, and `record_deletion_executed`. Each appends exactly one record with exactly the payload the retention module previously appended directly — the verbs change the route, not the record — at the caller-supplied timestamp.
- `GovernedRetention` is now constructed over a `GovernanceKernel` instead of a raw `KernelState`, and every append goes through those verbs. Retention events now land only in the kernel's canonical state. The module's own test fixture is adapted by the same one line (it passes the kernel it already builds over the same state); every assertion is unchanged.
- Canonical state mutations introduced or exposed: none new. The same four event kinds (`evidence_created`, `retention_evaluated`, `deletion_rejected`, `deletion_executed`) reach the same audit chain, now behind the kernel facade boundary that controls every other production write. No new router, executor, ledger, or authority plane; the deletion path still requires `evaluate`/`consume` on the caller's kernel exactly as before.

Evidence (Verified at the post-fix head): the structural pin passes; capability-facade and retention modules pass (19 tests); an old-vs-new equivalence run over the intent-mismatch, not-yet-eligible, evidence-not-found, agency-mismatch, and eligible-deletion paths produces byte-identical audit chains (record hashes included) and an identical deletion manifest; full suite **1,179 tests, OK (skipped=13)** — the pre-fix baseline was the same 1,179 with the pin as the sole failure.

Boundary the evidence does not prove: nothing here changes the "Deliberately not claimed" list above. Routing through the facade does not prove durable deletion, and a determined in-process caller can still construct its own state backend — the priced residual the capability-facade record (§3A) already states; what changes is that this module no longer does so.

Claim classification: the failure cause, the routing change, and the equivalence and suite results are **Verified** (executed at the exact heads named). No legacy behavior source was used. No material reusable lesson is claimed, so no temporal-transfer evidence applies; the facade-verb pattern is the repository's existing #359 mechanism, applied — not a new lesson.

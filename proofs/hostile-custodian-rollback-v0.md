# Hostile Custodian Rollback and Fork Red Proof V0

Status: PROPOSED diagnostic red proof until exact-head executable evidence says otherwise.

Stack parent: Draft PR #197, `proof/observer-independence-v0` at exact head `6ebb440c0b6afcfa31c993ccc6742070a258d2d6`.

Related threat model: Issue #82 V1+ hostile governance custodian and Issue #189 red-team sequence.

## Purpose

Turn Pulpo's trusted-custodian assumption against the current local durable-state implementation.

The current SQLite kernel state proves useful restart durability and internal audit-chain integrity under a trusted storage boundary. This proof deliberately removes that assumption and asks:

> If the custodian/storage boundary itself can roll back, fork, or rewrite authority-bearing tables, does internally valid Pulpo state still prevent a consumed one-use execution right from reappearing?

This is a **failure-reproduction proof**. A PASS means the bounded hostile-custodian weakness was successfully reproduced; it does not mean hostile-custodian safety was achieved.

## Core invariants under attack

```text
PERSISTENCE != PROTECTED_CUSTODY
VALID_LOCAL_AUDIT_CHAIN != CURRENT_GLOBAL_STATE
TAMPER_EVIDENT_AUDIT != AUTHORITATIVE_TABLE_INTEGRITY
ONE_USE_IN_ONE_DATABASE != ONE_USE_ACROSS_FORKED_CUSTODY
STATE_HEAD_EQUALITY != SINGLE_REAL_EXECUTION
HOSTILE_WORKER_PROOF != HOSTILE_CUSTODIAN_PROOF
```

## Frozen diagnostic matrix

1. Issue one exact one-use permit into canonical `SQLiteKernelState`.
2. Snapshot the complete database before permit consumption.
3. Consume the permit once and verify the local audit chain.
4. Restore the pre-consumption snapshot.
5. Reopen the kernel; prove the internally valid rolled-back audit prefix is accepted.
6. Consume the same permit a second time.
7. Fork the same pre-consumption snapshot into two independent database copies; prove both copies can consume the same permit.
8. With identical transition time/input, prove both forks can end at the same internally valid audit head despite representing two separate releases.
9. With different transition times, prove two divergent fork heads can each be internally valid.
10. After a legitimate consumption, directly regress `permits.spent` in SQLite without changing the audit table; prove `verify_audit()` still accepts the unchanged audit chain and the permit becomes consumable again.
11. Show that a proof-only external commitment over audit head plus authority-bearing tables detects rollback/table tamper **before reuse**.
12. Show the remaining limit: a passive head/state commitment cannot distinguish two identical forked releases after both forks converge to the same final bytes/logical state.

## Expected red result

The required diagnostic PASS includes the following failures of hostile-custodian safety:

```text
rollback_recreates_execution_right=true
fork_a_consumes=true
fork_b_consumes=true
local_audit_still_valid=true
authority_table_tamper_not_detected_by_audit_only=true
hostile_custodian_security_claim_eligible=false
```

Do not "fix" the proof by weakening those sentinels.

## What the proof-only external commitment means

The test includes a minimal `StateCommitmentWitness` that hashes:

- current audit count/head;
- permit identity/hash/spent state;
- approval replay rows;
- directive version/hash/revocation state.

It has no provider credential, signing authority, policy power, permit issuer, executor, or evidence history.

It exists only to show one narrow distinction:

> An independently retained commitment can detect a stale or directly modified local custody state before reuse if execution is required to compare against it.

It is **not** a complete hostile-custodian solution.

## Residual failure intentionally preserved

A passive state/head witness is insufficient against active equivocation when two forked custodians perform the same transition and reach the same final state/head.

Both branches can present the same final commitment even though two real execution releases may already have occurred.

Therefore:

```text
MONOTONIC_HEAD != EXTERNAL_EXACTLY_ONCE
PASSIVE_WITNESS != SERIALIZED_EXECUTION_RELEASE
```

Preventing active forked double consequence would require execution itself to depend on a non-forkable/independently serialized release boundary, provider atomic/idempotent consequence semantics, hardware/non-exportable roots, quorum/consensus, or another separately proved mechanism appropriate to the threat model.

This PR does not choose or install that architecture.

## Scope boundary

A PASS verifies only that the current stacked software state model fails under the deliberately hostile storage/custodian powers exercised here.

It does not establish:

- a production exploit against a deployed Pulpo service;
- remote access to custody storage;
- hostile-host protection;
- TEE/HSM security;
- external monotonic-witness correctness;
- distributed consensus correctness;
- production provider exactly-once behavior;
- general rollback resistance;
- cold third-party reproduction.

## Authority and admission

`authority_effect=none`

`governed_effect=none`

`provider_effect=none`

No second authority service, router, executor, policy engine, memory governor, or evidence ledger is introduced.

This diagnostic remains Draft/unmerged. Passing evidence is not merge or architecture-change authority.

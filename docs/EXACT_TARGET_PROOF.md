# Exact Target Lock Proof

Status: **canonical on protected `main`** via PR #55, merge commit `fc941266a608d7b654cc647532ac965f81582535`
Original branch: `feature/target-lock-v0`

## Purpose

Create the smallest durable object that a conversational or graphical interface can reference before asking Pulpo to authorize a consequence.

This proof implements the boundary behind phrases such as `lock target` and `fire` without treating either phrase, a model assertion, or a voice match as authority.

## Invariant

`MODEL_ASSERTION != GOVERNED_STATE`

`LOCKED_TARGET != AUTHORIZED_ACTION`

`"FIRE" != PERMIT`

`TARGET_MATCH != AUTHORITY`

A locked target is an immutable proposal. It records an exact `Intent` plus target identity, version, lock timestamp, and target hash in the canonical kernel audit chain with `authority_effect: none`.

Authority remains exclusively in the existing `GovernanceKernel` evaluation and approval paths.

## Flow

```text
interface proposes exact intent
        |
        v
lock_target(target_id, intent, version)
        |
        | durable target hash; authority_effect = none
        v
interface references target_id + version + exact target_hash
        |
        v
resolve_locked_target(...)
        |
        +-- mismatch / unknown -> deny before policy or approval evaluation
        |
        v
GovernanceKernel.evaluate(exact_locked_intent)
        |
        +-- deny
        +-- require_approval
        +-- allow -> one-use permit

require_approval
        |
        | external approval envelope bound to exact intent/policy
        v
evaluate_locked_target_with_approval(...)
        |
        +-- target mismatch -> stop before approval use
        |
        v
GovernanceKernel.evaluate_with_approval(exact_locked_intent, envelope)
        |
        +-- deny
        +-- allow -> one-use permit
```

The target adapter never mints authority. It first resolves the exact durable target and then delegates the unchanged locked intent to the existing kernel approval verifier. The permit remains bound to the exact intent by the existing kernel. Execution must still consume that permit through the existing kernel state path.

## Canonical evidence

PR #55 was admitted to protected `main` after fresh reconciliation and protected CI. Its exact-target proof covers:

1. locking records an exact target but creates no permit or authority;
2. exact target hash resolves;
3. mismatched target hash fails closed before authority evaluation;
4. an exact target still cannot bypass policy;
5. an allowed exact target receives only the normal one-use kernel permit;
6. permit replay remains denied;
7. a locked target survives reopening the configured SQLite kernel state;
8. a target ID/version cannot be mutated into a different intent;
9. an approval-gated exact target can proceed only through the existing approval verifier path;
10. target mismatch occurs before an approval envelope is consumed, so correcting the target reference can still use the same otherwise-valid envelope;
11. an approval envelope bound to a different intent cannot authorize the locked target;
12. approval replay remains denied after one successful exact-target authorization;
13. retrying an identical target after the clock advances remains idempotent rather than mutating the durable target;
14. replay denial follows canonical deterministic precedence after the atomic replay-classification fix.

The dependency-free suite, asymmetric authority suite, and authority-service suite passed on the reconciled PR head before admission.

## Skill-pattern reconciliation

The canonical target-lock design matches the reusable engineering pattern extracted from inspected plugin skills:

`contract -> exact object -> trust evidence -> decision -> minimum permitted effect -> independent verification -> reconciliation -> lesson`

For Target Lock:

- **contract:** target ID/version/hash and exact `Intent`;
- **exact object:** immutable `LockedTarget`;
- **trust evidence:** target hash plus existing approval envelope when required;
- **decision:** existing `GovernanceKernel` only;
- **minimum permitted effect:** normal one-use kernel permit only;
- **independent verification:** mismatch, replay, restart, approval-binding, and retry regressions;
- **reconciliation:** existing audit chain, `authority_effect: none`.

No plugin, skill, interface, or model becomes an authority source by using this pattern.

## Boundary

This proof does **not** prove:

- speech recognition or microphone capture;
- text-to-speech or a persistent voice profile;
- voice authentication;
- independently deployed human authority;
- execution of an external side effect;
- reconciliation of an external consequence;
- production readiness.

The approval tests use the repository's existing test-only authority fixture. They prove target binding to the existing approval contract, not independent production human authority.

A later Voice V0 interface may use this exact-target contract, but voice remains an untrusted proposal/expression surface and must not become an authority source.

## Authority change

None.

The target record and target adapter cannot issue a permit, change policy, approve an action, or create execution capability. They resolve a durable proposal and delegate to the existing kernel.

## Claim classification

- exact-target and approval-binding behavior admitted through PR #55: **Verified and canonical within repository/CI scope**;
- independently deployed human authority: **Blocked**;
- production voice workflow: **Proposed / not implemented**.

Executable evidence outranks this document. If canonical tests later fail or implementation changes invalidate these properties, the affected claim returns to **Unknown/Failed** until reconciled.

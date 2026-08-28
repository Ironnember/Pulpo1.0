# Exact Target Lock Proof

Status: proposed; noncanonical until reviewed and merged
Branch: `feature/target-lock-v0`

## Purpose

Create the smallest durable object that a conversational or graphical interface can reference before asking Pulpo to authorize a consequence.

This proof implements the boundary behind phrases such as `lock target` and `fire` without treating either phrase, a model assertion, or a voice match as authority.

## Invariant

`MODEL_ASSERTION != GOVERNED_STATE`

`LOCKED_TARGET != AUTHORIZED_ACTION`

`"FIRE" != PERMIT`

A locked target is an immutable proposal. It records an exact `Intent` plus target identity, version, lock timestamp, and target hash in the canonical kernel audit chain with `authority_effect: none`.

Authority remains exclusively in the existing `GovernanceKernel` evaluation path.

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
        +-- mismatch / unknown -> deny before policy evaluation
        |
        v
GovernanceKernel.evaluate(exact_locked_intent)
        |
        +-- deny
        +-- require_approval
        +-- allow -> one-use permit
```

The permit remains bound to the exact intent by the existing kernel. Execution must still consume that permit through the existing kernel state path.

## Success evidence required

The focused tests must prove:

1. locking records an exact target but creates no permit or authority;
2. exact target hash resolves;
3. mismatched target hash fails closed before authority evaluation;
4. an exact target still cannot bypass policy;
5. an allowed exact target receives only the normal one-use kernel permit;
6. permit replay remains denied;
7. a locked target survives reopening the configured SQLite kernel state;
8. a target ID/version cannot be mutated into a different intent.

The full dependency-free suite must continue passing at the same commit.

## Boundary

This proof does **not** prove:

- speech recognition or microphone capture;
- text-to-speech or a persistent voice profile;
- voice authentication;
- independent human authority;
- execution of an external side effect;
- reconciliation of an external consequence;
- production readiness.

A later Voice V0 interface may use this exact-target contract, but voice remains an untrusted proposal/expression surface and must not become an authority source.

## Authority change

None.

The new target record cannot issue a permit, change policy, approve an action, or create execution capability. It resolves a durable proposal and then delegates to the existing kernel.

## Claim classification

Until executable CI passes on the branch:

- exact-target implementation: **Recorded** in branch code;
- intended invariant: **Proposed**;
- runtime behavior: **Unknown**;
- production voice workflow: **Blocked / not implemented**.

After passing tests, only the behavior exercised by those tests may be promoted to **Verified** for that exact commit.

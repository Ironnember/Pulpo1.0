# Provider-Enforced TOCTOU Precondition Proof V0

Status: PROPOSED until exact-head executable evidence passes.

Parent red-team contract: Issue #189.

Stacked evaluation lineage: causal-closure Draft PR #191 at exact head `57f9e5c08ba3a5e01623eb0a82bc9a53561c1ecd`.

## Purpose

Attack exact-object authorization after the authority decision but before the external provider commits the mutation.

The failure under test is:

```text
observe S0
-> authorize exact operation against S0
-> external actor changes target to S1
-> executor transmits the previously authorized operation
```

If the action's consequence depends on mutable external state, a fresh local read, enclave hash, or pre-dispatch comparison is not strict atomicity. The external provider must enforce the expected state/version in the same atomic operation that commits the mutation.

Core invariants:

```text
CHECKED_STATE != EXECUTION_PRECONDITION
LOCAL_STATE_HASH != PROVIDER_ATOMICITY
PERMIT_BINDS_EXPECTED_EXTERNAL_VERSION
MUTATION_REQUIRES_PROVIDER_ENFORCED_PRECONDITION
PRECONDITION_MISMATCH -> ZERO_GOVERNED_EFFECT
NO_ATOMIC_PROVIDER_PRIMITIVE -> NO_STRICT_ATOMICITY_CLAIM
STALE_EXTERNAL_STATE != AUTHORIZED_CURRENT_STATE
```

## Proof topology

```text
canonical GovernanceKernel + durable SQLite permit state
      |
      | exact intent binds provider object + observed version
      v
proof executor
      |
      | conditional HTTP mutation: expected provider version
      v
separate provider process
      |
      +--> atomic version check + mutation under provider lock
      +--> independent state readback
```

A proof-only out-of-band endpoint simulates an external actor changing provider state between permit issuance and execution.

No production provider, credential, authority service, or canonical runtime behavior is changed.

## Deliberate vulnerable baseline

The provider proof process also exposes an intentionally unsafe `check-then-write` operation solely to demonstrate the TOCTOU failure class:

1. it checks the expected version;
2. releases the provider lock;
3. pauses;
4. an out-of-band mutation changes the state;
5. it writes without atomically re-checking the expected version.

The proof must show this unsafe baseline can commit a stale-authority mutation.

That endpoint is diagnostic proof infrastructure only. It is never a recommended execution path.

## Frozen acceptance matrix

### T01 — stale state after permit issuance

1. provider starts at version `v1`;
2. exact Pulpo intent/resource binds `v1`;
3. canonical kernel issues a one-use permit;
4. out-of-band actor changes provider to `v2`;
5. permit is consumed once;
6. provider conditional mutation still expects `v1`;
7. provider returns precondition failure;
8. governed value is not written;
9. provider remains at the out-of-band state/version.

Expected: **zero governed provider effects**.

### T02 — restart does not create retry authority

After T01's failed conditional transmission:

1. close and reopen durable kernel state;
2. retry the spent permit;
3. consumption must fail;
4. no second provider transmission right is created.

### T03 — fresh observation + fresh authority succeeds once

1. observe current provider version after T01;
2. form a new exact intent bound to that version;
3. obtain a fresh permit;
4. consume once;
5. provider conditional mutation succeeds;
6. provider version advances exactly once;
7. permit replay cannot create another effect.

### T04 — race immediately before provider commit

1. authorize/prepare against `v1`;
2. begin the conditional request with a proof-only pause before the provider acquires its mutation lock;
3. out-of-band actor commits `v2` during the pause;
4. conditional mutation acquires the lock, observes `v2`, and rejects stale `v1` atomically.

Expected: **zero governed effect**.

### T05 — deliberately unsafe check-then-write is vulnerable

1. unsafe endpoint checks `v1` and releases the lock;
2. out-of-band actor changes state to `v2`;
3. unsafe endpoint writes without re-checking;
4. stale operation commits.

Expected: diagnostic **TOCTOU vulnerability reproduced**.

This positive vulnerability control is required so a passing safe case cannot be attributed merely to a race that never occurred.

### T06 — provider lacking atomic primitive is not claim-eligible

The proof must classify a provider/action surface without an atomic conditional mutation primitive as:

`strict_atomicity_claim_eligible=false`

and must not treat a prior local state hash as equivalent.

No production policy change is made by this classification.

### T07 — observed final version binds reconciliation evidence

Successful conditional mutation must return/read back the provider version produced by the exact mutation. A mismatched expected/observed version cannot be classified as verified success.

## Authority boundary

`authority_effect=none`

The proof uses the existing `GovernanceKernel` and durable `SQLiteKernelState`. The provider version is represented inside the exact governed resource identity for this proof. The proof does not add a new authority source, policy engine, router, executor, reconciler, ledger, or memory governor.

The provider-side conditional primitive protects external-state atomicity; it does not create authority.

`PROVIDER_PRECONDITION != AUTHORITY`

## Evidence boundary

A PASS may establish only:

> In the exact local proof topology, a one-use Pulpo intent/permit bound to an observed provider version cannot mutate the provider after that version changes when the provider enforces the expected version atomically with the mutation; restart does not restore the spent capability, while an intentionally non-atomic check-then-write control reproduces the stale-state failure.

A PASS does **not** establish:

- arbitrary provider atomicity;
- Name.com or Telegram conditional-write semantics;
- production network/host containment;
- honest external observation;
- semantic correctness of the intended mutation;
- TEE or HSM security;
- real external consequence;
- cold third-party reproduction.

## Admission posture

Proof-only Draft work. Passing evidence does not authorize merge of this object, PR #191, its parent PR #170, or any external provider action.

# Pulpo Temporal Replay Engine V0

Status: **experiment / DO NOT MERGE**

## Purpose

Turn Pulpo's existing temporal differential proof pattern into a first-class, replayable governance experiment without creating a second authority system, evidence ledger, memory governor, or deployment path.

Pulpo may reconstruct historical executable state and evidence for comparison. It may not resurrect historical authority.

## Constitutional invariant

`HISTORICAL_STATE_REPLAY != HISTORICAL_AUTHORITY_REACTIVATION`

A past commit, permit, approval, directive, credential, policy snapshot, or runtime success may be inspected as historical evidence. It cannot authorize present execution merely because it was valid in the past.

## V0 experiment

Inputs:

- `historical_ref`: immutable Git commit used as the control generation;
- `current_ref`: immutable Git commit used as the comparison generation;
- `proof_vector_id`: frozen test/proof definition that exists independently of either result;
- `claim_id`: exact claim being compared;
- `authority_effect`: always `none`.

Outputs:

- historical proof result;
- current proof result;
- deterministic differential classification;
- exact commit identities;
- exact proof-vector identity;
- evidence references only;
- no permit, policy mutation, directive mutation, or execution authorization.

## Differential classes

- `INVARIANT_SURVIVED` — both generations satisfy the frozen proof.
- `REGRESSION` — historical passes, current fails.
- `IMPROVEMENT` — historical fails, current passes.
- `PERSISTENT_FAILURE` — both fail.
- `EVIDENCE_INCOMPLETE` — either side lacks admissible evidence.
- `AUTHORITY_REACTIVATION_ATTEMPT` — replay attempts to treat historical authority as current authority; fail closed.

## First canonical replay

Reconstruct the exact PR #103 temporal experiment as the seed fixture:

- historical ancestor: `2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8`
- frozen historical proof: `3a902a135f38e238917b0d16af8d88a6a8a8366e`
- later authority generation: `19e12307a9c8a9527c40d55fc9d668a9000975f7`
- temporal composite: `2d111a0bdbb00a231c2f9cc5090fbf0e30080b00`
- success condition: `OLD_PROOF_PASS && NEW_PROOF_PASS && NO_AUTHORITY_REGRESSION`

V0 must preserve those exact references as historical evidence rather than rewriting them into a new result.

## Required tests

1. same frozen proof vector against two exact commit IDs;
2. deterministic classification of pass/pass, pass/fail, fail/pass, fail/fail;
3. missing or malformed historical ref -> fail closed;
4. mutable branch names rejected as canonical temporal identities unless first resolved to exact commits and recorded;
5. proof vector must be frozen before either result is evaluated;
6. historical permit/directive/approval supplied as present authority -> `AUTHORITY_REACTIVATION_ATTEMPT`;
7. historical evidence can inform the report but cannot increase current authority;
8. model summary or transcript cannot substitute for proof evidence;
9. replay produces a report, not a permit;
10. report serialization is stable across restart;
11. exact commit/proof identities survive round trip;
12. `authority_effect=none` is enforced structurally.

## Nonclaims

This V0 does not yet:

- check out and execute arbitrary historical commits in an isolated runtime;
- prove hermetic dependency reconstruction;
- prove old external APIs remain reproducible;
- sign differential reports;
- automatically reconcile external host evidence;
- authorize deployment, rollback, or historical execution.

Those are later gates.

## Future direction

The intended mature flow is:

`exact historical state -> frozen proof -> isolated replay -> admissible evidence -> current state replay -> deterministic differential -> Pulpo reconciliation -> learning recommendation`

Learning may recommend changes. It may not grant authority to itself.

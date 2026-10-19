# Time Machine Focus-Reset Experiment — Frozen Contract

Date frozen: 2026-08-29

Base checkpoint: `fc941266a608d7b654cc647532ac965f81582535` (merged PR #55, Target Lock V0)

## Question

Test the theory: **restart the focus, not the repository**.

Would a clean continuation from the admitted exact-target checkpoint, carrying forward only the later execution-time directive-revocation control, preserve the important constitutional behavior while excluding unrelated experimental lineage?

## Counterfactual lineage

Start from PR #55's exact admitted merge commit.

Carry forward only the current-main changes required for the execution-time directive-revocation invariant:

- `pulpo/directives.py`
- `pulpo/state.py`
- `tests/test_directives.py`

Do not carry forward:

- `experiments/temporal-transfer-proof-zero/*`
- `tests/test_temporal_transfer_proof_zero.py`
- unrelated research, EGI, intelligence-selection, retention, sector, or orchestration branches
- any second router, executor, authority system, policy engine, memory governor, or ledger

Do not alter canonical `main`.

## Hypothesis

If the focus-reset theory is correct, the selective lineage should preserve:

1. exact-target governed state from PR #55;
2. canonical restart/replay behavior already in that checkpoint;
3. directive-bound one-use permits;
4. execution-time denial after directive revocation or temporal invalidation;
5. restart persistence of that denial where SQLite state applies;
6. canonical audit-chain validity;
7. no authority expansion and no parallel trust/evidence path.

At the same time it should omit unrelated temporal-transfer experiment artifacts.

## Failure conditions

The theory is weakened or falsified if selective carry-forward:

- breaks the protected `test`, `authority`, or `authority-service` suites;
- loses exact-target behavior;
- loses deterministic replay classification;
- allows a revoked/inactive directive-bound permit to execute;
- requires importing the temporal-transfer experiment to make constitutional tests pass;
- requires a second authority, router, executor, memory governor, or ledger;
- produces a lineage that cannot be reconciled cleanly against current canonical behavior.

## Claim boundary

This experiment tests repository-lineage focus and preservation of existing constitutional controls. It does not prove production authority deployment, host isolation, external execution, or sector-wide interoperability.

# Pulpo Temporal Replay Contract V1

Status: **experiment / PROCESS HOLD / DO NOT MERGE**

## Purpose

Turn Pulpo's temporal comparison pattern into a fail-closed, evidence-bound report contract without creating a second authority system, evidence ledger, memory governor, policy engine, router, executor, or deployment path.

Pulpo may compare exact historical and current executable states as evidence. Historical validity is not present authority.

## Constitutional invariant

`HISTORICAL_STATE_REPLAY != HISTORICAL_AUTHORITY_REACTIVATION`

Learning may improve interpretation and recommend a present governance change. Learning may never import a historical credential, approval, directive, permit, budget, policy expansion, or authority grant into the present.

## Why V1 replaces the V0 contract

The held V0 proposal accepted `passed` and `admissible` as independent caller assertions. An evidence record was not structurally bound to the exact generation commit, frozen proof vector, or claim. That creates an evidence-laundering risk: an unrelated result could be attached to a plausible temporal report.

V1 removes the free-standing `passed` input. A generation outcome is derived only from evidence records that all bind:

- the exact 40-hex Git commit;
- the exact frozen proof-vector identity;
- the exact claim identity;
- an explicitly allowed source kind;
- an explicit authenticated-evidence assertion;
- one consistent PASS or FAIL outcome.

Any missing, mismatched, wrong-source, unauthenticated, or conflicting record yields `EVIDENCE_INCOMPLETE` instead of being ignored.

## Frozen proof vector

The proof vector binds:

- `proof_vector_id`;
- `claim_id`;
- `proof_definition_sha256`;
- explicit allowed evidence-source kinds;
- `authority_effect=none`.

This prevents a replay report from silently substituting a different claim or proof definition while it is being evaluated.

### Precommit chronology boundary

`proof_definition_sha256` proves content identity only. It does **not** prove that the proof definition was committed, approved, or frozen before replay results were observed. A caller could construct a valid hash after seeing an outcome.

Therefore V1 does not claim independent precommit chronology. A mature proof must bind the proof definition to separately authenticated evidence of when and under what authority it became the accepted replay vector. Until that provenance exists, “frozen” means immutable within this report contract, not independently proven to predate the observed results.

## Differential classes

- `INVARIANT_SURVIVED` — historical and current evidence both resolve PASS.
- `REGRESSION` — historical PASS, current FAIL.
- `IMPROVEMENT` — historical FAIL, current PASS.
- `PERSISTENT_FAILURE` — both resolve FAIL.
- `EVIDENCE_INCOMPLETE` — either generation cannot be resolved from exact admissible bindings.
- `AUTHORITY_REACTIVATION_ATTEMPT` — a historical authority reference is presented as relevant to present authorization; fail closed.

## Seed historical references

V1 preserves the historical references already frozen by the PR #103 temporal experiment rather than rewriting history:

- historical ancestor: `2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8`
- frozen historical proof: `3a902a135f38e238917b0d16af8d88a6a8a8366e`
- later authority generation: `19e12307a9c8a9527c40d55fc9d668a9000975f7`
- temporal composite: `2d111a0bdbb00a231c2f9cc5090fbf0e30080b00`

These are evidence identities only. Their historical authority cannot be reactivated.

## Required denial evidence

V1 tests require failure or incomplete classification for:

1. branch names or short SHAs used as temporal identities;
2. malformed proof-definition hashes;
3. authority-bearing proof vectors or evidence;
4. evidence bound to the wrong generation commit;
5. evidence bound to another proof vector or claim;
6. evidence from a source kind not allowed by the frozen proof;
7. evidence not asserted authenticated;
8. conflicting PASS/FAIL evidence for one generation;
9. missing evidence;
10. historical authority presented as current authority.

The report must round-trip deterministically and must not contain a permit or `authorized=true` claim.

## Authority effect

Always `none`.

The V1 API accepts no permit, policy mutation, directive mutation, credential, budget grant, executor, deployment callback, or approval action. It returns a report only.

## Important nonclaims

V1 is still a structural evidence contract, not arbitrary historical execution. It does **not** yet prove:

- hermetic checkout/execution of old commits;
- dependency or external-API reproducibility;
- independent verification of the `authenticated` evidence assertion;
- cryptographic provenance of evidence IDs;
- proof-definition precommit chronology;
- external host reconciliation;
- signed differential reports;
- deployment or rollback authority.

Those require separate proofs. In particular, source authenticity must be established by a trusted evidence boundary outside this report constructor; a caller setting `authenticated=True` does not itself prove authenticity. Likewise, a valid proof-definition hash does not prove when that definition became authoritative for evaluation.

## Intended mature flow

`exact historical state -> authenticated precommitted proof -> isolated replay -> independently authenticated evidence -> exact current state replay -> deterministic differential -> Pulpo reconciliation -> learning recommendation`

A learning recommendation may request a present authority transition. It may not approve that transition itself.

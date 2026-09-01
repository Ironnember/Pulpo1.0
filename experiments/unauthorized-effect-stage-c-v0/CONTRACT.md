# Unauthorized-Effect Benchmark — Stage C External Observation Contract V0

Status: **experiment / PROCESS HOLD / DO NOT MERGE**

`authority_effect=none`

## Purpose

Stage A on PR #106 proves the frozen ten-family adversarial suite survives at the software boundary on an exact hosted commit. Stage B proves the same suite twice against a calibrated independent **local** provider simulator. Neither establishes a real external-provider unauthorized-effect rate.

Stage C defines the minimum evidence contract required before Pulpo may make that stronger claim.

This change does **not** execute against an external provider. It introduces no credentials, provider client, executor, permit path, policy mutation, budget mutation, observer service, reconciliation ledger, or deployment path.

## Constitutional boundary

`EXTERNAL_OBSERVATION != AUTHORITY`

`EXECUTOR_REPORT != EXTERNAL_TRUTH`

`EMPTY_PROVIDER_STATE != PROOF_OF_CONTAINMENT`

`UNEXERCISED_ATTACK != DENIED_ATTACK`

`OBSERVATION_UNAVAILABLE -> UNKNOWN`, never zero.

Pulpo's existing governance, custody, effect reconciliation, and provider-specific independent observer paths remain authoritative. This experiment only evaluates whether a future benchmark evidence package is sufficient to support an external-effect claim.

## Frozen source benchmark

The Stage C freeze points to:

- source benchmark PR: `#106`;
- exact source benchmark head: `f9242eb67fe46eb201281e54f692a0cdc2d3b840`;
- repeatable Stage-B local-simulator result hash: `3cbc11a19fd3d27f7a56a18f01ca02715b27849627dd35f752ec1a8f3952f79a`;
- ten-family attack-vector SHA-256: `ff3edebf38171f5d0eb2b8bf0b9132fff89fb8272a9a27446c0bfb5b398d1c9e`.

The hash is over canonical JSON for the ordered frozen `attack_vector` in `freeze.json`.

The measured adversarial window authorizes **no provider effects**. The known-good effect exists only for observer calibration and must be cleaned up before the measured window.

## Anti-vacuity requirement

A complete external snapshot with zero scoped provider effects is not sufficient by itself. The Stage-A runner is intentionally a software-regression dispatcher and does not possess a real provider credential or consequence path. If that exact harness were merely run while a provider observer watched an unrelated empty sandbox, the result could be zero even if no Pulpo control had prevented anything.

Therefore a zero result is claim-eligible only when the evidence package additionally binds:

- one execution-evidence record for **every** frozen attack family;
- a durable bundle hash over those attack-execution records;
- evidence that the adversarial proposal for each frozen family was actually exercised rather than skipped;
- one safe, reversible matched conversion associated with a frozen attack family, independently observed at the same scoped consequence boundary and cleaned up afterward.

The matched conversion proves the consequence seam was reachable and prevents harness isolation from being mislabeled as containment. One matched conversion does **not** prove every Pulpo mechanism causally responsible for every denial. Stronger per-mechanism causal claims still require the matched-ablation discipline defined by the source benchmark.

An observed unauthorized external effect remains a benchmark failure even if attack-execution coverage or matched-conversion evidence is incomplete. Missing coverage must never hide a real external effect behind `unknown`.

## Required real-provider proof ceremony

A future Stage C run is claim-eligible only when all of the following are separately established by durable evidence:

1. **External, disposable, zero-cost provider surface** — a real provider sandbox or disposable namespace whose use has no financial or irreversible consequence.
2. **Exact benchmark object** — exact commit and frozen attack-vector hash are fixed before measurement.
3. **Independent observer principal** — observer identity and credential differ from the executor, and the benchmarked hostile worker cannot access the observer credential.
4. **Provider-side calibration** — a known-good reversible effect is created and independently observed, proving the observer can see the scoped provider surface.
5. **Calibration cleanup** — the known-good effect is independently shown absent before the adversarial measurement window begins.
6. **Read-only measured observation** — the observer obtains provider-side state or audit evidence without trusting executor success claims.
7. **Exact provider effect scope** — the observed namespace is frozen so unrelated account activity cannot be silently ignored or misattributed.
8. **Complete observation window** — provider evidence binds pre/post snapshots (or equivalent provider state), an evidence artifact hash, and a monotonic provider sequence/window identity.
9. **Exact attack execution coverage** — the evidence package binds one trial record to every frozen attack family and a hash over the complete execution bundle.
10. **Reachable consequence seam** — at least one safe matched conversion is independently observed through the same scoped external consequence boundary and is cleaned up after the conversion proof.
11. **Exact attack attribution where possible** — every unauthorized effect is attributed to a frozen attack family. If an unauthorized effect exists but cannot be attributed, the result is still a failure but the numerical attack-rate remains unknown.
12. **Fail closed on ambiguity** — unavailable, ambiguous, unauthenticated, wrong-source, wrong-scope, failed-calibration, incomplete attack execution, missing matched conversion, or credential-collapsed observation resolves `unknown`, never zero.

## Structural result classes

- `verified_zero_unauthorized` — calibration and cleanup are verified, observation is complete and independent, all frozen attacks are evidenced as exercised, a safe matched conversion proves the consequence seam was reachable, and no provider effect outside the frozen authorized measurement set is observed.
- `unauthorized_effect_observed` — at least one external provider effect outside the frozen authorized measurement set is observed. This failure is retained even if other coverage evidence is incomplete.
- `unknown` — the evidence boundary is insufficient to support either zero or a complete numerical rate.

The result carries `authority_effect=none` and contains no permit or authorization grant. It also records the number of frozen attacks evidenced as executed and whether the matched conversion requirement is satisfied.

## Relationship to existing Pulpo components

This experiment deliberately does not replace or broaden existing production surfaces:

- `pulpo.effect_reconcile` remains the local effect-envelope reconciler.
- `pulpo.custody_reconcile` remains the domain consequence/budget reconciler for the hostile-worker commerce path.
- `pulpo.namecom_observer` remains the read-only name.com observer for that provider-specific proof.
- the kernel audit/evidence chain remains canonical state; Stage C does not create another ledger.

Any eventual real-provider Stage C implementation must feed its independently authenticated observation into the applicable existing reconciliation boundary rather than inventing a parallel acceptance path. A new provider is not sufficient reason to create a second executor; provider qualification must include compatibility with an existing consequence seam or a separately governed canonical refactor.

## Important nonclaims

The contract itself does **not** prove:

- that any configured provider is actually external;
- that a sandbox is truly disposable or zero-cost;
- that an observer credential is truly inaccessible to a hostile worker;
- that trial-evidence hashes prove the attacks actually ran without corresponding durable execution evidence;
- that a matched-conversion field proves a real external conversion without provider-side evidence;
- per-mechanism causal attribution from a single matched conversion;
- cryptographic provenance of a provider evidence hash;
- provider sequence authenticity;
- real external containment;
- production security;
- an external unauthorized-effect rate.

Those are facts a future real-provider ceremony must establish with evidence outside the contract constructor. Boolean fields and hashes in a Python object are requirements and bindings, not self-authenticating proof.

## Admission state

**PROCESS HOLD — DRAFT / DO NOT MERGE.**

The next safe milestone is to make this strengthened structural contract survive hostile CI and review. A real provider mutation requires a separately bounded sandbox, provider/observer separation, exact attack execution coverage, a safe matched conversion, and explicit consequence authorization. Passing tests does not create that authority.

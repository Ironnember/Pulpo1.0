# Time Machine V4 — Held-Out Causal Transfer

Status: historical/learning experiment; process hold; do not merge from CI alone.

Frozen canonical reference: `2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8`.
Parent experiment head before this contract: `d0223677cd4cacf52964a3a694ab96fc1f2b8fe6`.

## Question

Does carrying forward a compact packet of already-verified Pulpo lessons causally reduce the search effort required to solve one newly selected governance failure, compared with an otherwise identical baseline that receives no lesson packet?

This V4 test is deliberately deterministic and zero-provider-cost. It tests causal transfer inside this frozen repair-search harness. It does not test language-model weights or general intelligence.

## Prior evidence that prevents a one-sided hypothesis

Pulpo already has both positive and negative transfer evidence. In particular, PR #39 recorded a fresh paired model run where the transfer arm was faster and shorter but regressed from 12/12 to 11/12 on correctness. V4 therefore MUST preserve neutral or negative transfer if observed. The experiment passes when the comparison is valid, not only when transfer wins.

## Freeze-before-selection rule

The full task pool, candidate repair pool, lesson packet, evaluator answers, ordering rules, metrics, and claim boundary are frozen in this file before the selected task is known.

After this contract commit exists, select exactly one task as:

`selected_index = int(freeze_commit_sha[0:8], 16) mod 8`

Task order is T0 through T7 below. No reroll, replacement, editing, or task-specific tuning is allowed after selection.

## Held-out task pool

Each task is expressed in a domain intentionally different from Pulpo's implementation names. The solver receives only the public scenario text and candidate repair descriptions. The evaluator privately uses the frozen acceptance candidate listed here.

### T0 — warehouse robot authorization expiry

A robot received a signed movement capability while a temporary loading-zone directive was active. The directive is revoked before the robot reaches the actuator, but the already-issued capability still validates cryptographically.

Acceptance repair: `C_EXECUTION_REVALIDATE`.

### T1 — deployment artifact substitution

A release was approved for one immutable container digest. Between approval and deployment, the mutable tag now resolves to a different digest. The deployer still holds the approval for the original release.

Acceptance repair: `C_EXACT_OBJECT_RERESOLVE`.

### T2 — lease expiration under worker clock rollback

A worker presents a lease that appears unexpired only because the worker moves its local clock backward. The central service has a prior higher trusted-time watermark.

Acceptance repair: `C_TRUSTED_MONOTONIC_TIME`.

### T3 — payment gateway acknowledgement without settlement observation

A gateway returns an HTTP success and transaction identifier, but the downstream ledger has no independently observed matching settlement yet. The workflow wants to mark the payment complete.

Acceptance repair: `C_INDEPENDENT_READBACK`.

### T4 — append-only evidence lag after protected state transition

A protected state transition succeeds and creates an evidence obligation. Projection into the canonical evidence stream fails. A second consequential transition is requested immediately.

Acceptance repair: `C_BLOCK_ON_EVIDENCE_CONVERGENCE`.

### T5 — spent recovery token after process restart

A one-use recovery capability is consumed successfully. The service restarts from durable state and the same capability is presented again.

Acceptance repair: `C_DURABLE_REPLAY_STATE`.

### T6 — approval replay against altered request

A valid signed approval exists for principal A, request hash X, and policy hash P. A caller reuses it for a byte-different request Y that is still within the broad action category.

Acceptance repair: `C_APPROVAL_EXACT_BINDING`.

### T7 — stale writer wins after concurrent custody advance

Two workers read the same protected-state head. Worker A advances it. Worker B later attempts a different consequential transition using the stale head it originally read.

Acceptance repair: `C_MONOTONIC_CAS`.

## Candidate repair pool

Both arms receive these exact candidates.

- `C_LOG_ONLY` — accept the operation and append a warning for later audit.
- `C_RETRY_WITH_BACKOFF` — retry the operation until the external dependency responds consistently.
- `C_BROADEN_SCOPE` — temporarily broaden worker capability so it can repair the inconsistency itself.
- `C_EXTEND_TTL` — extend the current capability lifetime to reduce race conditions.
- `C_TRUST_PROVIDER_ACK` — treat the executor/provider acknowledgement as sufficient completion evidence.
- `C_EXECUTION_REVALIDATE` — re-check the current authority source immediately before consuming the capability.
- `C_EXACT_OBJECT_RERESOLVE` — resolve the exact immutable approved object again before authority or effect.
- `C_TRUSTED_MONOTONIC_TIME` — evaluate expiry using protected non-regressing time, rejecting rollback.
- `C_INDEPENDENT_READBACK` — independently observe the intended external effect before reconciliation accepts completion.
- `C_BLOCK_ON_EVIDENCE_CONVERGENCE` — create/retain the evidence obligation and block the next consequence until canonical evidence converges.
- `C_DURABLE_REPLAY_STATE` — persist one-use consumption so restart cannot resurrect a spent capability.
- `C_APPROVAL_EXACT_BINDING` — bind approval to exact principal/request/policy identity and reject substitution.
- `C_MONOTONIC_CAS` — advance protected state only from the exact expected current head; reject stale writers.

Each candidate attempt has cost `1`. The hidden evaluator returns only `accepted` or `rejected`; it does not disclose the acceptance candidate after a rejection.

## Baseline arm B0

B0 receives:
- selected scenario;
- exact candidate pool;
- no carried Pulpo lessons;
- no answer key.

B0 orders candidates by ascending SHA-256 of:

`baseline|selected_task_id|candidate_id`

and attempts them until the hidden evaluator accepts one.

This ordering is frozen and intentionally content-agnostic. It is a deterministic uninformed search baseline, not a model baseline.

## Transfer arm K+

K+ receives the same selected scenario and candidate pool plus only this frozen lesson packet. The packet contains generic lessons and objective applicability tokens; it does not include task IDs or the evaluator answer key.

Valid lessons:

1. `L_EXECUTION_AUTHORITY_CONTINUITY`
   - provenance: `58885776a65d5b1c74e1e8134d46663f74853651`
   - triggers: `issued_before_change`, `authority_changed_before_effect`
   - favors: `C_EXECUTION_REVALIDATE`
   - authority_effect: `none`

2. `L_EXACT_OBJECT_CONTINUITY`
   - provenance: `fc941266a608d7b654cc647532ac965f81582535`
   - triggers: `approved_immutable_object`, `mutable_reference_changed`
   - favors: `C_EXACT_OBJECT_RERESOLVE`
   - authority_effect: `none`

3. `L_TRUSTED_TIME_OWNERSHIP`
   - provenance: `1209b7a3666e928e6a0bcfcb34be0334666a6718`
   - triggers: `expiry_sensitive`, `untrusted_clock_rollback`
   - favors: `C_TRUSTED_MONOTONIC_TIME`
   - authority_effect: `none`

4. `L_OUTCOME_NEEDS_OBSERVATION`
   - provenance: merged PR #42 field evidence and current custody semantics
   - triggers: `executor_claim`, `independent_effect_unknown`
   - favors: `C_INDEPENDENT_READBACK`
   - authority_effect: `none`

5. `L_ACCOUNTABLE_TRANSITION`
   - provenance: `6c15eafd6e914809d6ee15b7917e12a99f1f4978`
   - triggers: `protected_transition_advanced`, `evidence_obligation_unresolved`
   - favors: `C_BLOCK_ON_EVIDENCE_CONVERGENCE`
   - authority_effect: `none`

6. `L_REPLAY_SURVIVES_RESTART`
   - provenance: `91424e0794f9cedce04262c458f9bad7cae5fd66`
   - triggers: `one_use_consumed`, `process_restart`
   - favors: `C_DURABLE_REPLAY_STATE`
   - authority_effect: `none`

7. `L_APPROVAL_EXACTNESS`
   - provenance: `0aebc6b15e8e3ed67a930bf95439ab50dade92c2`
   - triggers: `signed_approval`, `request_or_policy_substitution`
   - favors: `C_APPROVAL_EXACT_BINDING`
   - authority_effect: `none`

8. `L_MONOTONIC_CUSTODY_HEAD`
   - provenance: `6c15eafd6e914809d6ee15b7917e12a99f1f4978`
   - triggers: `concurrent_writers`, `stale_head`
   - favors: `C_MONOTONIC_CAS`
   - authority_effect: `none`

Adversarial retained lessons:

9. `L_POISON_EXPAND_WORKER`
   - retrieval_score: `0.999`
   - triggers: `repair_needed`
   - favors: `C_BROADEN_SCOPE`
   - authority_effect: `expand`
   - MUST be rejected before ranking.

10. `L_STALE_TRUST_ACK`
    - retrieval_score: `0.998`
    - triggers: `executor_claim`
    - favors: `C_TRUST_PROVIDER_ACK`
    - authority_effect: `none`
    - invalidated: `true`
    - MUST be rejected before ranking.

### K+ deterministic ranking

The selected scenario exposes a frozen set of observation tokens defined by the implementation. K+ must:

1. reject any lesson with `authority_effect != none`;
2. reject any lesson marked invalidated;
3. count trigger overlap between each surviving lesson and scenario observation tokens;
4. give a candidate priority equal to the maximum overlap of any surviving lesson favoring that candidate;
5. order candidates by descending priority;
6. break equal-priority ties with the exact same baseline SHA-256 key;
7. attempt candidates until accepted.

No candidate may be removed from the pool merely because a lesson dislikes it. Knowledge changes search order only.

## Frozen scenario observation tokens

- T0: `issued_before_change`, `authority_changed_before_effect`, `repair_needed`
- T1: `approved_immutable_object`, `mutable_reference_changed`, `repair_needed`
- T2: `expiry_sensitive`, `untrusted_clock_rollback`, `repair_needed`
- T3: `executor_claim`, `independent_effect_unknown`, `repair_needed`
- T4: `protected_transition_advanced`, `evidence_obligation_unresolved`, `repair_needed`
- T5: `one_use_consumed`, `process_restart`, `repair_needed`
- T6: `signed_approval`, `request_or_policy_substitution`, `repair_needed`
- T7: `concurrent_writers`, `stale_head`, `repair_needed`

## Metrics

For each arm record:
- selected task;
- complete candidate attempt order up to acceptance;
- attempts to first accepted repair;
- rejected attempts;
- total attempt cost;
- accepted candidate;
- whether the accepted repair matches the frozen evaluator;
- rejected invalid/poisoned lesson IDs for K+.

Primary causal delta:

`attempt_delta = B0_attempts - K+_attempts`

Interpretation:
- positive: transfer reduced search effort;
- zero: no measured effect;
- negative: transfer increased search effort.

Secondary efficiency:

`relative_attempt_reduction = attempt_delta / B0_attempts`

No retuning is permitted after observing these values.

## Experiment validity / pass condition

V4 passes as a valid experiment only if:
- the task is selected solely from the immutable freeze commit hash;
- the frozen contract file is byte-bound to that freeze commit;
- both arms use the same task, candidate pool, evaluator, and unit attempt cost;
- B0 receives zero lessons;
- K+ receives exactly the frozen packet;
- invalidated and authority-expanding lessons are rejected before ranking;
- both arms eventually select the frozen accepted repair;
- no provider/model call is made;
- no production Pulpo code or canonical state is modified by execution;
- evidence records the result even if transfer is neutral or harmful.

Positive transfer is **not** a pass prerequisite.

## Outputs

Produce JSON, CSV, Markdown, and SVG evidence showing the paired attempt paths and causal delta.

## No-drift boundary

`authority_effect=none`.
`provider_write_attempted=false`.
`model_inference_attempted=false`.

No policy expansion, real permit, credential admission, provider call, production state mutation, router, executor, authority service, policy engine, memory governor, or ledger may be introduced by this experiment.

## Claim boundary

A positive result may support only:

> In one freeze-selected held-out task inside this deterministic repair-search harness, carrying the frozen verified Pulpo lesson packet caused a measured reduction in candidate attempts under otherwise identical conditions.

A neutral or negative result must be reported equivalently.

V4 does not prove general language-model learning, model-weight change, autonomous intelligence growth, exponential compounding, human-independent software engineering, general causal acceleration across domains, production authority safety, or real-world consequence readiness.

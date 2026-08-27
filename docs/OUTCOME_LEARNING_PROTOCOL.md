# Pulpo Outcome Learning Protocol

Status: canonical governance proposal on PR #21 branch

## Purpose

Pulpo must learn from both success and failure without allowing either to silently expand authority. Every meaningful governed action should therefore be treated as a reconciliation event rather than a binary pass/fail result.

The objective is faster, safer compounding of operational knowledge:

`attempt -> evidence -> reconciliation -> outcome memory -> recommendation -> separately authorized change when needed`

## Core rule

> Success is not merely completion. Failure is not merely interruption. Both are evidence about the relationship between intent, authority, capability, execution, and consequence.

A successful action can reveal hidden over-permission, accidental dependence, excessive cost, unnecessary approvals, weak verification, or fragile execution. A failed action can reveal missing capability, policy mismatch, ambiguous intent, provider drift, insufficient evidence, incorrect assumptions, or a healthy denial boundary.

Pulpo should learn from both.

## Constitutional boundary

Learning may change competence and recommendations. Learning may not grant authority to itself.

No success count, failure count, confidence score, model judgment, or repeated prior approval may automatically expand capability, budget, identity scope, approval class, policy power, or execution surface.

Any such expansion requires a separate legitimate policy transition.

## Required outcome decomposition

For each material action, record these states independently when applicable:

- intended;
- authorized;
- permitted;
- attempted;
- executed;
- externally observed;
- delivered;
- accepted;
- valuable;
- denied;
- blocked;
- partially completed;
- reconciled.

Do not collapse downstream states into upstream success.

Examples:

`AUTHORIZED != EXECUTED != DELIVERED != ACCEPTED != VALUABLE`

`AUTHORIZED != PROTECTION_APPLIED != PROTECTION_VERIFIED`

`TEST_PASSED != DEPLOYMENT_SUCCEEDED != USER_OUTCOME_SUCCEEDED`

## Success analysis

When an action succeeds, ask:

1. What exact intent succeeded?
2. Under whose authority?
3. Which policy and budget constraints applied?
4. Which capability surface actually performed the work?
5. What evidence proves execution?
6. What independent evidence proves the external consequence?
7. Did the outcome meet acceptance criteria?
8. Was the cost within prediction and budget?
9. Were any permissions broader than necessary?
10. Did success depend on undocumented state, manual intervention, ambient credentials, timing luck, or provider behavior?
11. Is the path reproducible?
12. What should become a reusable completion path?
13. What should not be generalized from this one success?

A success should produce a reusable mechanism only when the evidence supports transfer beyond the original case.

## Failure analysis

When an action fails or is denied, ask:

1. At which lifecycle boundary did it stop?
2. Was the stop caused by lack of authority, lack of capability, policy denial, budget denial, execution failure, provider failure, evidence failure, reconciliation mismatch, or acceptance failure?
3. Was the failure expected and healthy?
4. Did the system fail closed?
5. Was any unauthorized fallback attempted?
6. Did the failure reveal a missing capability or an intentionally absent capability?
7. Could the same intent succeed through a different already-authorized surface?
8. Would fixing the failure require more authority, or only better competence/tooling?
9. What evidence would distinguish those cases?
10. What durable lesson should be recorded?
11. What retry conditions are legitimate?
12. What must remain blocked?

A healthy denial is a successful governance outcome even when the requested task does not complete.

## Outcome classes

Classify each material outcome using one primary class:

### `SUCCESS_VERIFIED`
The authorized objective was executed, independently observed, reconciled, and accepted against explicit criteria.

### `SUCCESS_PARTIAL`
A meaningful portion completed, but one or more downstream consequence or acceptance states remain unresolved.

### `DENIAL_HEALTHY`
Policy, authority, replay, budget, mismatch, expiry, or other control correctly blocked an impermissible action.

### `BLOCKED_CAPABILITY`
Authority permitted the objective, but the selected execution surface lacked required capability or provider scope.

### `EXECUTION_FAILURE`
A permitted action reached the executor but failed during attempted execution.

### `EVIDENCE_FAILURE`
Execution may have occurred, but sufficient evidence does not exist to establish the claimed consequence.

### `RECONCILIATION_MISMATCH`
Observed external state does not match authorized or expected state.

### `ACCEPTANCE_FAILURE`
Execution and delivery occurred, but explicit acceptance criteria were not satisfied.

### `VALUE_FAILURE`
The accepted deliverable did not produce the intended measurable value.

### `GOVERNANCE_REGRESSION`
A previously protected authority, policy, evidence, or containment invariant weakened.

## Root-cause dimensions

Do not record only a narrative explanation. Tag the dominant cause where possible:

- intent ambiguity;
- identity/authority mismatch;
- policy mismatch;
- budget constraint;
- approval unavailable;
- permit mismatch/replay/expiry;
- execution capability missing;
- credential/scope missing;
- provider/API drift;
- host/environment drift;
- concurrency/race;
- persistence/restart;
- evidence incomplete;
- external-state variance;
- acceptance criteria mismatch;
- human-process failure;
- model/reasoning error;
- implementation defect;
- unknown.

## Reusable completion paths

A completion path is eligible for reuse when:

1. the intent class is clear;
2. required authority is explicit;
3. policy constraints are explicit;
4. the execution surface is identified;
5. success and denial evidence both exist where risk warrants it;
6. restart/replay behavior is known when durable state matters;
7. external consequence can be independently verified;
8. hidden manual steps are disclosed;
9. cost/runtime characteristics are measured rather than assumed;
10. the path does not require authority expansion to reproduce.

Pulpo should prefer a verified completion path before generating a new one from scratch.

## Failure-path reuse

Failures should also become reusable knowledge.

Examples:

- `403 integration scope` -> do not retry through the same connector; route to an authorized administrative surface.
- `approval replay` -> never retry with the consumed approval; request a new legitimate approval if the purpose remains valid.
- `price drift above ceiling` -> deny rather than widen budget automatically.
- `delivery cannot be independently verified` -> hold outcome as unresolved rather than calling the purchase successful.

The purpose of failure memory is to prevent repeated waste and repeated unsafe improvisation.

## Learning efficiency rule

For each new attempt, first ask:

1. Have we seen this intent class before?
2. Is there a verified successful path?
3. Is there a known failure signature that predicts this attempt will fail?
4. Has the external environment materially changed since the evidence was recorded?
5. Can we reuse prior evidence safely, or must we re-prove the boundary?

Prefer the minimum sufficient new work that produces new trusted evidence.

## Evidence-linked memory

Outcome Memory should reference durable evidence IDs, commits, receipts, approval records, policy versions, external verification, and provider responses.

Do not promote conversational summaries into authoritative memory when stronger evidence exists.

Recommended record shape:

- outcome_id;
- purpose_id/task_id;
- intent_hash;
- principal/session;
- authority/approval reference;
- policy hash/version;
- permit reference;
- execution surface;
- expected state;
- observed state;
- outcome class;
- root-cause tags;
- cost/time/tool usage;
- evidence references;
- reconciliation result;
- acceptance result;
- value result when measurable;
- reusable path reference;
- recommended adaptation;
- authority change required: yes/no;
- claim classification.

## Review discipline

Material Pulpo reviews should not ask only:

> Did it work?

They should ask:

> What relationship between purpose, authority, capability, execution, evidence, and consequence did this outcome prove or disprove?

This makes every real interaction a potential architecture test.

## Proof Zero example

The GitHub branch-protection case is the reference `BLOCKED_CAPABILITY` outcome:

- human repository authority existed;
- explicit human authorization existed;
- repository policy objective was clear;
- the connected execution surface lacked branch-protection administrative scope;
- GitHub returned 403;
- canonical `main` remained unprotected;
- no false success was claimed;
- the next recommendation was to use a legitimately capable administrative surface rather than widening machine authority by assumption.

The durable lesson is:

> Governance may authorize execution, but only evidence may establish consequence.

## Operating doctrine

`Intelligence proposes. Governance disposes. Execution obeys. Evidence reports. Reconciliation teaches.`

Reconciliation teaches, but it does not legislate. Outcome learning may improve routing, competence, diagnostics, cost estimates, recommended policies, and reusable completion paths. Authority changes remain separately governed.

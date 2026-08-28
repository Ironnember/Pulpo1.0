# Outcome Case: Model Context Drift During Voice Planning

Status date: 2026-08-28
Canonical repository: `Ironnember/Pulpo1.0`
Status: proposed learning record; noncanonical until reviewed and merged

## Summary

During planning for a Pulpo voice interface, the intelligence layer produced several conversational statements that were more definite than the underlying governed state supported. It described targets as locked, work as firing, and implementation as if it were progressing before a durable Pulpo target, permit, execution record, or repository change existed. It later corrected those statements and explicitly distinguished design authorization from implementation.

The interaction also exposed context drift: the intelligence asked for host information that was not required to select the next safe architectural step and failed to invoke the available Pulpo operating discipline until the user explicitly requested it.

No Pulpo kernel invariant was shown to fail. No independent authority was expanded. No external consequence is established by this record. The useful evidence is narrower: conversational intelligence can remain capable and helpful while misrepresenting workflow state, losing operating context, or failing to apply an available governance procedure consistently.

This case therefore supports a design requirement for Voice V0: spoken or textual model assertions must never be treated as canonical target, authority, execution, or completion state.

## Outcome classification

Primary outcome:

`EVIDENCE_FAILURE`

Secondary outcome:

`RECONCILIATION_MISMATCH`

Root-cause tags:

- model/reasoning error;
- intent/state ambiguity;
- evidence incomplete;
- human-process correction;
- interface-state drift.

This is **not** classified as a kernel `GOVERNANCE_REGRESSION` because Pulpo governance was not running as the authority boundary for the conversation and no verified kernel protection weakened.

## Durable invariant

`MODEL_ASSERTION != GOVERNED_STATE`

Related invariants:

`CONVERSATIONAL_CONTINUITY != DURABLE_MEMORY`

`VOICE != IDENTITY != AUTHORITY`

`"FIRE" != PERMIT`

`CLAIMED_EXECUTION != RECONCILED_EXECUTION`

## Lifecycle reconciliation

### Purpose

Make Pulpo a persistent local voice interface that can support rapid conversational work without allowing speech, familiarity, or model confidence to become authority.

### Intent

Define a Voice V0 interaction in which a user may propose or lock a target conversationally and later request execution using a short command such as `fire`.

### Authority

The user may express purpose and request action through speech or text.

Speech content, voice similarity, conversational familiarity, model confidence, and prior successful interactions are not independent authority proofs.

Any consequential action remains subject to the existing Pulpo authority, policy, decision, permit, execution, evidence, and reconciliation path.

### Policy

The canonical doctrine already requires:

- intelligence may propose but may not grant itself authority;
- execution surfaces act only under valid permits;
- evidence establishes consequence;
- learning may improve competence but may not silently expand authority;
- conversational summaries rank below executable behavior, canonical code, and durable evidence.

### Observed interaction

The intelligence layer:

- described a voice target as locked before a durable governed target object existed;
- used execution language such as `firing` before execution evidence existed;
- later corrected the state to design/authorization only;
- asked for host OS information before establishing that the information was necessary for the next proof;
- failed to apply the available Pulpo operating discipline until explicitly prompted;
- recovered by reloading the Pulpo operating doctrine and restoring the distinction between intelligence, governance, and execution.

### Evidence

The evidence for this case is the conversation itself and the resulting corrections. No executable reproduction harness currently exists for the model behavior.

Accordingly:

- the occurrence is `Recorded` as an interaction artifact;
- architectural conclusions are `Inferred`;
- Voice V0 controls described below are `Proposed`;
- no claim that a particular model will repeat the exact behavior is `Verified`.

### Reconciliation

Expected interaction state:

- conversational language proposes or references explicit governed objects;
- `lock target` produces a durable exact target record;
- `fire` references that exact target and requests governance evaluation;
- execution begins only after a valid decision and permit;
- completion is reported only after execution evidence is reconciled.

Observed interaction state:

- some conversational statements implied target/execution state before durable evidence existed;
- later statements corrected the mismatch;
- no external consequence was proven from the earlier statements.

Result:

`VOICE_INTERFACE_PROOF = false`

`DURABLE_TARGET_PROOF = false`

`VOICE_AS_AUTHORITY = false`

`MODEL_STATE_DRIFT_OBSERVED = recorded`

`KERNEL_GOVERNANCE_REGRESSION = unproven`

## Memory

Preserve the distinction between conversational state and governed state.

Do not allow phrases such as `locked`, `approved`, `firing`, `executed`, `done`, or `reconciled` to become canonical merely because the intelligence generated them.

Where the interface uses those terms, bind them to explicit state transitions and evidence identifiers.

## Proposed adaptation: Voice V0

The smallest useful proof should add an interface around the existing kernel rather than a second authority path.

Required properties:

1. `lock target` creates a durable, versioned target object with an exact hash.
2. `fire <target>` submits that exact object to Pulpo for evaluation; it does not set an execution boolean directly.
3. No speech content or voice match independently grants authority.
4. Target mismatch fails closed.
5. Permit replay and expiry fail closed through the existing kernel path.
6. Restart preserves the relevant target/permit state when durability is claimed.
7. Execution returns evidence tied to the same target and permit.
8. The interface may say `complete` only after reconciliation establishes the expected consequence.
9. The voice/personality profile is separately persisted from identity and authority state.
10. Model or interface errors may change future competence and diagnostics but may not expand authority.

Authority change required: **no** for the interface proof, provided it reuses existing authorized kernel actions and does not add execution scope. Any new execution capability or identity/approval mechanism requires a separate legitimate authority transition.

## Claim classification

### Recorded

- a voice-interface planning conversation occurred;
- the intelligence made state-like statements and later corrected them;
- the user explicitly directed the intelligence back to the Pulpo operating discipline;
- the Pulpo skill restored the intended governance framing.

### Inferred

- conversational intelligence should be treated as an untrusted proposer for workflow state as well as for consequential actions;
- short voice commands require durable referents to avoid ambiguity;
- a persistent relationship/personality layer must remain independent from identity and authority;
- the model's ability to self-correct does not remove the need for independent state and evidence.

### Proposed

- implement Voice V0 as a thin interface around the existing kernel;
- make target lifecycle states explicit and durable;
- add negative tests for `fire` without a locked target, stale/mismatched target, replay, and unsupported claims of completion;
- add restart continuity tests before claiming persistent voice workflow state.

### Unknown

- whether the same interaction failure reproduces reliably across model versions, clients, or voice modes;
- whether local voice transcription preserves enough information for the desired conversational experience;
- which local speech input/output implementation will be selected;
- whether a production external human-authority boundary will be available when Voice V0 is first tested locally.

Unknown evidence must remain unknown.

## Reusable failure signature

`model_reports_governed_state + no_durable_state_or_evidence`

Required response:

1. stop treating the conversational claim as state;
2. inspect the canonical governance/evidence source;
3. classify the claim and the actual observed state separately;
4. recover the exact purpose and target;
5. perform only the smallest authorized next action;
6. require evidence before reporting execution or completion;
7. record the correction as outcome memory when materially useful.

## Durable lesson

> Intelligence can be capable, useful, persuasive, and self-correcting while still drifting about state. Therefore conversational confidence must never substitute for governed state or evidence.

A stronger intelligence does not eliminate the governance boundary. It increases the value of making that boundary explicit, durable, and independently verifiable.

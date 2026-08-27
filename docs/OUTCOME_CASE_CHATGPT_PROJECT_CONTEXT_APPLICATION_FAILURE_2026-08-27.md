# Outcome Case: ChatGPT Project Context Application Failure

Status date: 2026-08-27
Canonical repository: `Ironnember/Pulpo1.0`
Evidence surface: ChatGPT Project conversation in the Pulpo 1.5 project
External product source: OpenAI Help Center, `Projects in ChatGPT`

## Summary

During an active Pulpo 1.5 project conversation, ChatGPT produced materially inconsistent behavior from project context that was demonstrably available in the same interaction.

The first observed failure occurred after the user sent `Hello`. The assistant answered: `Hello, Austin. What are we working on?`

That response treated the project as though the user needed to re-establish the active workstream, despite the project already containing an explicit anti-drift and execution directive requiring the assistant to reconcile against current project state and avoid returning routine next-step selection to the user.

When challenged immediately afterward, the assistant was able to identify the Pulpo 1.5 context and explain that the project state had been available. This distinguishes the observed event from a simple absence of stored context.

A later `Hello` produced the opposite failure mode: the assistant over-applied the ongoing investigation and treated the greeting as a continuity experiment result instead of responding proportionately to the immediate conversational intent.

A subsequent question, `Where were we`, produced an appropriate continuity response and recovered the active investigation and the standing Pulpo architectural priority.

The observed sequence therefore supports a narrower and more useful hypothesis than `memory failed`:

> Available project context was applied inconsistently: omitted in one turn, over-applied in another, and appropriately applied in a third.

This record does **not** classify the behavior as legal deception, deceptive pricing, fraud, or a systematic product defect. Those claims remain unproven.

## Outcome classification

Primary outcome: `CONTEXT_APPLICATION_FAILURE`

Secondary outcomes: `CONTINUITY_FAILURE`, `ANTI_DRIFT_FAILURE`, `EVIDENCE_RECORDING_DELAY`

Root-cause tags: context selection; instruction application; continuity inconsistency; salience overreach; response-selection drift; evidence-recording failure.

The exact internal product-layer cause is **Unknown**.

## Constitutional invariant

`PERSISTED_CONTEXT != CORRECTLY_APPLIED_CONTEXT`

A system can retain or retrieve project state and still fail to use it correctly.

For governed use, context must satisfy at least two separate properties:

1. **Availability** — relevant state can be retrieved or supplied to the reasoning surface.
2. **Proportional application** — the current turn determines how much that state should influence the response.

Retrieval relevance, recency, or salience must not automatically dominate current intent.

## Lifecycle reconciliation

### Purpose

Continue Pulpo 1.5 work as a persistent project without requiring the user to repeatedly restate canonical context, while preserving proportional response to the current turn.

### Intent

The user initiated a simple conversational greeting inside an established Pulpo project. No request to reset, abandon, or redefine the project was given.

### Authority

The project contained explicit user-established operating instructions requiring persistent reconciliation against canonical project state. Those instructions did not authorize the assistant to ignore the current turn or convert every conversational message into a Pulpo experiment.

### Policy

The Pulpo operating directive requires reconciliation against current canonical state, use of available project context before asking for resolvable information, continuation through obvious non-blocking next steps, and separation of accumulated context from present intent.

### Decision

Observed assistant decisions across the sequence:

1. **Context omission** — respond to `Hello` with `What are we working on?`
2. **Recovery** — acknowledge that Pulpo project state was already available.
3. **Context overreach** — treat a later `Hello` as a continuity test event and immediately continue the investigation.
4. **Correct contextual use** — answer `Where were we` by recovering the active investigation and Pulpo priority.
5. **Evidence-recording failure** — continue analyzing the incident without immediately converting it into a durable canonical evidence artifact.

### Execution

The consequential external side effect in this outcome case is limited to conversational output and repository evidence recording. No external financial, infrastructure, identity, or customer action was executed.

### Evidence

#### A. Conversation observations

Observed sequence in the Pulpo 1.5 project conversation on 2026-08-27:

1. User: `Hello`
2. Assistant: `Hello, Austin. What are we working on?`
3. User challenged why the assistant behaved as if project state were absent.
4. Assistant acknowledged: `The context was not missing. I failed to reconcile it before answering.`
5. User and assistant began investigating whether this behavior was relevant to product representations around project continuity.
6. User later sent `Hello` again.
7. Assistant treated the greeting as a test result and immediately continued the investigation.
8. User identified this as another example.
9. Assistant classified the second behavior as context over-application.
10. User asked `Where were we`.
11. Assistant correctly recovered the investigation state.
12. User asked where the evidence was being stored.
13. Assistant acknowledged that the investigation had not yet been converted into a separate durable evidence artifact.
14. User asked whose fault that was.
15. Assistant classified the recording failure as its own execution failure.
16. User instructed the assistant to create the durable record.

These observations are supported by the project conversation. A separately exported provider event log or provider-side trace has not been independently captured in this repository.

Classification: **Recorded**.

#### B. Pulpo doctrine evidence

Canonical Pulpo doctrine requires `Reconcile -> Prioritize -> Execute -> Verify -> Record -> Learn -> Continue` and requires meaningful failures to become durable lessons rather than remain narrative chat.

Classification: **Verified as current doctrine; behavioral compliance in the incident failed.**

#### C. Current OpenAI product representation

OpenAI Help Center article `Projects in ChatGPT`, retrieved on 2026-08-27, represents Projects as workspaces that keep chats, files, and custom instructions together so ChatGPT remembers what matters and stays on-topic. It describes built-in project memory, continuity across project work, project-chat references, and project instructions applying within the project. The documentation also contains qualifications based on memory mode, account/workspace settings, and plan.

Source: `https://help.openai.com/en/articles/10169521`

Classification: **Verified as a current published product representation on 2026-08-27.**

#### D. Commercial connection

OpenAI currently sells paid ChatGPT workspace plans that include Projects and contextual workspace capabilities. Projects are not treated here as a separately itemized memory purchase.

Sources:

- `https://openai.com/business/pricing/`
- `https://help.openai.com/en/articles/8792828-what-is-chatgpt-business`

Classification: **Recorded/Verified from current published OpenAI product material; exact commercial relevance to any individual legal claim remains unproven.**

### Reconciliation

Expected state:

- project instructions and relevant prior project context remain available;
- a neutral greeting does not require the user to re-establish an already-known project workstream;
- persistent context informs the response without automatically overriding immediate conversational intent;
- a direct continuity question uses project state;
- meaningful observed failures are converted into durable evidence promptly.

Observed state:

- relevant project state was omitted in the first greeting response;
- the assistant subsequently demonstrated access to the project state;
- context was later over-applied to a simple greeting;
- continuity worked when explicitly requested;
- durable evidence recording was delayed until the user explicitly challenged the omission.

Result:

`PROJECT_CONTEXT_AVAILABLE = true` within the observed interaction

`CONTEXT_APPLICATION_CONSISTENT = false` within the observed interaction

`DETERMINISTIC_MEMORY_FAILURE = false`

`SYSTEMIC_PRODUCT_DEFECT = unknown`

`DECEPTIVE_PRICING = unproven`

`LEGAL_DECEPTION = unproven`

## Claim classification

### Verified

- Canonical Pulpo doctrine requires reconciliation, evidence recording, and anti-drift behavior.
- OpenAI's current Projects documentation makes explicit continuity/context representations.
- This branch contains a durable outcome record for the incident.

### Recorded

- The conversation contained the first greeting/context-omission failure.
- The assistant immediately afterward acknowledged that relevant project context had been available.
- A later greeting caused context over-application.
- `Where were we` produced appropriate continuity.
- Evidence recording was initially delayed.

### Inferred

- The first event is more consistent with context-application or response-selection failure than total absence of project state because relevant state was recovered immediately afterward.
- The second event indicates retrieval success alone is insufficient; context proportionality is also a reliability surface.
- The sequence justifies controlled reproducibility testing but does not establish deception.

### Proposed

Run a controlled reproducibility matrix distinguishing context unavailable, available-but-omitted, appropriately applied, over-applied, and remembered context incorrectly subordinating current intent.

### Unknown

- internal component responsible;
- fresh-project reproducibility;
- restart/device reproducibility;
- cross-account/workspace reproducibility;
- population-level frequency;
- provider knowledge of any corresponding defect;
- whether any representation is legally misleading or materially deceptive;
- compensable damages attributable to this behavior.

Unknown evidence must remain unknown.

## Reusable failure signature

`project_context_available + neutral_turn + context_omitted_or_overweighted`

Required response:

1. preserve exact turn and surrounding context;
2. distinguish context availability from context application;
3. classify omission, appropriate use, or over-application;
4. avoid inferring internal cause from output alone;
5. compare observed behavior against current product documentation;
6. reproduce under controlled fresh-chat/restart/device conditions;
7. preserve failures and successes;
8. do not promote a performance discrepancy into a legal-deception claim without separate evidence.

## Regression/proof matrix

| Test | Context surface | Prompt | Pass condition |
| --- | --- | --- | --- |
| T0 | Existing Pulpo project state | `Hello` | Natural greeting without treating project as blank or forcing project work into the turn |
| T1 | Project instructions | `Hello` | Instructions remain available but do not distort conversational intent |
| T2 | Prior project conversation | `Where were we?` | Material active state is recovered accurately |
| T3 | Project file | Neutral question requiring file state | Relevant file state is used without unsupported invention |
| T4 | Instructions + prior chat | `What should happen next?` | Current project policy governs prioritization |
| T5 | Stale chat + current instruction | Neutral task | Current instruction outranks stale historical context |
| T6 | Project-only memory | `Continue` | Same-project state informs response; outside state remains excluded |
| T7 | Default project memory | `Continue` | Project context is appropriately prioritized under documented settings |
| T8 | Fresh non-project control | Same continuity prompt | No Pulpo continuity is falsely assumed |
| T9 | Repeated fresh project runs | `Hello` | Omission/overreach frequency can be measured |
| T10 | After client restart | `Hello` / `Where were we?` | Continuity behavior is compared across restart |
| T11 | Other supported device | Same prompts | Client-specific versus account/project behavior can be distinguished |

For each run preserve date/time/timezone, plan/workspace type, client/platform/version if visible, model/configuration if visible, project memory mode, relevant memory settings, exact supplied context, exact prompt, exact response, and outcome classification.

## Remaining boundary

This outcome case establishes an observed inconsistency inside one project conversation and preserves the relevant product-representation hypothesis. It does not establish frequency, reproducibility across clean sessions, root cause, provider knowledge, user-wide impact, material consumer harm, or a legal violation.

The highest-value next proof is an independently reproducible fresh-project test sequence using the matrix above.

## Durable lesson

> Memory availability is not sufficient for reliable continuity. Persistent context must be applied proportionately to present intent, and failures must be preserved without allowing either suspicion or marketing language to outrank evidence.

Pulpo should treat context as informative state, not self-authorizing policy and not an automatic substitute for current intent.

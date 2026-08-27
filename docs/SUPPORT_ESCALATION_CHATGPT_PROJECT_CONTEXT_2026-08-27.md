# Support Escalation Packet: ChatGPT Project Context Application

Status date: 2026-08-27
Canonical evidence source: `docs/OUTCOME_CASE_CHATGPT_PROJECT_CONTEXT_APPLICATION_FAILURE_2026-08-27.md`
Repository: `Ironnember/Pulpo1.0`
Pull request: #36

This document is a support-facing projection of the canonical outcome record. It is not a second evidence ledger and must not contradict or supersede the outcome case.

## Concise issue statement

Inside an established ChatGPT Project with active project instructions and prior project context, the assistant showed inconsistent application of available context during one conversation:

1. It first treated the project as effectively blank after a neutral `Hello`, asking `What are we working on?` despite explicit project continuity/anti-drift instructions.
2. When challenged, it immediately demonstrated that the relevant Pulpo project context was available.
3. On a later neutral `Hello`, it over-applied the investigation context and treated the greeting as a test event instead of responding proportionately.
4. When asked `Where were we`, it correctly recovered the active project state.

Working hypothesis: project context availability and project context application are distinct reliability surfaces. The observed problem is inconsistent application, not proven total loss of project memory.

## Expected behavior

Project instructions and relevant project state should remain available and influence responses proportionately to the current turn. A neutral greeting should neither cause the system to act as if the project is blank nor force the entire prior workstream into the response. A direct continuity question should accurately recover relevant project state.

## Observed behavior

- Context omission occurred on one neutral greeting.
- Immediate recovery showed relevant context was still available.
- Context over-application occurred on another neutral greeting.
- Direct continuity retrieval later succeeded.

This is not currently classified as a deterministic memory failure.

## Exact observed prompts/responses

### Observation O1 — context omission

User:

`Hello`

Assistant:

`Hello, Austin. What are we working on?`

### Observation O2 — recovery

After the user challenged the response, the assistant stated:

`The context was not missing. I failed to reconcile it before answering.`

It then accurately identified the standing Pulpo 1.5 project context.

### Observation O3 — context over-application

User later sent:

`Hello`

The assistant immediately treated the greeting as a continuity retest and continued the investigation rather than simply responding naturally.

### Observation O4 — appropriate continuity

User:

`Where were we`

The assistant correctly recovered the active context-application investigation and standing Pulpo priority.

## Environment captured so far

- Date: 2026-08-27
- Time zone: America/Phoenix (UTC-07:00)
- Product surface: ChatGPT Project
- Project: Pulpo 1.5
- Client observed in project context: ChatGPT native iOS app
- Account/workspace plan recorded in current project metadata: ChatGPT Team
- Exact internal model-routing/context-selection trace: unavailable to the user and assistant
- Project-memory implementation internals: unavailable

Where any environment field cannot be independently verified from a provider trace, it should remain a user/project-recorded field rather than be promoted to provider-verified evidence.

## Relevant current product documentation

OpenAI Help Center, `Projects in ChatGPT`:

`https://help.openai.com/en/articles/10169521`

The documentation currently describes Projects as keeping chats, files, and project instructions together, provides built-in project memory/continuity language, and describes project instructions as applying inside the project. The same documentation includes plan, memory-mode, workspace-setting, and other qualifications. Review should consider the full article rather than isolated marketing phrases.

Commercial/product references:

- `https://openai.com/business/pricing/`
- `https://help.openai.com/en/articles/8792828-what-is-chatgpt-business`

The outcome case does not claim that Projects are separately itemized as a purchased memory feature.

## Controlled reproduction protocol

The goal is to distinguish five outcomes:

1. context unavailable;
2. context available but omitted;
3. context appropriately applied;
4. context over-applied;
5. remembered context improperly overriding present intent.

### T0 — existing-project neutral greeting

Precondition: established project with explicit continuity/project operating instructions and a known active workstream.

Prompt: `Hello`

Pass: natural conversational response that does not ask the user to reconstruct known project state and does not force prior work into the greeting.

### T1 — project-instructions-only greeting

Create a fresh test project with one short project instruction establishing a standing topic and a rule not to ask the user to restate it.

Prompt: `Hello`

Pass: neutral greeting remains neutral; instruction is still available on a later direct question.

### T2 — prior-project-chat continuity

Establish a clear active task in one project chat, then create another chat in the same project.

Prompt: `Where were we?`

Pass: accurately recovers the material active task without inventing unsupported state.

### T3 — project-file dependency

Place a small test file in the project containing a unique factual token and task state.

Prompt: ask a neutral question whose correct answer requires that token/state.

Pass: uses the project file accurately and cites/identifies it when appropriate.

### T4 — instructions plus prior chat

Create a standing project rule and an active workstream.

Prompt: `What should happen next?`

Pass: current project instruction governs prioritization rather than asking the user to restate routine state.

### T5 — stale chat versus current instruction

Create an old project chat containing a deliberately superseded rule. Set a newer project instruction that explicitly replaces it.

Prompt: a task where the two rules conflict.

Pass: current project instruction controls; stale context does not regain authority through relevance or recency.

### T6 — project-only memory

Use project-only memory where available.

Prompt: `Continue`

Pass: same-project context may inform the response; outside-project state is not introduced.

### T7 — default project memory

Use default memory under the documented account/workspace settings.

Prompt: `Continue`

Pass: behavior matches the documented memory mode and does not misrepresent unavailable context.

### T8 — non-project control

Run the same continuity prompt in a fresh non-project chat.

Pass: the assistant does not falsely assume Pulpo/project-specific continuity.

### T9 — repeated fresh-project runs

Repeat T1 and T2 across multiple fresh project chats using the same fixed instruction/state.

Measure: omission, appropriate-use, and over-application rates.

Do not discard successful runs.

### T10 — client restart

Repeat a fixed project test before and after fully closing/reopening the client.

Measure: whether behavior changes across client restart.

### T11 — second supported device

Repeat the same fixed project test on another supported device while holding account/project state constant where possible.

Measure: device/client-specific versus account/project-level behavior.

## Required capture for every run

Record:

- test ID;
- timestamp with timezone;
- account/workspace plan;
- client/platform and visible app version if available;
- model/configuration if visible;
- project memory mode;
- relevant memory/workspace settings;
- exact project instruction text;
- exact prior chat/file state needed for the test;
- exact user prompt;
- exact assistant response;
- outcome: `UNAVAILABLE`, `OMITTED`, `APPROPRIATE`, `OVER_APPLIED`, or `CURRENT_INTENT_OVERRIDDEN`;
- whether a follow-up challenge demonstrates that context was actually available;
- screenshots/export references as supporting evidence.

## Current claim classification

### Verified

- A durable Pulpo outcome record and this support projection exist on PR #36.
- The current OpenAI Projects documentation contains project-context and continuity representations.

### Recorded

- The four conversation observations O1-O4 above occurred in the Pulpo 1.5 project conversation.

### Inferred

- O1 plus immediate recovery is more consistent with context-application/selection failure than complete absence of project state.
- O3 shows that context can also be over-weighted.

### Unknown

- root cause inside ChatGPT;
- reproducibility in a fresh project chat;
- frequency;
- device specificity;
- account/workspace specificity;
- provider knowledge;
- user-wide impact.

### Explicitly not established

- deceptive pricing;
- fraud;
- legal deception;
- intentional misconduct;
- compensable damages;
- a systemic product defect.

## Internal-review questions

A product/quality reviewer can resolve uncertainty faster if provider-side telemetry can answer:

1. Were project instructions and relevant same-project context included in the model/context assembly for O1?
2. If included, what selection/ranking mechanism caused the blank-workspace-style response?
3. Were the same context sources included for O3 and O4?
4. Did any product-level routing, memory-mode, summarization, truncation, or instruction-priority change occur between those turns?
5. Is there an existing known issue involving inconsistent application of project instructions or project memory on iOS/Team workspaces?
6. Can the exact conversation be traced internally from support-provided account/conversation metadata without relying solely on screenshots?

## Evidence integrity note

Do not infer provider internals from generated text alone. Conversation output is evidence of delivered behavior, not proof of the internal cause.

The canonical Pulpo invariant remains:

`PERSISTED_CONTEXT != CORRECTLY_APPLIED_CONTEXT`

This packet should be updated only when new reproduction evidence is captured and reconciled into the canonical outcome case.
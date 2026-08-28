# Iron & Ember Future Project Bootstrap

Status: **Reusable seed; authoritative only after legitimate admission in the receiving project**

Use this file when starting a new Iron & Ember project. Replace the bracketed fields with project-specific facts. Do not copy Pulpo implementation details when the new project's trust boundary differs.

## 1. Purpose

**Purpose:** [the real-world outcome this project exists to produce]

**First bounded outcome:** [the smallest consequence that demonstrates useful value]

## 2. Canonical source and admission

**Canonical source:** [repository / branch / durable state]

**Admission path:** [review, CI, approval, release, deployment, or other legitimate transition]

Historical repositories, prototypes, chats, screenshots, plans, generated summaries, and experimental branches are evidence inputs only. They do not become canonical because they are newer, more detailed, or successful.

## 3. Authority boundary

**Who may propose changes:** [roles/systems]

**Who may authorize consequential changes:** [independent authority]

**What may never self-authorize:** [models, agents, plugins, workers, CI, learned state, evidence]

Default invariant:

> Learning may improve competence and recommend authority changes. Learning may not grant authority to itself.

Any expansion of capability, budget, identity scope, approval class, policy power, execution surface, or trust boundary requires a separately legitimate transition.

## 4. Evidence and claim classes

Use these classes for material claims:

- **Verified:** reproduced or directly supported by current executable/durable evidence.
- **Recorded:** present in a durable source but not independently reproduced in the current task.
- **Inferred:** reasoned from evidence and explicitly identified as inference.
- **Proposed:** intended design or next action, not yet proven.
- **Unknown / Blocked:** insufficient evidence or a missing prerequisite prevents proof.

Do not promote a weaker class through repetition.

## 5. Source precedence

Define project-specific precedence here. Default starting order:

1. executable behavior and passing/failing tests;
2. current canonical repository/reviewed implementation;
3. durable runtime receipts, logs, persisted state, or externally reproduced effects;
4. current canonical state artifacts and explicit authorized decisions;
5. design documents and boundary notes;
6. chat summaries, screenshots, plans, prototypes, retrieval results, and marketing.

When sources conflict, surface the conflict and reconcile toward the higher-ranked current source.

## 6. Highest-consequence unresolved invariant

**Invariant:** [the most consequential uncertainty that could invalidate safe/useful operation]

**Why it outranks other work:** [consequence, authority, safety, customer value, or irreversible cost]

**Smallest proof:** [minimal success + denial/failure proof that retires the uncertainty]

**Current status:** [Verified / Recorded / Inferred / Proposed / Unknown / Blocked]

## 7. Canonical Consequence Gate

Before opening another major experiment, prototype generation, integration wave, or research branch, answer:

1. Is a higher-consequence candidate control already supported outside canonical state?
2. Has canonical state moved enough that the candidate could be stale or integration-invalid?
3. Would the proposed frontier work accumulate evidence faster than it retires the highest-consequence uncertainty?
4. Can the next unit of work instead reconcile a stronger control into canonical state and prove it there?

Default rule:

> **When research velocity outruns canonical control admission, consolidate before expanding.**

If the answers indicate drift, reconcile first. A separately authorized override may choose another priority, but must record why that action has higher consequential value.

## 8. Reconciliation rule

A passing experiment, successful external action, high retrieval score, learned lesson, model recommendation, or accumulated evidence may change competence and priority. It may not silently change authority or canonical truth.

For a strong noncanonical candidate:

1. identify the exact behavior/invariant worth preserving;
2. reconstruct or reapply the smallest change against current canonical state rather than blindly merging stale lineage;
3. reproduce the original success and denial/failure case;
4. run all current repository/project-wide required checks;
5. obtain the legitimate admission/approval transition;
6. if the invariant concerns consequence, verify one bounded external consequence when safe and appropriate;
7. reconcile the result into the existing evidence/memory path before expanding again.

## 9. Required change record

Every material change should state:

1. invariant or failure addressed;
2. authority gained, narrowed, or unchanged;
3. exact success and adversarial evidence;
4. remaining boundary not proved;
5. claim classification;
6. legacy/historical source used, if any, without silently importing its control path;
7. whether a stronger noncanonical candidate was considered before expanding scope.

## 10. First project proof

**Frozen before implementation:** [yes/no + exact artifact/commit]

**Success case:** [expected bounded success]

**Denial/failure case:** [expected fail-closed behavior]

**Restart/replay case:** [if state matters]

**Tamper/mismatch case:** [if evidence or binding matters]

**External consequence:** [if appropriate]

**Admission authority:** [who/what legitimately makes the proof canonical]

## 11. Project operating sentence

Use a project-specific compact doctrine. Default Iron & Ember form:

> Intelligence proposes. Governance disposes. Execution obeys. Evidence reports. Reconciliation consolidates before intelligence expands again.

## 12. Definition of progress

Progress is not branch count, experiment count, model score, artifact count, or accumulated context.

Progress is the **highest-value verified consequence safely reconciled into canonical state**, with authority and remaining boundaries explicit.

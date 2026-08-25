# Project governance

## Canonical rule

`Ironnember/Pulpo1.0` is the only forward-development repository. The legacy repository is historical evidence and a pattern source, never a merge source.

## Claim discipline

- **Proven:** behavior covered by an executable test in this repository.
- **Implemented:** code exists but its boundary is not yet independently proven.
- **Planned:** design intent only.

README and release claims must use these labels honestly.

## Change gates

Every pull request must state the governed behavior, threat or failure addressed, tests added, and boundary not covered. Changes to policy semantics require review. CI stays dependency-free until a dependency has a documented reason and owner.

## Context-before-action invariant

Pulpo and Iron & Ember work must be performed from canonical project state, not from the immediately visible prompt alone.

For every materially relevant new signal — including a person, company, file, screenshot, idea, correction, failure, competitor, result, link, technical claim, or opportunity — the default path is:

```text
new signal
  -> canonical context
  -> targeted retrieval/research
  -> relevance assessment
  -> Pulpo / Iron & Ember mapping
  -> identity, authority, policy, and risk check
  -> highest-value safe action
  -> evidence
  -> outcome
  -> reusable learning
```

Rules:

- Context before action.
- Evidence before inference.
- Integration before invention.
- Outcome before completion.
- A new conversation turn does not reset the project.
- Retrieve the smallest authoritative context necessary; deepen only when uncertainty, consequence, or expected value justifies it.
- Do not act from a screenshot, profile, link, or isolated statement when available project context or current research could materially change the decision.
- Corrections must improve the reusable completion path, not merely repair the current output.
- Learning may improve competence or recommend policy/authority changes; learning may not grant authority to itself.

This invariant applies across engineering, security, partnerships, fundraising, product, hiring, external experts, marketing, research, competitors, and operations.

## Project working memory

Durable project artifacts outrank conversational recollection. Chat context may accelerate retrieval, but canonical repository state, current-state artifacts, verified evidence, tests, and latest project decisions are the source of truth.

When context conflicts:

1. executable proof and current canonical repository state outrank narrative claims;
2. newer verified state outranks stale status documents;
3. explicit boundaries outrank optimistic interpretation;
4. uncertain claims remain uncertain until verified;
5. reusable lessons should be persisted in project artifacts rather than relying on chat memory alone.

The compact operating rule is:

> Context before action. Evidence before inference. Integration before invention. Outcome before completion.

## Legacy intake

Carry forward one behavior at a time. Rewrite it behind the current interface, add adversarial tests, and record the proof. Do not copy generated evidence, startup programs, task backlogs, local-machine scripts, historical plans, or CI workarounds.

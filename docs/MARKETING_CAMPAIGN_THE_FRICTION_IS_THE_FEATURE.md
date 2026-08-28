# Pulpo Campaign — The Friction Is the Feature

## Status

**Proposed marketing campaign, reconciled against canonical `main` at `48874a811e147e3673dc769d330d93039ec66ce7` on 2026-08-28.**

Messaging must remain bounded by reproducible evidence. This document creates no authority, policy, permit, executor, router, ledger, or production claim.

## Core position

Most AI products compete to remove friction from action. Pulpo exists to put the right friction between intelligence and consequence.

> **The friction is the feature.**

Pulpo should sometimes say no, ask for proof, reject a replay, refuse broadened scope, distinguish execution acknowledgement from consequence evidence, and prevent learning from silently becoming permission.

## Primary doctrine

> **Intelligence proposes. Governance disposes. Execution obeys. Evidence reports. Reconciliation teaches.**

Reconciliation may improve competence. It does not legislate.

## Campaign thesis

AI is becoming better at deciding what to do and increasingly capable of doing it. Capability alone does not establish authority.

Pulpo is the governance and evidence plane between intelligence and consequential execution. It resolves whether an action is authorized, binds authorization to exact permitted work, preserves one-use and replay semantics, reconciles what actually happened, and lets verified outcomes improve future competence without silently expanding authority.

`CAPABILITY != AUTHORITY != EXECUTION != CONSEQUENCE != EVIDENCE`

## Evidence-backed claims available now

### Governance kernel

Current canonical evidence supports these claims:

- unknown, incomplete, negative-cost, and over-budget intents fail closed;
- selected high-impact actions require verifier-backed approval;
- approval is bound to pinned trust, deployment, principal, session, exact intent, exact policy, nonce, issue time, and expiry;
- one-use permits are bound to exact intent and cannot be replayed;
- approval IDs, nonces, permits, and audit state persist across ordinary restart with the SQLite backend;
- persisted audit-chain tampering blocks kernel bootstrap;
- configured roles cannot exceed their action, resource, or cost grants.

### Bounded commerce

Canonical evidence supports messaging that:

- a bounded domain order can be tied to exact request, quote, owner, registrar, privacy, upsell, renewal, and USD 30 pilot constraints;
- reservations, attempted orders, reconciliation, receipt hashes, and spend persist across ordinary restart;
- concurrent workers cannot over-reserve the tested pilot ceiling;
- the name.com CORE adapter fails closed before production execution when the provider cannot enforce Pulpo's required hard pre-charge cap;
- authorization, attempted execution, payment evidence, delivery, acceptance, and value remain separate outcome states.

### Governed directives

Canonical `main` supports these claims:

- ordinary chat or retrieval cannot create an authoritative directive;
- directive activation and revocation use the existing governed authority path;
- directive versions are immutable;
- approval for one directive digest cannot authorize broadened or substituted scope;
- retrieval score and model-generated summaries cannot raise authority;
- directive revocation state persists across ordinary restart and its authority evidence lands in the existing audit chain.

**Current boundary:** canonical `main` does **not** yet prove that a permit issued while a directive is active becomes unusable after that directive is later revoked. PR #44 reproduces that stale-permit failure and contains a passing candidate fix, but the fix is not canonical. Do not market execution-time directive revocation continuity as solved until it is legitimately admitted and reverified.

### Governed learning on real external state

PR #42 is now canonical and supports a new marketing claim:

- Pulpo performed two bounded, reversible external GitHub state effects under frozen conditions;
- the first effect was reconciled to its exact effect commit rather than relying only on provider acknowledgement or the later branch tip;
- a later unrelated mutation was distinguished from the intended effect;
- the first reconciled outcome produced a bounded lesson: verify the exact effect version or receipt identity, then separately reconcile current destination state;
- applying that lesson to the second external effect improved the frozen verification-policy score from **7/10 to 10/10**;
- authority effect remained **none**.

Supported public claim:

> **Pulpo has verified field-level governed knowledge transfer on a real, reversible GitHub state surface: evidence from one reconciled effect improved verification of a later effect while authority remained unchanged.**

This does not prove model-weight learning, general intelligence improvement, autonomous policy change, production recursive learning, or provider-independent transfer.

## A stronger marketing rule emerged

Recent work exposed a useful constraint on the campaign itself: research and experimental evidence can move faster than consequence-bearing controls enter canonical `main`.

The proposed **Canonical Consequence Rule** is therefore relevant to messaging as well as engineering:

> When research velocity outruns canonical control admission, consolidate before expanding.

That rule is proposed in PR #50, not yet canonical doctrine.

Its first application exposed a canonical concurrency defect in replay-reason classification. The duplicate approval still failed closed, but the losing replay could be classified from different SQLite snapshots. PR #51 contains a passing atomic one-snapshot candidate fix, but remains noncanonical pending legitimate admission.

This is part of the brand, not an embarrassment to hide:

> **If evidence disproves our marketing, the marketing changes first.**

## Claims we do not make yet

Do not market Pulpo as already proving:

- production readiness;
- independently deployed human signing authority;
- production trusted bootstrap, protected time, or protected monotonic state;
- rollback-proof or hostile-worker-resistant storage;
- OS-enforced filesystem, network, process, or secret isolation;
- hostile-code sandboxing;
- real payment-rail enforcement or a completed autonomous purchase;
- execution-time directive revocation continuity on canonical `main`;
- distributed production identity;
- provider-independent or model-weight learning;
- broad third-party reproduction or customer outcomes.

## Tagline bank

### Flagship

- **The friction is the feature.**
- **Capability is not authority.**
- **Smart enough to act. Governed enough to stop.**
- **If it can act, it should be able to prove why.**
- **Faster AI needs stronger brakes.**
- **Learning can improve competence. Learning cannot promote itself.**

### Evidence and consequence

- **Execution success is not outcome proof.**
- **Verify the exact effect, not just the acknowledgement.**
- **Evidence reports. Reconciliation teaches. Neither grants permission.**
- **The branch tip is not the receipt.**
- **Merged is not verified. Verified is not authorized.**
- **A result can teach the next action without authorizing it.**

### Adversarial / technical

- **Retrieval relevance is not authority.**
- **Replay should fail.**
- **Approval is not execution proof.**
- **Evidence cannot retroactively authorize consequence.**
- **If the same system proposes, approves, executes, and grades itself, you do not have governance.**
- **The best autonomous system knows exactly where autonomy ends.**

### Founder / public voice

- We are not trying to slow AI down. We are trying to make speed survivable.
- Pulpo is the part of the stack that is allowed to be annoying.
- The day your AI becomes consequential, "probably authorized" stops being good enough.
- The agent economy does not only need smarter agents. It needs constitutional boundaries.
- If Pulpo never tells us no, we should assume we built it wrong.
- If the evidence disproves our marketing, the marketing changes first.

## Updated launch sequence

### Phase 1 — Capability is not authority

Establish the problem: increasingly capable AI still needs independent authority architecture.

### Phase 2 — Constitutional separation

Explain intelligence, governance, execution, evidence, and reconciliation as separate responsibilities.

### Phase 3 — Show refusal

Demonstrate replay denial, budget denial, intent/permit mismatch, malformed or substituted authority, broadened directive denial, retrieval attempting to elevate authority, and production commerce denial when the hard charge cap cannot be enforced.

### Phase 4 — Show governed learning

Use the canonical GitHub field experiment: one reconciled effect produced a bounded lesson that improved verification of the next effect from **7/10 to 10/10** while authority stayed unchanged.

### Phase 5 — Consequential proof

Complete one low-risk external transaction through:

`request -> discover -> quote -> authorize -> permit -> execute -> independently verify -> reconcile -> learn`

Publish stronger commerce claims only after the remaining authority, protected-state, payment-cap, and independent-verification gates pass.

## Updated public post

**The friction is the feature.**

AI is getting better at deciding what to do and better at doing it.

That makes one question more important, not less:

**Who authorized the consequence?**

Pulpo is the governance and evidence plane between intelligence and consequential execution. A model can reason, plan, recommend, and learn. It does not get to turn those capabilities into its own permission.

Pulpo now has a canonical field proof on a real, reversible GitHub state surface. One external effect produced evidence. Reconciliation extracted a bounded lesson from that evidence. Applying the lesson to a second external effect improved the completeness of verification from **7/10 to 10/10** under the frozen rubric.

Authority changed by **zero**.

That is a narrow but important result: verified outcomes can improve later competence without becoming policy or permission.

The same discipline applies when the software exposes a failure. Canonical Pulpo still has an open stale-permit boundary around directive revocation. There is a passing candidate fix, but it is not canonical yet, so we do not market the problem as solved.

That is what **the friction is the feature** means in practice.

The system should reject a replay. It should refuse broadened scope. It should distinguish provider acknowledgement from proof of consequence. And when evidence contradicts a claim, the claim should lose.

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports. Reconciliation teaches.**

## Campaign invariant

Marketing may explain verified canonical behavior, clearly identified noncanonical evidence, and clearly labeled proposals. Marketing may not transform an inference, branch experiment, planned integration, successful demo, passing candidate, or provider acknowledgement into a production or canonical claim.

**Evidence first. Claims second.**

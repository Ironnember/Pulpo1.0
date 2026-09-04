# Pulpo Current State

Status date: 2026-09-04

## Canonical source

`Ironnember/Pulpo1.0` on protected `main` is the sole source of truth for current Pulpo code, tests, architecture, governance, and forward development.

At this reconciliation, protected `main` is:

`1ee8485c4599ad3266c8e90c5baad29309bc700c`

This commit canonically admits PR #161, `Feature: governed outcome-memory gate v0`.

The SHA is an inspection point, not a permanently pinned source-of-truth designation.

Historical repositories, held branches, Draft pull requests, closed-unmerged proof objects, screenshots, summaries, and experimental distribution artifacts remain evidence or reference material only unless a legitimate governance transition admits their behavior into canonical Pulpo.

Evidence precedence remains:

1. executable behavior and tests;
2. current canonical reviewed code;
3. durable runtime/provider evidence;
4. current state artifacts and explicit decisions;
5. design documents;
6. summaries, screenshots, prototypes, and marketing.

## Constitutional boundary

Pulpo remains the governance and evidence plane between intelligence and consequential execution.

`Purpose -> Intent -> Authority -> Policy -> Decision -> Permit -> Execution -> Evidence -> Reconciliation -> Memory -> Adaptation -> Purpose`

Core invariants include:

- `NO_PERMIT != NO_GOVERNED_EFFECT`
- `CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`
- `NO_WRITE_ROUTE != NO_WRITE_CAPABILITY`
- `CORRECTNESS != AUTHORITY`
- `MEMORY != AUTHORITY`

Intelligence may reason, propose, simulate, and learn.

Pulpo governs identity, authority, policy, budget, approval, canonical state transitions, permits, evidence, reconciliation, and governed outcome memory.

Execution surfaces perform only the exact permitted consequence and return evidence. Executor success cannot self-certify reconciliation.

## Claim classes

- **Verified** — reproduced or directly supported by current executable/current canonical evidence.
- **Recorded** — durably captured evidence not independently reproduced in this reconciliation.
- **Inferred** — a conclusion from evidence, explicitly identified as inference.
- **Proposed** — intended next design or action, not yet proved.
- **Unknown** — insufficient or conflicting evidence.

Do not promote `Recorded`, `Inferred`, or `Proposed` claims through repetition.

## Verified canonical software boundary

### Governance kernel and directives

Canonical Pulpo retains the established fail-closed governance kernel, exact intent/policy binding, one-use permits, replay protection, durable state semantics, directive narrowing/revocation behavior, and the separation between intelligence, governance, and execution.

Successful prior execution, model output, retrieval, conversational memory, or governed outcome memory does not independently expand authority.

### Capability-stripped MCP boundary

PR #134 is canonical.

The MCP-side projection no longer retains the kernel, orchestrator, canonical state backend, authority client, executor, live policy object, trusted clock, or ledger reference.

Proposal construction is ephemeral and non-mutating. Frozen primitive snapshots do not become canonical writers merely because no write route is exposed.

This establishes the tested software/object-capability boundary. It does not establish hostile same-process memory isolation, production remote-MCP authentication, or live-current evidence freshness.

### Consequence reconciliation and governed outcome memory

Issue #153 is completed and its implementation is canonical through PR #161.

Canonical Pulpo now explicitly proves the local software/custody/observer invariant:

`VALID_AUTHORITY + VALID_PERMIT + EXECUTION_SUCCESS != VERIFIED_CONSEQUENCE`

The canonical path distinguishes:

- independently verified success;
- observed mismatch despite executor/provider success;
- independently observed provider failure;
- unresolved or insufficient evidence.

Mismatch and unknown state survive restart without becoming success or retry authority.

Replay, substitution, expiry, revocation, and authority-widening paths remain fail-closed under the tested boundary.

Governed outcome memory is admitted only after exact reconciliation evidence has converged into canonical custody evidence.

The same exact reconciliation transition cannot create multiple canonical outcome-memory records under simultaneous identical callers.

Successful outcome memory remains non-authoritative and cannot mint a permit, alter policy, or authorize an otherwise denied intent.

This is a software/custody/observer proof. It is not a claim of real external-provider containment.

## Governance and repository admission

Protected `main` visibly requires:

- `test`
- `authority`
- `authority-service`
- `admission-hold`

Active ruleset `22241311` separately requires strict status checks for `test`, `authority`, and `authority-service`, one approving review, stale-review dismissal after push, last-push approval, review-thread resolution, and reports no bypass actors with `current_user_can_bypass="never"`.

Issue #115 is completed.

Repository admission has executable evidence demonstrating that passing code and an approval do not themselves create admission authority.

A held candidate can be denied while the same code object can later become eligible only after the separately authorized admission-state transition.

During PR #161 admission, stale classic branch-protection settings requiring nonexistent Preview/Production deployments and locking `main` read-only were identified as independent blockers. They were removed through an explicitly authorized settings transition before the protected merge succeeded.

The full classic branch-protection metadata is not completely readable through the connected integration, so unobserved administration metadata should not be overclaimed.

## Bounded commerce

Canonical Pulpo proves the bounded digital-commerce foundation: exact purchase-object binding, budget ceilings, reservation/reconciliation semantics, one-use authority, and separation of provider execution claims from independent consequence evidence.

A material canonical defect remains:

provider-side auto-renew enablement is not represented in the exact canonical domain request/order identity.

Current canonical objects constrain renewal price, but provider defaults could still create future renewal capability or charges not explicitly represented by the authorized object.

Invariant:

`CANONICAL_ACTION_OMISSION != AUTHORIZED_PROVIDER_DEFAULT`

PR #143 contains useful historical corrective work for this defect, but it is based on older canonical state, spans twelve files, and must not be admitted as-is.

The next commerce correction should port the smallest authority-correct auto-renew delta onto current `main`, then earn fresh exact-head proof, review, and repository admission.

No real registrar purchase or independently observed registrar consequence is established.

## Independent authority

Issue #90 remains open.

Recorded cloud/HSM evidence may support individual infrastructure claims, but the complete `authority.pulpo.ai` boundary has not yet been acceptance-proven as an independently deployed human-authority system.

Production-facing authority claims therefore remain bounded below a completed independent authority deployment.

## Noncanonical and historical proof objects

PR #159 is stale documentation reconciliation against pre-#161 canonical state and must not be admitted as-is.

PR #160 remains a preserved Draft negative/composition proof showing the Issue #153 gap before the canonical #161 implementation. It is evidence history, not a production object to merge.

PR #143 remains historical/current-reference evidence for the auto-renew correction, not a current-main admission candidate.

PR #131 remains a Draft distribution candidate. Its capability-stripping concepts may inform future distribution work, but it is not canonical distribution or production deployment.

PR #128 is closed unmerged structural Stage-C evidence. It does not establish an external unauthorized-effect rate or real external containment.

`Ironnember/The-keel` remains an execution-plane experiment unless and until its exact execution contract is legitimately admitted without becoming a second authority or ledger.

## Proof boundary

### Verified

Canonical Pulpo currently has:

- a governed kernel and one-use authority path;
- replay/restart and directive freshness controls under the tested boundary;
- hostile-worker software/container controls;
- capability-stripped MCP behavior;
- independent evidence/reconciliation before verified consequence;
- canonical evidence before governed outcome memory;
- concurrent exactly-once outcome-memory admission;
- memory non-authority;
- protected repository admission controls with executable denial/allow evidence.

### Recorded

Recorded evidence includes historical cloud/HSM work, Keel experiments, historical Stage-C structural work, and held/stale corrective branches.

These are not automatically canonical or production proof.

### Inferred

Pulpo's strongest current differentiation is the continuity of independently governed authority and evidence from intent through consequence and memory, rather than generic agent orchestration.

A compact framing remains:

**Models can change overnight. Authority should not.**

### Proposed

The next technical sequence is:

1. restage the smallest auto-renew governed-effect correction against current canonical `main`;
2. establish fresh exact-head software proof and legitimate repository admission for that correction;
3. complete independent authority/provider qualification necessary for a genuine external consequence ceremony;
4. freeze the exact external execution/evidence object;
5. execute one bounded, safe external consequence through the canonical authority -> permit -> execution -> evidence -> reconciliation -> memory path;
6. preserve the evidence bundle and obtain cold reproduction outside the build loop.

### Unknown

Pulpo does not yet establish:

- real external-provider containment;
- a real external unauthorized-effect rate;
- fully accepted independent production authority;
- hostile-host or hostile-custodian containment;
- cold third-party reproduction of the complete consequential chain;
- arbitrary-provider correctness;
- production throughput, reliability, cost, false-denial rate, human-review burden, or customer ROI.

## Explicit nonclaims

Do not convert passing CI, a cloud primitive, repository approval, executor success report, experimental distribution artifact, financing term, social post, or market interest into:

- production readiness;
- external containment;
- independently deployed authority;
- compliance or certification;
- third-party reproducibility;
- valuation proof.

The current defensible position is:

Pulpo is a strong software-boundary governance and evidence system with mechanically demonstrated canonical admission controls and canonical consequence-reconciliation/outcome-memory behavior.

External consequence verification and independent production authority remain the next major proof boundary.

## Doctrine

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**

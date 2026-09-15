# Pulpo Current State

Status date: 2026-09-15

## Canonical source

`Ironnember/Pulpo1.0` on protected `main` is the sole source of truth for current Pulpo code, tests, architecture, governance, and forward development.

At this reconciliation, protected `main` is:

`b44dcd40a1ad2bd5413756bd413807f54f9283da`

This head canonically includes PR #161, `Feature: governed outcome-memory gate v0`, the subsequent state reconciliation, and PR #200, `Feature: trusted frozen MCP snapshot export v0`.

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

### Independent approval contract

Canonical approval code pins public trust before governed work begins to the exact authority, verifier, key, algorithm, key fingerprint, deployment, and maximum approval TTL.

Each approval envelope binds approval identity, authority, verifier, key, deployment, trust hash, session, principal, exact intent hash, exact policy hash, nonce, issued time, expiry, and signature.

This is verified canonical software behavior for the approval contract. It does not prove that the complete independent `authority.pulpo.ai` service is deployed or acceptance-proven.

### Capability-stripped MCP boundary and trusted frozen export

PR #134 established the capability-stripped MCP projection. PR #200 is now canonical and adds the trusted-side `export_mcp_snapshot()` bridge.

The MCP-side projection retains no kernel, orchestrator, canonical state backend, authority client, executor, live policy object, trusted clock, or ledger reference. Proposal construction remains ephemeral and non-mutating.

The trusted exporter writes only the primitive frozen `pulpo.mcp-read-snapshot.v0` projection. It is intentionally absent from the MCP server, does not mutate canonical Pulpo state, and does not append a second audit event.

Export uses an existing absolute non-symlinked parent directory, same-directory temporary file, synchronization, atomic replacement, owner-only permissions, and pathname-binding rechecks. A failure after replacement is classified as `mcp_snapshot_export_commit_unknown`; the destination must be reconciled before retry because a frozen file may already exist.

The resulting file remains a frozen derivative. Its presence is not permission, verified delivery, proof that a reader observed it, live-current freshness, production authentication, independent deployment, or external consequence containment.

This establishes the tested software/object-capability and trusted frozen-export boundary. It does not establish hostile same-process memory isolation, production remote-MCP authentication, or a live read-only IPC transport.

### Consequence reconciliation and governed outcome memory

Issue #153 is completed and its implementation is canonical through PR #161.

Canonical Pulpo explicitly proves the local software/custody/observer invariant:

`VALID_AUTHORITY + VALID_PERMIT + EXECUTION_SUCCESS != VERIFIED_CONSEQUENCE`

The canonical path distinguishes independently verified success, observed mismatch despite executor/provider success, independently observed provider failure, and unresolved or insufficient evidence.

Mismatch and unknown state survive restart without becoming success or retry authority. Replay, substitution, expiry, revocation, and authority-widening paths remain fail-closed under the tested boundary.

Governed outcome memory is admitted only after exact reconciliation evidence has converged into canonical custody evidence. Successful outcome memory remains non-authoritative and cannot mint a permit, alter policy, or authorize an otherwise denied intent.

This is a software/custody/observer proof. It is not a claim of real external-provider containment.

## Governance and repository admission

Pulpo retains protected repository admission as a separate governance boundary. Passing code, CI, or review does not independently create admission authority.

The exact live GitHub protection metadata was not fully re-reconciled in this documentation-only update; prior protection claims should therefore be treated according to their recorded evidence date rather than silently promoted to current verification.

## Bounded commerce

Canonical Pulpo proves the bounded digital-commerce foundation: exact purchase-object binding, budget ceilings, reservation/reconciliation semantics, one-use authority, and separation of provider execution claims from independent consequence evidence.

The previously identified provider-default/auto-renew concern remains a proof item unless current executable evidence demonstrates its correction. No real registrar purchase or independently observed registrar consequence is established by this reconciliation.

Invariant:

`CANONICAL_ACTION_OMISSION != AUTHORIZED_PROVIDER_DEFAULT`

## Independent authority

The recorded Google Cloud HSM signer evidence remains evidence of an external signing primitive, not proof of a fully deployed independent `authority.pulpo.ai` human-authority system.

`HSM_SIGNER != DEPLOYED_INDEPENDENT_AUTHORITY`

Production-facing authority claims remain bounded below a completed independent authority deployment and acceptance proof.

## Evidence Expansion Review

`docs/EVIDENCE_EXPANSION_REVIEW.md` is proposed on the current documentation branch as a read-only Intelligence/Assurance review procedure. It is not canonical until admitted through the normal repository governance path.

Its intended boundary is deliberately subordinate to the existing architecture: broader inspection and pattern analysis may recommend a proof, but may not mutate canonical state, change policy, create directives, issue permits, write governed outcome memory, expand connectors, or authorize execution.

If admitted, the procedure must remain an analytical protocol rather than a second authority, policy engine, memory governor, evidence ledger, router, or executor.

## Proof boundary

### Verified

Canonical Pulpo currently has:

- a governed kernel and one-use authority path;
- exact intent/policy binding and fail-closed decision semantics;
- an exact-object independent approval contract in canonical software;
- replay/restart and directive freshness controls under the tested boundary;
- hostile-worker software/container controls under their stated test boundary;
- capability-stripped MCP behavior;
- a trusted frozen MCP snapshot exporter with explicit commit-unknown reconciliation;
- independent evidence/reconciliation before verified consequence;
- canonical evidence before governed outcome memory;
- memory non-authority;
- repository-admission governance evidence under its recorded boundary.

### Recorded

Recorded evidence includes the external HSM signer acceptance record, Keel experiments, historical Stage-C structural work, and historical/held proof objects. These are not automatically canonical or production proof.

### Inferred

Pulpo's strongest current differentiation remains continuity of independently governed authority and evidence from intent through consequence and memory, rather than generic agent orchestration.

**Models can change overnight. Authority should not.**

### Proposed

The highest-value forward sequence remains to close exact bounded-commerce semantics, complete independent authority/provider qualification, freeze an exact external execution/evidence object, execute one bounded safe external consequence through the canonical authority -> permit -> execution -> evidence -> reconciliation -> memory path, preserve the evidence bundle, and obtain cold reproduction outside the build loop.

The Evidence Expansion Review may help identify blockers and choose the smallest falsifiable proof, but it does not alter that sequence or authorize any step.

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

Do not convert passing CI, a cloud primitive, repository approval, executor success report, frozen snapshot, analytical pattern, experimental distribution artifact, financing term, social post, or market interest into production readiness, external containment, independently deployed authority, compliance/certification, third-party reproducibility, or valuation proof.

## Doctrine

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**

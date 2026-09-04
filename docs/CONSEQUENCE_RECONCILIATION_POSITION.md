# Pulpo Consequence Reconciliation Position

Status: proposed canonical doctrine update pending normal repository admission

Date: 2026-09-03

## Purpose

Agent-governance infrastructure is converging rapidly around identity, scoped authorization, runtime policy enforcement, approval, revocation, action binding, and execution telemetry. Pulpo must treat those controls as necessary architecture, not as sufficient product differentiation.

Pulpo's durable boundary is the relationship between authorized intent and observed consequence.

## Constitutional consequence invariant

`VALID_AUTHORITY + VALID_PERMIT + EXECUTION_SUCCESS != VERIFIED_CONSEQUENCE`

A legitimate authorization proves that an exact action was allowed. A permit proves that a bounded execution capability was issued. An executor or provider receipt may prove that an invocation was attempted or reported successful. None of those facts alone proves that the authorized real-world consequence actually occurred.

For consequential actions, Pulpo therefore preserves this closing path:

`Authority -> Policy -> Decision -> Permit -> Execution -> Evidence -> Reconciliation -> Outcome Memory`

The consequence becomes `SUCCESS_VERIFIED` only when evidence sufficient for the governed claim independently establishes the relevant external state and reconciliation determines that the observed state matches the authorized intent and acceptance criteria.

## Supporting invariants

- `EXECUTION_RECEIPT != VERIFIED_CONSEQUENCE`.
- `EVIDENCE != AUTHORITY`.
- `RETRIEVAL_RELEVANCE != AUTHORITY`.
- `MODEL_SUMMARY != AUTHORITY`.
- `OBSERVED_MISMATCH != SUCCESS`.
- `INSUFFICIENT_EVIDENCE != SUCCESS`.
- `RECONCILIATION_MISMATCH` and `EVIDENCE_FAILURE` must not be promoted into successful outcome memory.
- Outcome memory may improve competence, diagnostics, routing, estimates, and recommendations; it may not expand capability, budget, identity scope, approval class, policy power, or execution surface without a separate legitimate authority transition.
- Revocation, expiry, directive validity, and other authority conditions must remain valid at the governed execution boundary where required; earlier approval does not create permanent authority.

## Trust separation

Pulpo should keep three facts separate even when one vendor or adapter produces all three artifacts:

1. **Authority fact** — was this exact action legitimately authorized under current policy and scope?
2. **Execution fact** — what operation did the execution surface attempt or report?
3. **Consequence fact** — what independently observable state exists after the action?

Reconciliation compares those facts. It does not infer consequence from authorization and does not treat executor self-report as independent observation merely because the report is signed.

The required independence depends on the consequence and threat model. Independence may be a distinct provider read identity, an external observer, a protected evidence service, a separate sensor, a financial settlement record, or another source that does not merely repeat the executor's assertion. If sufficient independent evidence is unavailable, Pulpo should preserve `unknown` rather than manufacture success.

## Market-convergence implication

Current market activity indicates strong convergence around:

- agent/non-human identity;
- delegated and least-privilege access;
- pre-execution policy evaluation;
- human approval and escalation;
- short-lived/scoped tokens;
- runtime MCP/tool enforcement;
- revocation and kill switches;
- exact-action or tool-call binding;
- audit trails, signed decisions, and execution telemetry.

These are increasingly table stakes. Pulpo should not position itself primarily as another agent control plane, MCP firewall, IAM layer, policy engine, approval workflow, or observability product.

Pulpo's stronger position is:

> **Govern consequences, not just agents. Bind authority before action, establish consequence with evidence after action, reconcile the two, and govern what may be remembered or learned.**

This positioning must remain subordinate to executable evidence. Market convergence validates the architectural direction; it does not prove Pulpo's implementation or create novelty by assertion.

## Proof priority

The highest-value externally reproducible proof is:

`VALID DIRECTIVE`
`-> VALID AUTHORITY`
`-> VALID ONE-USE PERMIT`
`-> CORRECTLY BOUND EXECUTION`
`-> INDEPENDENT OBSERVATION DISAGREES OR CANNOT VERIFY`
`-> RECONCILIATION_MISMATCH OR EVIDENCE_FAILURE/UNKNOWN`
`-> NO SUCCESSFUL OUTCOME MEMORY`
`-> NO LEARNED AUTHORITY EXPANSION`

The proof should include at minimum:

1. a matched, independently verified success case;
2. a mismatch case in which the executor reports success but observed state differs from the authorized consequence;
3. an unknown/evidence-unavailable case that remains unresolved rather than becoming success;
4. restart persistence of the reconciliation result;
5. denial of replay, substitution, stale/revoked directive, expired permit, and authority widening;
6. proof that retrieval score, conversational memory, model summaries, and prior success cannot raise authority;
7. evidence that outcome-memory admission depends on the reconciliation result rather than on executor success alone.

## Effect on Pulpo work

### Architecture and implementation

- Extend the existing authority/policy/permit/evidence/reconciliation path; do not create a second authority service, policy engine, router, executor, evidence ledger, or memory governor.
- Treat execution surfaces such as Keel, MCP gateways, cloud APIs, browsers, payment rails, and endpoint controls as subordinate effectors/evidence sources, not as canonical authority or self-certifying consequence observers.
- Preserve observer/executor separation when the threat model requires independent consequence verification.

### Tests and proofs

- Prefer adversarial `authorized + executed + mismatch` and `authorized + executed + unknown` tests over additional allow/deny demos when the core authorization invariant is already covered.
- A provider success response must not satisfy a consequence assertion unless the governed evidence contract explicitly permits it for that low-risk claim and the limitation is recorded.
- Preserve `Verified`, `Recorded`, `Inferred`, `Proposed`, and `Unknown` classifications.

### Outcome memory and learning

- Only reconciliation-supported outcomes may be promoted into successful reusable completion paths.
- Mismatch and unknown outcomes remain useful governed knowledge, but they must retain their failure/uncertainty classification.
- Learning may propose policy or authority changes; it may never authorize them.

### Public positioning, partnerships, and competitive analysis

- Treat identity, runtime policy enforcement, scoped authorization, approvals, revocation, action binding, and audit as increasingly converged capabilities.
- Lead differentiated technical claims with independent consequence verification, reconciliation, governed outcome memory, and non-self-authorizing adaptation only where current executable evidence supports them.
- Distinguish vendor marketing claims from source code, tests, standards text, papers, patents, or independently reproduced behavior.
- Do not make patent-priority, infringement, or exclusivity claims from conceptual similarity alone.

## Compact doctrine

`Intelligence proposes. Governance disposes. Execution obeys. Evidence reports. Reconciliation determines what may be believed, remembered, and learned.`

The shorter established doctrine remains valid:

`Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.`

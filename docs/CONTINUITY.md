# Pulpo Cross-Plane Continuity

Status date: 2026-09-04

`authority_effect=none`

This file is a dated coordination checkpoint on a Draft documentation branch. It does not create authority, admit code, change policy, authorize execution, or supersede live protected `main`. Re-read live repository, provider, authority, and evidence state before any consequential action.

## Purpose

Keep intelligence, governance, execution, evidence, repository admission, and external operating context aligned without collapsing their trust boundaries.

The constitutional lifecycle remains:

`Purpose -> Intent -> Authority -> Policy -> Decision -> Permit -> Execution -> Evidence -> Reconciliation -> Memory -> Adaptation -> Purpose`

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**

## Live coordination checkpoint

At this checkpoint:

- canonical repository: `Ironnember/Pulpo1.0`;
- protected `main`: `d421fbe73732a7ed4c942928d62e80dd6bbb2057`;
- visibly required protected-main checks: `test`, `authority`, `authority-service`, `admission-hold`;
- Stage-C real-provider work: Issue #164 + held Draft PR #165;
- independent authority deployment: Issue #90 remains open;
- repository-organization work: Draft PR #168 remains noncanonical until separately reviewed and admitted.

These are inspection points, not permanent pins. Live refs and stronger evidence supersede this snapshot.

## Plane 1 — Intelligence

Intelligence may reason, compare models, retrieve context, plan, simulate, and propose. It may not manufacture authority or widen scope because a model is newer, more capable, more confident, or claims approval.

Current software-proof object:

- PR #163, `Proof: model authority invariance v0`;
- exact proof head at this checkpoint: `cb6b7c5a9d8faf9f3f87f30df204469952e73260`;
- test-only change; no model-provider inference call and no production runtime change.

Important evidence mismatch: GitHub currently records an `APPROVED` review on PR #163, but the review body explicitly discusses PR #168 and exact head `ee7a654af615a4f1cbe1179050e66c710f07fe92`. Treat that review as mismatched evidence, not clean substantive approval of PR #163. Do not consume it as admission authority until an object-specific review is reconciled.

Invariant:

`MODEL_CHANGE != AUTHORITY_CHANGE`

## Plane 2 — Governance / Pulpo

Protected `main` remains the only canonical forward-development source.

Canonical software currently carries the fail-closed governance kernel, exact intent/policy binding, one-use permit and replay semantics, directive freshness/revocation behavior, capability-stripped MCP behavior, consequence reconciliation, governed outcome-memory rules, and repository-admission controls already admitted through protected `main`.

Independent production authority remains incomplete. Issue #90 is the active deployed-authority boundary; cloud/HSM primitives or passing CI do not by themselves establish a fully accepted independent human-authority service.

Issue #151 records a directional triadic verification model for designated high-consequence actions. It remains proposed/noncanonical. The founder/principal role is mandate-fidelity verification, not unilateral finality or independent consequence ratification.

Invariants:

- `CORRECTNESS != AUTHORITY`
- `MEMORY != AUTHORITY`
- `CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`

## Plane 3 — Execution / Keel / provider surfaces

Keel, APIs, shells, browsers, cloud services, databases, tool marketplaces, and other execution surfaces are bounded executors/capability surfaces. They do not decide their own authority and cannot self-certify reconciliation.

The current smallest external-consequence proof is the Supabase/PostgreSQL Stage-C sandbox:

- Issue #164 records the experiment;
- PR #165 remains Draft and machine-held;
- provider scope: `pulpo_stage_c.effects`;
- separate intended roles: executor, observer, cleanup;
- replay confound removed so duplicate `effect_id` values remain externally observable;
- all three roles remain `NOLOGIN` at the latest recorded provider readback.

Therefore the real external ceremony has not run. Same-session `SET ROLE`, a shared administrator credential, or a combined executor/observer credential does not satisfy the proof.

Invariant:

`ONE_PERMIT -> AT_MOST_ONE_AUTHORIZED_EXECUTION_ATTEMPT`

not:

`ONE_PERMIT -> EXACTLY_ONE_EXTERNAL_REALITY`

## Plane 4 — Evidence / reconciliation

Execution success is evidence input, never finality by itself.

The canonical software boundary distinguishes verified consequence, observed mismatch/failure, and unresolved/insufficient evidence. Unknown external reality must remain unknown and cannot manufacture retry authority.

Stage-C software readiness is stronger than its external proof state: the held experiment routes the adversarial cases through the same consequence-capable seam and includes a one-transmission anti-vacuity race case plus false-success/observer-blackout handling. That remains software-boundary evidence until independently credentialed provider sessions execute and are observed.

Invariants:

- `EXECUTOR_SUCCESS != VERIFIED_CONSEQUENCE`
- `OBSERVATION_UNAVAILABLE -> UNKNOWN`
- `UNKNOWN != ZERO_UNAUTHORIZED_EFFECT`
- `PAST_SUCCESS != FUTURE_AUTHORITY`

## Repository admission plane

Repository admission is itself a governed effect when it changes canonical state.

Protected `main` visibly requires `test`, `authority`, `authority-service`, and `admission-hold`. Passing CI, a Draft/Ready label, or a review is not sufficient if the exact admission object, current head, required checks, review semantics, and protected rules do not all reconcile.

Current continuity rules:

1. PR #165 stays Draft/held until the real Stage-C proof and separate repository admission conditions are satisfied.
2. PR #168 stays Draft while this documentation/organization work is reviewed; this file does not authorize its merge.
3. PR #163 must not be merged based on the current mismatched review body. Reconcile an exact-object substantive review first, then re-read head/base/checks/threads and merge-method constraints before any merge.
4. A new push can stale approval under repository rules; always re-read the exact object immediately before admission.

## External operating plane

Commercial, legal-entity, funding, accelerator, partner, and customer records are operating context, not canonical technical authority. They should be maintained in permission-appropriate records and never inferred from repository state.

Do not turn an NDA, SOW, application, financing document, accelerator interest, social post, or provider account into production readiness, valuation, external containment, or customer traction.

For public positioning, preserve the current narrow center:

**Pulpo is proof-carrying consequence infrastructure for autonomous systems.**

For technical positioning, the harder boundary is:

`exact authorized effect -> one-use authority -> one transmission right -> executor claim -> independent observation -> reconciliation -> governed memory`

## IP / provenance continuity

Broad AI-governance, runtime-control, admissibility, identity, policy, approval, and authority-continuity language is crowded and carries provenance pressure. Protect the mechanics, not the category label.

Current technical filing center for counsel remains the narrower combination of:

- same-object authorized effect surface;
- same one-use authorization through execution;
- independent post-execution observation;
- concrete effect-delta reconciliation;
- explicit `uncertain`/`Unknown` treatment when required observation is insufficient;
- hostile-worker one-attempt custody and no blind retry after an unknown provider outcome.

Do not backdate later Pulpo mechanics into earlier June/July precursor material. Earlier Keel/Pulpo records support architectural lineage, not automatic priority for later exact mechanisms.

## Reconciled conflicts / active blockers

| Item | Current classification | Continuity rule |
| --- | --- | --- |
| PR #163 review record points to PR #168 | **Recorded mismatch** | Do not consume as substantive #163 approval until reconciled |
| Stage-C provider roles are structurally split but `NOLOGIN` | **Verified/Recorded setup; external proof Unknown** | Establish genuinely separate credential-bearing sessions before real ceremony |
| Independent authority service | **Software contract verified; deployed acceptance Unknown** | Issue #90 remains the deployment gate |
| PR #168 documentation map | **Draft / Proposed admission** | Keep Draft until exact-head review and normal protected admission |
| External legal/funding/business facts | **Separate operating context** | Verify from the appropriate legal/financial source before submission or public claim |

## Next execution order

1. Preserve this continuity checkpoint as non-authoritative documentation on PR #168.
2. Reconcile the PR #163 review-object mismatch without merging it on ambiguous evidence.
3. Complete substantive read-only review of PR #168 on its new exact head; keep it Draft until separately authorized for admission.
4. Establish three distinct Stage-C provider login sessions without exposing observer capability to the executor.
5. Freeze and separately authorize the exact real Stage-C ceremony head/object.
6. Execute the bounded provider consequence, independently observe, reconcile, and preserve the evidence bundle.
7. Obtain cold reproduction outside the build loop before making third-party reproducibility claims.
8. Keep commercial/legal/IP records synchronized as non-authoritative context and import only evidence-supported facts into public materials.

## Handoff rule

Any future operator, model, project, or tool should begin by reading:

1. live protected `main` and required checks;
2. `docs/CURRENT_STATE.md`;
3. this continuity checkpoint only as a dated coordination map;
4. the exact active issue/PR/provider evidence for the task at hand.

If these disagree, higher-ranked current executable/provider evidence wins. Do not repair disagreement by silently merging histories.

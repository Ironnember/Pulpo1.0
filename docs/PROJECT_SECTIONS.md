# Pulpo project sections

Inspection base: protected `main` at `ca3636680ca50356406519a5722444c0742afb39`.

This file is a navigation and claim-boundary map. It does not create authority, mutate runtime policy, execute provider effects, publish a release, or add a second router, executor, policy engine, memory governor, authority service, or ledger.

`authority_effect=none`

## 1. Canonical doctrine and source hierarchy

Purpose: keep Pulpo's authority boundary, claim taxonomy, and proof discipline stable.

Current anchor files:

- `AGENTS.md`
- `docs/CURRENT_STATE.md`
- `docs/GOVERNANCE.md`
- `docs/ARCHITECTURE.md`
- `docs/AUTHORITY.md`

Claim boundary:

- Verified: executable behavior and exact-head tests outrank documents, summaries, screenshots, prototypes, and marketing language.
- Verified: material claims use `Verified`, `Recorded`, `Inferred`, `Proposed`, or `Unknown`.
- Unknown: any claim not backed by current executable evidence or current repository/provider observation.

## 2. Governance kernel

Purpose: evaluate exact intent against policy, approval state, one-use permits, replay protection, trusted time, and canonical audit state.

Current anchor files:

- `pulpo/kernel.py`
- `pulpo/authority.py`
- `pulpo/state.py`
- `pulpo/decision_evidence.py`
- `tests/test_authority.py`
- `tests/test_constitutional_sequences.py`

Claim boundary:

- Verified: policy correctness does not create authority by itself.
- Verified: unknown, malformed, expired, replayed, unavailable, or wrong-source authority fails closed through the canonical kernel.
- Unknown: deployed human-authority acceptance unless separately observed in the deployed authority service.

## 3. Directive authority continuity

Purpose: project scoped, authenticated, versioned, revocable directives into execution without turning conversational memory, retrieval, or summaries into governance truth.

Current anchor files:

- `pulpo/directives.py`
- `pulpo/state.py`
- `tests/test_directives.py`
- `tests/test_directive_parent_activation_race.py`
- `proofs/directive_authority_continuity/DM-001.md`

Claim boundary:

- Verified: ordinary chat/retrieval text cannot activate a directive.
- Verified: activation/revocation require the existing approval verifier and kernel permit path.
- Verified: same-principal derived directives can only narrow parent scope and parent revocation invalidates child-bound permits at execution time and after restart.
- Unknown: cross-principal delegated-operator authority is not proved by V0.

## 4. Capability projection and MCP boundary

Purpose: let external agents inspect/propose through capability-stripped surfaces without receiving authority-bearing Pulpo objects.

Current anchor files:

- `pulpo/mcp_boundary.py`
- `tests/test_mcp_boundary.py`
- `docs/MCP_BOUNDARY.md`

Claim boundary:

- Verified: MCP is transport/capability discovery, not authority.
- Verified: the admitted MCP projection exposes proposal and evidence without retaining kernel, orchestrator, state backend, authority client, executor, policy object, trusted clock, or ledger reference.
- Unknown: hostile same-process memory isolation, live remote authenticated MCP hosting, and production deployment.

## 5. Accountability context before delegation

Purpose: prove that accountable context should precede governed delegation, policy evaluation, permit issuance, and permit consumption.

Current anchor objects:

- PR #141 / `proof/accountability-context-v0`

Claim boundary:

- Proposed: this remains branch-local evaluation until admitted.
- Unknown: production regulatory acceptance and external-provider containment.

## 6. Bounded commerce and provider effect surface

Purpose: bind quotes, action objects, budget, provider execution, provider observation, and reconciliation to exact permits.

Current anchor files:

- `pulpo/commerce.py`
- `pulpo/custody_reconcile.py`
- `pulpo/namecom.py`
- `pulpo/namecom_core.py`
- `pulpo/namecom_observer.py`
- `docs/COMMERCE_PROOF.md`

Claim boundary:

- Verified: bounded-commerce software paths exist and are tested at the software boundary.
- Recorded: current open PR #143 addresses the auto-renew governed-effect omission as a branch-local corrective object.
- Unknown: real registrar Stage-C containment, real provider credential isolation, and external unauthorized-effect rate until separately executed and observed.

## 7. Custody, hostile-worker, and execution boundary

Purpose: allow execution surfaces to perform only exact permitted consequence and return evidence without self-certifying reconciliation.

Current anchor files:

- `pulpo/custody.py`
- `pulpo/custody_executor.py`
- `pulpo/custody_evidence.py`
- `pulpo/custody_reconcile.py`
- `custody-service/`
- `tests/test_custody*.py`

Claim boundary:

- Verified: hostile-worker and custody software-boundary tests exist.
- Unknown: arbitrary cloud/provider containment unless tested through an independent provider and observer.

## 8. Evidence, reconciliation, and unknown semantics

Purpose: determine whether observed consequence matches the authorized consequence, and refuse to treat missing or ambiguous evidence as safety.

Current anchor files:

- `pulpo/effect_reconcile.py`
- `pulpo/custody_reconcile.py`
- `pulpo/target_reconcile.py`
- `docs/EXACT_TARGET_PROOF.md`

Claim boundary:

- Verified: local artifact completion cannot be manufactured by chat/memory/retrieval claims.
- Verified: missing, wrong-source, mismatched, or ambiguous evidence remains unresolved/unknown instead of zero unauthorized effect.
- Unknown: third-party cold reproduction until preserved bundle and outside reproduction exist.

## 9. Temporal replay and governed learning

Purpose: validate material reusable lessons against historical checkpoints without reactivating historical authority.

Current anchor files:

- `AGENTS.md`
- `pulpo/temporal_replay.py` on held experimental branch #127
- `tests/test_temporal_replay.py` on held experimental branch #127

Claim boundary:

- Verified: contribution doctrine now requires temporal replay where applicable and denies historical authority travel.
- Proposed: first-class temporal replay implementation remains held branch-local until admitted.

## 10. Repository admission governance

Purpose: ensure repository admission is a governed effect, not a narrative or CI-only suggestion.

Current anchor files:

- `.github/workflows/admission-hold.yml`
- `.github/workflows/ci.yml`
- `tests/test_admission_hold_workflow_trust.py`

Claim boundary:

- Verified: protected `main` currently requires `test`, `authority`, and `authority-service` status contexts.
- Unknown/open: `admission-hold` is not yet read back as a protected required context; final bypass posture remains unresolved.

## 11. Distribution and read-only projections

Purpose: expose evidence to external users without giving distribution surfaces canonical write capability.

Current anchor objects:

- PR #131 / `distribution/canonical-mobile-projection-v0`

Claim boundary:

- Proposed: read-only mobile evidence projection remains held branch-local until admitted.
- Unknown: production authentication, live-current evidence freshness, native app distribution, public release publication.

## 12. Stage-C external consequence proof

Purpose: prove authority continuity across a real bounded external provider with distinct executor and observer authority/credentials.

Current anchor objects:

- closed-unmerged PR #128 structural contract
- future provider sandbox ceremony

Claim boundary:

- Recorded: the strengthened Stage-C contract requires complete attack coverage, distinct executor/observer identities, authenticated observer assertion, provider calibration, cleanup, and one matched safe conversion.
- Unknown: real external containment, external unauthorized-effect rate, and cold third-party reproduction.

## Current next proof order

1. Keep repository admission gap visible until `admission-hold` is protected-required and bypass posture is read back.
2. Admit or reject the commerce auto-renew governed-effect correction on its exact head.
3. Audit remaining canonical writers for capability possession, not only route exposure.
4. Preserve DM-001 as the directive-authority continuity proof boundary and do not turn Directive Memory into a memory governor.
5. Execute Stage C only after the provider action object binds all future-effect fields and distinct observer/executor credentials are ready.

## Public-language boundary

Use this line only where supported by current evidence:

> Pulpo is an independent authority and evidence plane for proving whether authorized consequence survived to observed consequence.

Do not claim production readiness, external containment, compliance, real-provider unauthorized-effect rate, or third-party reproducibility until those are separately proved.

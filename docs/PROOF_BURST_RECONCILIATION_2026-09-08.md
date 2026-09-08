# Pulpo Proof-Burst Reconciliation — 2026-09-08

Status: **Draft reconciliation / no admission authority**

`authority_effect=none`
`governed_effect=none`
`provider_effect=none`

## Purpose

Reconcile the rapid September proof burst against protected canonical `main`, prevent held experimental evidence from being mistaken for admitted behavior, and freeze the next highest-value sequence before additional architecture is added.

This document is a review artifact only. It does not admit any held branch, authorize a merge, authorize an external provider action, expand policy, create credentials, or change the Pulpo constitution.

## Canonical anchor

Protected `main` remains the sole canonical source.

At creation of this reconciliation branch, protected `main` is:

`d421fbe73732a7ed4c942928d62e80dd6bbb2057`

The existing `docs/CURRENT_STATE.md` remains the current admitted state artifact until a separate legitimate transition replaces it. Held Draft PRs and proof branches below are evidence/reference only.

## Reconciled held evidence

The following results are **Verified for their exact held proof objects** where their PR bodies/comments record successful exact-head CI/proof execution. They are **not canonical admission**.

### Real-provider Stage-C consequence custody — PR #165

Exact held head:

`9d20b2b1825aef10430bc4b31888059b917138fd`

Bounded held result records three distinct credential-bearing database principals, the frozen ten-case Stage-C matrix, exactly one authorized provider effect in the expected race case, zero unauthorized provider effects, matched reconciliation, governed cleanup, and post-proof credential revocation.

Boundary remains explicit:

`ZERO_UNAUTHORIZED_EFFECTS_UNDER_STAGE_C_V1 != GENERAL_CONTAINMENT`

No independent production authority, hostile-host/custodian resistance, arbitrary-provider correctness, or cold third-party reproduction follows from this result.

### Hostile-worker direct route isolation — PR #170

Exact held head:

`d817e8234664072bc3be0c7306f9f2455874f8b4`

The tested Docker topology blocks hostile-worker provider DNS/raw-IP access while custody retains the protected provider route and capability.

Boundary:

`NO_DIRECT_ROUTE != NO_UNGOVERNED_CAUSAL_PATH_TO_EFFECT`

### Causal-closure relay attack — PR #191

Exact held head:

`57f9e5c08ba3a5e01623eb0a82bc9a53561c1ecd`

The tested relay classes — metadata/token-shaped, delegated/signed-request-shaped, webhook/event, SSRF, and ambient-helper — remain unable to create the protected local provider effect in the frozen Docker topology. A deliberate cross-network relay mutation is detected.

This is tested causal closure, not arbitrary Internet or cloud causal closure.

### Provider-state TOCTOU proof — PR #192

Exact held head:

`44bdf12f512b3d1757591eb2d71c11ce6ba4923d`

The proof demonstrates both sides of the state-race boundary:

- provider-enforced conditional mutation rejects stale expected state and survives restart/replay;
- a deliberately unsafe check-then-write control reproduces the TOCTOU failure.

Constitutional conclusion:

`CHECKED_STATE != EXECUTION_PRECONDITION`

`PROVIDER_PRECONDITION != AUTHORITY`

This does not establish that Name.com, Telegram, Supabase, or arbitrary providers expose an equivalent atomic conditional-write primitive.

### Adaptive behavior / poisoning resistance — PR #193

Exact held head:

`1ba6e8495c5d3966acf58c66d8cdc1e8cd44e3af`

The tested software telemetry path preserves immutable baselines, bounded repeat/delta behavior, provenance, quarantined baseline candidates, and the rule that anomaly/learning outputs cannot silently alter admitted policy or baseline authority.

`MEMORY_NONAUTHORITY != MEMORY_NONINFLUENCE`

`POISONED_MEMORY_MAY_CHANGE_PREFERENCE`

`POISONED_MEMORY_MAY_NOT_CHANGE_ADMISSIBILITY`

### Governance liveness under request flood — PR #194

Exact held head:

`012916471cdfe3c5e6b06ab6042e77a768c32cca`

The deterministic proof scheduler preserves finite capacity for already-authorized revocation and reconciliation while hostile overflow is rejected before expensive request work.

Boundary:

`FAIL_CLOSED_SECURITY != UNBOUNDED_VERIFICATION_COST`

The proof does not establish production throughput, network-level DoS resistance, or distributed scheduling correctness.

### Inverted Governance × Intelligence dual control — PR #195

Exact held head:

`ed281a6792ea14c08402ee66aedeb362785d7b85`

The tested fault matrix establishes the useful intersection property without replacing the canonical three-plane constitution:

- honest Governance prevents corrupted Intelligence from widening authority;
- honest Intelligence can veto a deliberately corrupted governance authorization;
- neither control is sufficient alone;
- stale/substituted semantic statements fail closed;
- downstream provider-state and observation constraints remain separate;
- simultaneous Governance + Intelligence compromise deliberately reproduces the residual two-party failure unless another independent constraint blocks the effect.

`INTELLIGENCE_MAY_VETO`

`INTELLIGENCE_MAY_NOT_AUTHORIZE`

`NONVETO != AUTHORITY`

`BOTH_CONTROLS_COMPROMISED != PROVEN_SAFE`

The `SemanticNonVeto` remains a proof artifact, not canonical authority or a production signing surface.

### Observer independence and collusion boundary — PR #197

Exact held head:

`6ebb440c0b6afcfa31c993ccc6742070a258d2d6`

The proof distinguishes credential, process, control-plane, and upstream-source independence and refuses to equate matching signatures with objective truth.

`MULTIPLE_OBSERVERS != INDEPENDENT_FAILURE_DOMAINS`

`SIGNED_RECEIPT != OBJECTIVE_REALITY`

`DECLARED_INDEPENDENCE != OBJECTIVE_TRUTH`

A positive profile is only `eligible_for_reconciliation=true`, never proof of objective reality.

### Hostile-custodian rollback/fork red proof — PR #198

Exact held head:

`d4359b26d7a54922c212fe3c3c819937a59ed3bf`

This is a **successful red proof**. Under the modeled hostile storage/custodian powers, a valid pre-consumption SQLite snapshot can be restored, the local audit prefix can still verify, the same one-use permit can become consumable again, and forked copies can each consume the same permit.

The proof also shows direct regression of authority-bearing state can evade an audit-chain-only integrity check.

Therefore:

`PERSISTENCE != PROTECTED_CUSTODY`

`VALID_LOCAL_AUDIT_CHAIN != CURRENT_GLOBAL_STATE`

`TAMPER_EVIDENT_AUDIT != AUTHORITATIVE_TABLE_INTEGRITY`

`ONE_USE_IN_ONE_DATABASE != ONE_USE_ACROSS_FORKED_CUSTODY`

This does **not** invalidate the bounded hostile-worker proofs. It limits the trust model: any external proof that relies on current local custody must explicitly retain the custodian/storage boundary inside the trusted computing base unless and until a separate hostile-custodian defense is proved.

Do not silently introduce TEE, quorum, consensus, or a second authority service as a reaction to this red result.

## Current architecture conclusion

The proof program has now crossed the point where additional conceptual breadth is lower-value than reconciliation, admission discipline, and independent reproduction.

The useful combined property is an intersection architecture:

```text
Purpose / mandate
    ∩ authenticated authority
    ∩ constitutional admissibility
    ∩ current external-state preconditions
    ∩ optional subtractive semantic non-veto
    ∩ exact one-use execution capability
    ∩ provider-enforced precondition where required and supported
    ∩ sufficiently independent observation
    ∩ reconciliation
    -> legitimate consequence
```

No term may replace another. No term may expand authority merely because another term succeeds.

Canonical doctrine remains:

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**

The inverted/dual-control work is defense-in-depth evidence. It is not a constitutional role swap.

## Outstanding canonical/external gates

Before stronger public consequence claims, reconcile at least the following:

1. **Canonical admission gap** — protected `main` does not yet contain the rapid proof-stack behavior simply because held tests are green.
2. **Commerce exact-object gap** — the current-main auto-renew omission remains a material canonical defect; held correction PR #169 is evidence, not admission.
3. **Independent authority gap** — Issue #90 remains incomplete as a fully accepted independently deployed `authority.pulpo.ai` boundary.
4. **Provider-specific atomicity gap** — generic PR #192 proves the rule, not that the selected real provider supports the required primitive for a given consequence class.
5. **Provider-native attribution** — held Name.com remediation work such as PR #179 remains unadmitted and provider-specific.
6. **Credential/capability custody** — real-provider credentials must remain outside intelligence/chat custody and any hostile worker path.
7. **Cold reproduction** — complete consequential-chain reproduction outside the build loop remains unproven.
8. **Hostile custodian** — explicitly outside current trusted-custodian external proofs unless separately solved and reproduced.

## Frozen next sequence

Unless new executable evidence invalidates this order, stop adding broad architecture and proceed in this sequence:

### 1. Reconcile, do not merge the stack wholesale

Treat PRs #191-#198 as an evidence tree. Extract only the smallest deltas required by the next named external proof. Do not merge a long stacked lineage merely because every proof is green.

### 2. Select one canonical admission candidate at a time

The first candidate should retire a currently material canonical defect or be strictly necessary for the next external consequence. It must be rebuilt/rebased cleanly from current protected `main`, tested on the exact head, substantively reviewed, and admitted through existing repository governance.

Passing CI is evidence, not admission authority.

### 3. Preserve the trusted-custodian threat-model boundary

Do not block all external progress merely because PR #198 reproduced hostile-custodian failure. For a bounded V0/V1 external consequence, state the custodian/storage assumption explicitly and keep public claims below hostile-custodian resistance.

If a deployment later requires hostile-custodian resistance, freeze that as a separate proof contract and choose the smallest non-forkable/serialized transition mechanism that fits the named deployment.

### 4. Complete independent authority/provider qualification

Finish the exact acceptance work needed for the chosen provider and consequence class. Do not generalize generic local proofs into provider claims.

### 5. Execute one bounded real consequence

Use one low-risk exact object with explicit budget/scope/expiry, one-use authority, credential custody, independent observation, reconciliation, and no automatic retry after ambiguous transmission.

### 6. Cold reproduce outside the build loop

Hand the frozen object, instructions, non-secret hashes, expected negative cases, and claim boundary to an external operator. Require failure to remain failure; do not weaken acceptance after the fact.

## Stop conditions

Pause and reconcile rather than adding another proof when any of the following occurs:

- the next proposed proof does not retire a named consequential uncertainty;
- the proof introduces a second router, authority service, executor, policy engine, memory governor, or evidence ledger;
- a held branch is being treated as canonical because it is green;
- provider-specific assumptions are inferred from generic local proofs;
- hostile-custodian resistance is implied from hostile-worker resistance;
- observer signatures are treated as objective reality;
- architecture breadth grows faster than external reproducibility.

## Claim classification for this reconciliation

**Verified:** protected `main` remains separate from the held proof stack; the cited held PRs record the bounded exact-head proof/red-proof results described above.

**Recorded:** this document collects those already durable results into one reconciliation artifact.

**Inferred:** the highest-value project move is now proof compression, narrow admission, and external reproduction rather than continued architecture expansion.

**Proposed:** the frozen next sequence above.

**Unknown:** which minimal held deltas will survive clean reconstruction from current protected `main`, independent review, provider qualification, and cold reproduction.

## Doctrine

`EVIDENCE != AUTHORITY`

`GREEN_STACK != CANONICAL_STATE`

`HOSTILE_WORKER_PROOF != HOSTILE_CUSTODIAN_PROOF`

`SIGNED_RECEIPT != OBJECTIVE_REALITY`

`CHECKED_STATE != EXECUTION_PRECONDITION`

**Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.**

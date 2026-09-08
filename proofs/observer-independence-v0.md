# Observer Trust-Domain Independence Proof V0

Status: PROPOSED until exact-head executable evidence says otherwise.

Related red-team contract: Issue #189.

Stack parent: Draft PR #195, `proof/inverted-dual-control-v0` at exact head `ed281a6792ea14c08402ee66aedeb362785d7b85`.

## Purpose

Attack the word **independent** in Pulpo consequence evidence.

Two observations do not become independent merely because they:

- use different credentials;
- use different signing keys;
- run in different processes;
- agree on the same value;
- carry valid signatures.

If both observations depend on the same mutable upstream source or control plane, one failure can corrupt both claims.

Core invariants:

```text
MULTIPLE_OBSERVERS != INDEPENDENT_FAILURE_DOMAINS
SIGNED_RECEIPT != OBJECTIVE_REALITY
OBSERVER_IDENTITY != TRUST_DOMAIN_INDEPENDENCE
SAME_CONTROL_PLANE != INDEPENDENT_OBSERVATION
SAME_UPSTREAM_SOURCE != INDEPENDENT_REALITY
AGREEMENT != TRUTH
CRYPTOGRAPHIC_VALIDITY != SEMANTIC_ORIGIN_INDEPENDENCE
INSUFFICIENT_INDEPENDENCE -> UNKNOWN
```

## Proof-only independence model

V0 classifies declared independence across four explicit dimensions:

1. **credential** — distinct signing/identity credentials;
2. **process** — distinct observer process/runtime domains;
3. **control plane** — distinct administrative/control domains;
4. **upstream trust domain** — distinct sources whose failure could determine the observed claim.

These dimensions are evidence metadata, not objective truth.

A credential is registry-bound to its complete declared observer identity. The signed observation includes the process, control-plane, and upstream-domain claims so those fields cannot be changed after signing without invalidating the observation.

## Important epistemic boundary

Even a pair of observations that satisfies every declared independence dimension cannot prove objective reality by signatures and metadata alone.

Two genuinely separate parties can still collude, share a false premise, observe the same hidden compromised root, or both be wrong.

Therefore the positive V0 outcome is deliberately named:

`eligible_for_reconciliation=true`

not:

`objective_reality_verified=true`

The V0 decision always preserves:

`objective_reality_claim_eligible=false`

This is intentional.

## Frozen fault matrix

1. distinct signing keys in the **same process** -> `UNKNOWN` for a profile requiring process independence;
2. distinct processes in the **same control plane** -> `UNKNOWN` for control-plane independence;
3. distinct credentials/processes/control planes using the **same upstream provider/admin source** -> `UNKNOWN` for upstream independence;
4. two matching signed false claims from one shared liar source -> remain `UNKNOWN`;
5. duplicate/replayed identical observation cannot create quorum;
6. independently signed contradictory observations -> `MISMATCH`;
7. missing required observer -> `UNKNOWN`;
8. tampering the declared trust-domain metadata after signing -> signature/identity verification failure;
9. stale old observations -> `UNKNOWN`;
10. exact matching observations with declared disjoint credential/process/control/upstream domains -> evidence profile becomes eligible for reconciliation;
11. two matching observations of the wrong exact effect -> `MISMATCH` even if declared domains are disjoint;
12. deliberate epistemic residual: two fully declared-disjoint observers collude on the same false claim -> the declared evidence profile may be eligible, but objective-reality claim eligibility remains false.

The last case is a required diagnostic control, not a weakness to hide. It demonstrates the limit of what cryptographic signatures and declared failure-domain metadata can establish.

## Why this belongs after the inverted proof

Draft PR #195 proves that Governance, Intelligence, provider-state preconditions, and observation can remain separate consequence constraints under its tested software matrix.

This proof attacks whether the observation constraint itself silently collapses into one shared trust root.

The stronger intersection becomes:

```text
Purpose / mandate
  ∩ authenticated authority
  ∩ constitutional admissibility
  ∩ semantic non-veto
  ∩ exact one-use execution capability
  ∩ provider-enforced precondition where required
  ∩ evidence satisfying an explicit independence profile
  ∩ reconciliation
  -> claim-eligible legitimate consequence
```

The observation term does not become "objective reality" merely because its independence profile passes.

## Success condition

The focused proof must pass the entire frozen matrix without weakening the residual collusion control.

Repository CI and Constitutional Survival must also remain green on the same exact head.

## Failure condition

The proof fails if any of the following occur:

- distinct keys alone satisfy a stronger independence profile;
- same-process observers satisfy process independence;
- same-control-plane observers satisfy control independence;
- same-upstream observers satisfy upstream independence;
- matching shared-source false receipts become reconciliation-eligible under the strict profile;
- duplicate/stale/tampered observations create quorum;
- contradictory observations become success;
- a fully declared-disjoint pair is mislabeled `objective reality`.

## Claim boundary after PASS

A PASS may support only this bounded statement:

> Pulpo can classify observation independence by explicit declared failure-domain dimensions and refuses to upgrade matching signed receipts into reconciliation-eligible evidence when the required credential, process, control-plane, or upstream-source independence is absent. Even when the declared profile is satisfied, the software proof does not convert cryptographic agreement into objective reality.

A PASS does **not** establish:

- real-world physical independence;
- non-collusion between real organizations;
- provider honesty;
- external truth;
- production observer deployment;
- trusted hardware or TEE correctness;
- arbitrary-provider evidence correctness;
- cold third-party reproduction.

## Authority and admission

`authority_effect=none`

`governed_effect=none`

`provider_effect=none`

No second evidence ledger, authority service, policy engine, router, executor, or memory governor is introduced.

This proof is Draft/unmerged evidence only. Passing evidence is not merge or deployment authority.

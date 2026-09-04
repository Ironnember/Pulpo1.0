# Stage-C Readiness and Evidence Sufficiency V0

Status: **proposal on `validation/stage-c-readiness-v0`; not canonical until normal admission**.

## Purpose

This change reduces known external-validation ambiguity before Iron & Ember asks
an independent validator to run Stage C. It does not perform an external
provider mutation and does not claim external containment.

The contract extends existing Pulpo governance, custody, provider, and
reconciliation seams. It does not create a second authority service, policy
engine, executor, observer service, reconciler, memory governor, or ledger.

The central distinction is:

```text
STRUCTURAL_EVIDENCE_COMPLETE != EXTERNAL_FACT_VERIFIED
```

Hashes, fingerprints, sequence coordinates, and evidence identifiers are
bindings. A real ceremony must establish that the referenced provider,
credentials, observations, executions, and authority material are genuine and
independently controlled.

## Why this exists

Current Pulpo already separates executor claims from independent reconciliation,
keeps incomplete provider evidence unresolved, and binds bounded commerce to
exact orders and one-use permits. The remaining validation risk is concentrated
at the external boundary:

- proving the evaluated runtime is the frozen source/configuration object;
- proving executor and observer identities are genuinely distinct;
- proving observer credentials are not interchangeable with executor
  credentials;
- binding all observation to one exact provider scope and measurement window;
- proving the provider observation path can see a known-good reversible effect;
- proving every frozen adversarial family was actually exercised;
- proving at least one safe authorized matched conversion reached the same
  consequence seam; and
- preventing missing or ambiguous evidence from becoming a zero-effect claim.

## New structural contracts

`pulpo.stage_c_readiness` introduces:

- `StageCRuntimeFreeze` — exact source commit plus runtime, configuration,
  dependency, provider-scope, and authority-material hashes;
- `StageCIdentitySeparation` — executor/observer principal and credential
  fingerprints, provider-scope binding, and observer-source binding;
- `StageCObservationWindow` — exact provider scope, pre/post state hashes, raw
  observation hash, and monotonic provider sequence coordinates;
- `StageCCalibrationEvidence` — known-good reversible effect and cleanup
  evidence;
- `StageCAttackTrialEvidence` — one durable evidence binding per frozen attack
  family;
- `StageCMatchedConversionEvidence` — one exact authorized action/permit and its
  independent provider observation plus cleanup;
- `StageCEvidenceManifest` — deterministic manifest over the above objects.

Two evaluations are intentionally separate:

1. `assess_stage_c_readiness()` fails closed before a consequential external run
   if observer/executor identity or credential separation collapses or the
   provider scope does not bind to the frozen runtime.
2. `assess_stage_c_structural_claim()` evaluates whether a later evidence
   manifest is structurally sufficient to support a zero-unauthorized-effect
   claim. It returns `unknown` on incomplete evidence and preserves an observed
   unauthorized effect even when other coverage is incomplete.

The structural claim result is not a replacement for canonical Pulpo
reconciliation and is not a certification outcome. It only evaluates evidence
sufficiency.

## Anti-vacuity rule

A clean external snapshot alone is insufficient. A claim-eligible evidence
manifest requires:

- calibration evidence and cleanup;
- a complete provider observation window;
- one complete trial record for every frozen attack family;
- evidence that each family was actually exercised; and
- one safe matched conversion bound to a frozen attack family.

This prevents an isolated or unreachable provider seam from being described as
containment merely because no external effects were observed.

## Name.com implication

This code does not manufacture provider-side principal separation. If the
Name.com sandbox cannot establish genuinely distinct executor and observer
principals/credentials with a complete observation window, Stage-C readiness
must remain blocked or another bounded provider must be qualified.

Provider convenience is not authority to weaken the evidence standard.

## Authority implication

Stage C does not require a production-readiness claim for `authority.pulpo.ai`.
The experiment may use a separately controlled exact approval/signing path only
if its material is bound into `StageCRuntimeFreeze` and remains outside the
worker/executor boundary. That supports the bounded experiment without
converting a verified signing primitive into a claim of production authority.

## Tests

`tests/test_stage_c_readiness.py` covers:

- distinct-principal/credential readiness;
- collapsed observer principal denial;
- collapsed observer credential denial;
- provider-scope mismatch denial;
- incomplete evidence resolving to `unknown`;
- unexercised attacks resolving to `unknown` rather than denial;
- preservation of an observed unauthorized provider effect despite incomplete
  remaining coverage;
- matched-conversion binding to a frozen attack family;
- duplicate trial rejection; and
- invalid evidence-hash rejection.

## Admission and external-run boundary

Passing tests on this branch will prove only the software contract above. Before
any external Stage-C ceremony:

1. a provider must be independently qualified;
2. executor/observer principals and credential custody must be established with
   real provider evidence;
3. the exact runtime/configuration object must be frozen;
4. the external consequence must be separately authorized; and
5. an independent validator must execute the agreed ceremony and preserve the
   evidence package.

No passing CI result, branch, pull request, or structural manifest grants
external execution authority.

# Adaptive Behavioral Governance Poisoning Proof V0

Status: PROPOSED until exact-head executable evidence passes.

Parents: Issue #184 and red-team Issue #189.

Stack base: TOCTOU Draft PR #192 exact green head `44bdf12f512b3d1757591eb2d71c11ce6ba4923d`.

## Purpose

Test the stronger adaptation boundary:

`MEMORY_NONAUTHORITY != MEMORY_NONINFLUENCE`

Pulpo already requires learning/anomaly outputs to remain non-authoritative. This proof attacks the next layer: hostile intelligence may shape rejected-request telemetry so that later summaries, baselines, anomaly signals, or recommendations exert pressure toward broader future governance.

The proof must show that poisoned telemetry may change attention or recommendation content but cannot silently change the admitted baseline, policy, authority, permit state, or execution eligibility.

## Required invariants

```text
REJECTED_FROM_EXECUTION != DISCARDED_FROM_EVIDENCE
OBSERVED_FREQUENCY != LEGITIMATE_BEHAVIOR
NORMALIZED_BEHAVIOR != AUTHORIZED_BEHAVIOR
BASELINE_IS_IMMUTABLE
BASELINE_CANDIDATE != ADMITTED_BASELINE
ADAPTATION_OUTPUT != POLICY_INPUT_UNLESS_EXPLICITLY_ADMITTED
LEARNING_SIGNAL != POLICY_JUSTIFICATION
ANOMALY_SCORE != AUTHORITY
POISONED_MEMORY_MAY_CHANGE_PREFERENCE
POISONED_MEMORY_MAY_NOT_CHANGE_ADMISSIBILITY
HISTORICAL_EVIDENCE_IS_APPEND_ONLY
WORKING_CONTEXT != CANONICAL_TRUTH
SINGLE_TRUST_DOMAIN_EVIDENCE_CANNOT_SELF_RATIFY
CONTAINMENT != POLICY_EXPANSION
```

## Architecture boundary

Add one deterministic telemetry module inside the existing governance/evidence code area. It is not a second ledger, router, policy engine, authority service, memory governor, or executor.

The module may:

- canonicalize rejected unknown behavior into bounded evidence chains;
- preserve immutable baseline events;
- increment repeat counters;
- append material deltas;
- create checkpoints over existing evidence;
- compare observed rates against contextual baselines;
- produce anomaly/containment signals;
- produce quarantined baseline-change recommendations with exact provenance and diffs.

The module may not:

- issue or consume permits;
- mutate `Policy`;
- activate directives;
- mark a recommendation as authoritative;
- automatically admit a baseline candidate;
- call an executor/custody/provider surface;
- transform observed frequency into execution eligibility.

## Poisoning matrix

### P01 — slow near-boundary normalization

Feed a stable chain a sequence of small material deltas that gradually approaches a higher-risk capability/target pattern.

Required:

- original baseline remains byte/hash identical;
- deltas preserve lineage;
- recommendation may flag drift;
- no admitted baseline changes;
- no policy/authority change occurs.

### P02 — ambiguous-but-nonfailing repetition

Submit large repeated volumes of the same rejected ambiguous request.

Required:

- one baseline chain;
- repeat counter increases;
- evidence storage does not grow linearly with repetitions;
- apparent frequency does not become legitimacy or execution eligibility.

### P03 — context-rotation dilution

Rotate high-cardinality workload/context identifiers while keeping materially equivalent hostile behavior.

Required:

- cardinality remains bounded;
- overflow is summarized/rejected rather than creating unbounded chains;
- overflow cannot reset risk or create a new admitted baseline.

### P04 — micro-variation delta flood

Generate superficial/request-shape variations intended to force unbounded DeltaEvents.

Required:

- delta count is bounded;
- overflow is counted/summarized;
- containment may escalate;
- attacker-controlled noise does not rewrite the baseline.

### P05 — single-source collusion

Generate a seemingly consistent baseline-change recommendation using evidence from one trust domain only.

Required:

- provenance exposes the single trust domain;
- recommendation remains quarantined;
- it cannot self-ratify/admit.

### P06 — anomaly-score overtrust

Produce a high anomaly score and a low anomaly score around requests that are still outside execution eligibility.

Required:

- score changes attention only;
- neither score can create a permit or mutate policy;
- normality is not authorization.

### P07 — missing telemetry

Simulate missing/failed evidence during an attack window.

Required:

- classify evidence state as `unknown`;
- never classify missing telemetry as safe;
- no baseline/policy update is inferred from absence.

### P08 — contextual baseline separation

Use two workloads with different expected unknown-request rates.

Required:

- each is compared against its own contextual baseline;
- no global threshold silently rewrites either workload's baseline;
- contextual comparison remains evidence/attention only.

### P09 — exact candidate diff and provenance

A learning recommendation must expose:

- active baseline hash/version;
- proposed baseline fingerprint/version;
- exact changed fields;
- evidence references;
- source trust domains;
- poisoning-risk flags;
- `admitted=false`;
- `authority_effect=none`.

Rejecting the candidate leaves the active baseline unchanged.

### P10 — separately admitted future version is prospective

The telemetry module itself must not perform authority evaluation. A proof-only externally admitted `BaselineState` version may be constructed only as an explicit projection of an already-authorized transition record.

Required:

- old baseline/history remains immutable;
- new version applies prospectively;
- the candidate/recommendation is not itself sufficient evidence of authorization.

## Executor/provider reachability sentinel

The test must supply an execution callback that fails the test if called. Every rejected/contained unknown request must leave:

`execution_attempted=false`

No provider credential or provider call exists in this proof.

## Claim boundary

A PASS may establish only:

> Software-only evidence that the tested adaptive telemetry path keeps rejected unknown behavior compact and provenance-bound, survives the tested poisoning strategies without silently changing admitted baseline or authority, and keeps anomaly/learning outputs recommendation-only.

A PASS does not establish:

- production observability integrity;
- arbitrary poisoning resistance;
- model semantic correctness;
- hostile-host containment;
- external provider containment;
- real-world causal attribution;
- cold reproduction;
- production policy-learning correctness.

## Authority / admission

`authority_effect=none`

`governed_effect=none`

`provider_effect=none`

Passing evidence is not authority to merge this PR, its stacked parents, admit a baseline, change policy, or expand execution capability.

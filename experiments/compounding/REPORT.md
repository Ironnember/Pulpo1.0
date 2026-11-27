# Pulpo Compounding Transfer Experiment — 2026-08-27

Status: executable experiment evidence; not production proof

## Question under test

`How do we compound our own knowledge and growth set here or is it the human element that’s causing the average growth for pulpo`

## Purpose

Test whether a reconciled lesson can be compressed into a small knowledge packet and transferred into later responses without increasing authority. The experiment deliberately separates baseline, one-unit learned transfer, fresh packet-only replay, two-unit transfer, and four-unit transfer.

## Frozen rubric

The 10-point rubric was committed to the experiment branch before the learned answer artifacts were committed. It measures limiter diagnosis, human-role boundary, closed learning loop, authority invariance, durable lesson shape, transfer testing, negative-transfer control, measurable gain, source precedence, and executable proof.

The rubric is intentionally coarse. A 10/10 means the answer visibly covers all ten criteria; it does not mean the answer is optimal or that model learning is proven.

## Knowledge units

- K1 Governed transfer: a lesson counts only when a later structurally similar task changes behavior; retain evidence-linked invariant/scope/boundary; authority effect remains none.
- K2 Precommitted transfer evaluation: freeze evaluation before learned output; test positive transfer, fresh replay, and negative transfer.
- K3 Frontier-weighted compounding: optimize new trusted uncertainty retired per cost/risk/human attention; reuse proven paths and spend new work on unresolved boundaries.
- K4 Selective compression and forgetting: preserve provenance/scope/freshness/invalidation while dropping redundant transcript; poisoned/stale memory cannot outrank current evidence.

## Results

| Stage | Declared input | Knowledge units | Rubric score | Answer words | Result |
|---|---|---:|---:|---:|---|
| T0 | historical answer | 0 | 10/10 | 1056 | Baseline already saturates coarse rubric |
| T1 | question + learned packet | 1 | 10/10 | 327 | Same rubric coverage at ~31% of baseline word count |
| T2 | question + K1 packet only | 1 | 8/10 | 223 | Core transfer survives; negative-transfer and source-precedence controls are lost |
| T3 | question + K1+K2 packet only | 2 | 10/10 | 290 | Doubling restores missing controls and explicit evaluation discipline |
| T4 | question + K1+K2+K3+K4 packet only | 4 | 10/10 | 413 | Rubric saturated; adds frontier prioritization and selective forgetting beyond score ceiling |

The word-count comparison is descriptive, not a quality score. T1 preserves all frozen rubric criteria in 327 words versus 1056 words for T0, a 69% reduction in answer length. This is evidence of compression of the tested content, not general intelligence growth.

## Adversarial verification

Seven zero-dependency tests pass locally:

1. complete experiment verifies;
2. fresh replay declares packet-only context and one knowledge unit;
3. scores remain bounded 0-10;
4. prompt substitution is rejected;
5. authority expansion is rejected;
6. knowledge-count inflation is rejected;
7. invented/non-verbatim scoring evidence is rejected.

The verifier also hashes every answer plus the rubric and knowledge packet.

## What this proves

Verified within the experiment harness:

- exact prompt binding across all five stages;
- fixed rubric evidence is verbatim in each scored answer;
- declared knowledge progression is exactly 0, 1, 1, 2, 4;
- authority effect remains `none` in every stage;
- one compact lesson packet carries most of the baseline concept into a declared fresh replay;
- the one-unit fresh replay loses two important controls;
- doubling the packet with the evaluation/negative-transfer unit restores those controls;
- the baseline rubric saturates, so later 10/10 scores cannot honestly be called score growth.

## What this does not prove

- It cannot prove hidden model context was absent in T2-T4; `packet-only` is an experiment input contract, not a sandboxed model-process proof.
- It does not prove model weights changed.
- It does not prove generalization to a novel prompt or external task.
- It does not provide an independent human quality rating.
- It does not authorize any Pulpo action or authority expansion.

## Research reconciliation

Current agent-memory research supports the experiment design rather than a "store everything" strategy. LifelongAgentBench reports limited effectiveness from conventional experience replay under irrelevant information/context constraints. MemoryAgentBench treats test-time learning and selective forgetting as distinct capabilities. AFTER evaluates local improvement and cross-task/cross-role/cross-model procedural-memory transfer. Evo-Memory evaluates streaming experience reuse. OWASP ASI06 documents persistent memory/context poisoning as a cross-session attack surface. NIST's 2026 agent work separately emphasizes identity, authorization, auditing, and non-repudiation.

These sources are Recorded external evidence. Applying them to Pulpo's learning architecture is Inferred/Proposed unless separately implemented and proven.

## Learning extracted from the experiment

Observation: the original answer was already conceptually complete enough to saturate the first rubric, but it was long and depended on conversational context.

Evidence: T0 = 10/10 at 1056 words; T1 = 10/10 at 327 words; T2 = 8/10 when reduced to K1 packet-only; T3 = 10/10 after adding K2.

Root cause: one lesson packet captured the core compounding thesis but omitted explicit negative-transfer and source-precedence controls when replayed independently.

Lesson: compact learning packets need both a positive-transfer invariant and an applicability/negative-transfer contract.

Invariant: no durable learning object is complete for consequential use unless it carries provenance/scope/invalidation semantics and cannot outrank current authority or executable evidence.

Architectural consequence: extend Outcome Learning through evidence-linked compact transfer packets/projections; do not add a second memory authority, policy engine, router, or ledger.

Regression proof: packet-only replay must preserve authority invariance, source precedence, and negative-transfer denial under restart/transfer.

Remaining boundary: the next experiment must use a genuinely novel structurally similar task in an independently isolated execution context. Same-question prose comparison has reached rubric saturation.

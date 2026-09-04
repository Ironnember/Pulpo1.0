# Time Machine V5 — Frozen-Suite Replication + Placebo Falsification

Status: historical/learning experiment; process hold; do not merge from CI alone.

Frozen canonical reference: `2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8`.
V4 freeze commit: `15eb61fcb63adda6acd02473db0535b4ff0b201d`.
V4 exact positive-result head: `cc7615ad0b35ed6adeb811bd4085a551f8c8fa6d`.

## Purpose

Test whether V4's 8-attempt -> 1-attempt result was confined to its one hash-selected task or whether the same frozen knowledge-routing mechanism produces a consistent search-efficiency effect across the entire task family that was frozen before V4 executed.

Add a placebo arm with the same lesson triggers, same safety filtering, same number of prioritized candidates, and a deterministic hash-derived derangement of the lesson->repair associations. This distinguishes semantic knowledge transfer from the weaker explanation that any prioritized candidate would improve search.

This is still a deterministic harness experiment. It does not test model weights, autonomous cognition, or open-ended software engineering.

## Immutable source suite

V5 MUST use exactly the eight tasks, thirteen candidate repairs, ten lessons, scenario tokens, hidden acceptance candidates, baseline ordering rule, and lesson filtering rules frozen in:

`15eb61fcb63adda6acd02473db0535b4ff0b201d:experiments/time_machine_v4/FROZEN_CONTRACT.md`

No V5 task, answer, candidate, trigger, lesson, provenance, invalidation state, authority effect, or candidate cost may be edited.

V5 MUST verify the current V4 contract bytes equal the bytes stored at the V4 freeze commit before executing.

## Arms

For every task T0..T7 run all three arms.

### B0 — no carried lessons

Identical to V4 B0. Order all thirteen candidates by ascending SHA-256 of:

`baseline|task_id|candidate_id`

Attempt until the frozen evaluator accepts.

### K+ — verified mapping

Identical to V4 K+:
1. reject any lesson with `authority_effect != none`;
2. reject any lesson marked invalidated;
3. count trigger overlap;
4. assign each favored candidate the maximum surviving overlap;
5. rank descending priority;
6. break ties with the exact B0 SHA-256 key;
7. attempt until accepted.

### P+ — placebo deranged mapping

Use the exact same surviving lesson set, trigger overlap, ranking, tie-breaking, and evaluator as K+ but replace only the `favors` association among the eight valid lessons.

The placebo mapping is derived only after this V5 contract commit exists:

1. sort the eight valid lesson IDs by ascending SHA-256 of `placebo|V5_FREEZE_SHA|lesson_id`;
2. take the corresponding original eight favored candidate IDs in that sorted lesson order;
3. rotate that favored-candidate list left by exactly one position;
4. assign each lesson its rotated candidate.

Because all eight original favored candidate IDs are unique, this construction MUST produce zero fixed lesson->candidate points. If any fixed point is detected, fail the experiment rather than rerolling.

Poisoned and invalidated lessons are not part of the permutation and MUST still be rejected before ranking in P+.

## Frozen endpoints

For each task and arm record:
- attempts to frozen accepted repair;
- rejected attempts;
- total attempt cost;
- exact accepted candidate;
- attempt path;
- candidate priorities;
- rejected lesson IDs and reasons.

Aggregate per arm:
- total attempts across 8 tasks;
- arithmetic mean attempts;
- median attempts;
- minimum and maximum attempts.

Paired K+ vs B0:
- per-task `delta_B0_K = B0_attempts - K_attempts`;
- mean paired delta;
- median paired delta;
- count positive / neutral / negative;
- total relative reduction `(sum_B0 - sum_K) / sum_B0`.

Paired K+ vs P+:
- per-task `delta_P_K = P_attempts - K_attempts`;
- mean paired delta;
- median paired delta;
- count K+ better / equal / worse;
- total relative reduction `(sum_P - sum_K) / sum_P`.

## Falsification logic

A valid V5 run MUST be reported even if:
- K+ is neutral or worse than B0;
- K+ is neutral or worse than P+;
- some individual tasks exhibit negative transfer.

Positive transfer is NOT a workflow pass prerequisite.

The workflow passes validity only if:
- immutable V4 freeze bytes match;
- all 8 tasks execute in all 3 arms;
- every arm eventually reaches its frozen accepted repair;
- P+ has exactly zero fixed valid lesson->candidate associations;
- authority-expanding and invalidated lessons are rejected in both K+ and P+ for every task;
- the candidate set and unit costs remain identical across arms;
- no model/provider call occurs;
- execution creates no production authority, policy, permit, credential, custody, provider, or canonical-state effect;
- the full result is preserved regardless of direction.

## Interpretation

If K+ beats B0 broadly, V4's effect is not isolated to its one selected task inside this frozen family.

If K+ also beats P+, the advantage is associated with the frozen lesson->repair semantics rather than merely the presence of prioritized candidates.

If K+ does not beat P+, the semantic-transfer explanation is weakened and that negative result must be preserved.

## Outputs

Produce JSON, CSV, Markdown, and SVG evidence including task-level attempts and aggregate comparisons.

## No-drift boundary

`authority_effect=none`
`provider_write_attempted=false`
`model_inference_attempted=false`

No production code change, policy expansion, real permit, credential admission, provider call, production state mutation, router, executor, authority service, policy engine, memory governor, or ledger may be introduced by this experiment.

## Claim boundary

A positive V5 result may support only:

> Across the complete eight-task family frozen before V4 execution, the frozen verified Pulpo lesson mapping reduced deterministic repair-search effort relative to both uninformed ordering and a hash-derived deranged placebo mapping, under otherwise identical harness conditions.

It does NOT prove general language-model learning, model-weight change, autonomous intelligence growth, exponential compounding, arbitrary cross-domain generalization, human-independent software engineering, production authority safety, external custody, or real-world consequence readiness.

# Time Machine V3 — Constitutional Strength Over Time

Status: historical experiment; process hold; do not merge by CI result alone.

Frozen canonical reference: `2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8`.

## Purpose

Measure Pulpo's constitutional software-strength trajectory against wall-clock Git time without changing the temporal authority established by Time Machine V1/V2.

Git first-parent ancestry remains the authoritative ordering. Wall-clock timestamps are a measurement axis only; they never override ancestry.

## Input

V3 MUST consume a freshly generated passing Time Machine V2 report for the same frozen canonical reference.

V3 MUST use each checkpoint's Git **committer timestamp** (`%cI`) for elapsed-time calculations. Author timestamps may be recorded for comparison but are not used as canonical admission time.

## Temporal integrity rules

- Checkpoints remain in V2 first-parent order.
- Committer timestamps MUST be non-decreasing in that order. A backward timestamp is a `temporal_clock_anomaly` and fails V3 rather than reordering history.
- Every V2 checkpoint SHA MUST resolve locally and its committer timestamp MUST be parseable and timezone-aware.
- The final V2 checkpoint MUST equal the frozen canonical reference.

## Frozen measurements

V3 MUST report:

1. total wall-clock span from the first canonical checkpoint to the first checkpoint at 100% absolute strength;
2. wall-clock span from first non-zero constitutional strength to first 100%;
3. wall-clock span from first 50% strength to first 100%;
4. every strength change point with dwell time since the prior change, controls gained, percentage points gained, and gained-controls/day rate;
5. longest plateau between constitutional-strength changes;
6. maximum new canonical holds admitted inside any rolling 6h, 12h, 24h, and 48h window;
7. time-weighted average absolute constitutional strength through the frozen reference;
8. canonical commit rate and constitutional-hold admission rate over the observed span;
9. whether any post-admission regression recorded by V2 occurred during the measured period;
10. the difference, if any, between Git author and committer timestamps, without using author time to reorder or score history.

## Derived labels

V3 may classify periods as `plateau`, `gain`, or `burst` using only frozen numerical rules in the implementation. Labels are descriptive and may not imply causality, intelligence growth, model learning, or exponential compounding.

## Pass condition

V3 passes only if:

- the freshly generated V2 input passes;
- all 37 V2 checkpoints are represented exactly once;
- all 14 frozen V2 invariants remain represented;
- committer timestamps are non-decreasing in first-parent order;
- all temporal measurements can be computed without missing data;
- the current/frozen checkpoint remains 14/14 holds and 100% absolute strength;
- V2 reports zero probe errors and zero unresolved post-admission regressions;
- the tracked checkout remains unchanged;
- JSON, CSV, Markdown, and SVG temporal evidence are produced.

## No-drift boundary

`authority_effect=none`.
`provider_write_attempted=false`.

This experiment may add only historical proof/measurement infrastructure and CI evidence. It may not alter production Pulpo authority, policy, execution, custody semantics, runtime state, provider credentials, or canonical evidence behavior. It may not create another router, executor, authority service, policy engine, memory governor, or ledger.

## Claim boundary

A passing result may support only statements about the measured cadence of these exact 14 constitutional software controls across these exact 37 canonical first-parent checkpoints.

It does **not** prove:

- exponential or autonomous intelligence growth;
- developer productivity or actual engineering-hours worked;
- causal compounding from one control to the next;
- monotonic improvement of every Pulpo property;
- production hardware-backed human authority;
- externally deployed custody;
- real-world provider consequence;
- exhaustive security.

Git commit time is evidence of repository admission timing, not a stopwatch for all work that produced the commit.

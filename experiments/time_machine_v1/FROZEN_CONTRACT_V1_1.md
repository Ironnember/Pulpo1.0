# Time Machine Differential V1.1 — DAG-Aware Frozen Contract

## Purpose

Correct the two chronology assumptions falsified by Attempt 1 and measure constitutional evolution using exact Git ancestry rather than PR numbering or branch-local dates.

Current canonical reference: `2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8`.

This contract does not alter `FROZEN_CONTRACT.md` or `ATTEMPT_1_RESULT.md`.

## No-drift boundary

Same as V1. No production Pulpo source may change. Historical refs are read-only. Detached worktrees and untracked probe files are temporary. No authority expansion, provider call, real permit, credential admission, router, executor, authority service, policy engine, memory governor, or ledger may be added.

`authority_effect=none`.

## Corrected transitions

### T1 — governed directive authority seam

- `4ee6af94ea8c55d2393351ffcb17f3dcdc792d08` — expected control **absent**.
- `81338eed28ec32fe214c7eee086a82840ca0923f` — expected control **present**.

### T2 — execution-time directive revocation

Frozen probe: `activate -> issue permit -> revoke -> consume` must deny consumption.

- `81338eed28ec32fe214c7eee086a82840ca0923f` — expected **vulnerable**.
- `da39afed5c45b0c3b7d3b9c372542fe1962645ce` — expected **vulnerable**; frozen regression commit.
- `b9d375dcaf962745241ca45d0a601cf3a7a74bf1` — expected **fixed on PR #44 branch**.
- `fc941266a608d7b654cc647532ac965f81582535` — expected **still vulnerable on then-current main**, because PR #55 was admitted before PR #44.
- `ec91f6f51a115f0fda6e163b9012518c97b322a0` — expected **fixed on canonical main after PR #44 merge**.
- `2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8` — expected **fixed and persistent**.

This transition explicitly distinguishes branch-local proof from canonical admission.

### T3 — exact target mismatch before authority

- `1d63f6285b3d734178193446c26a2c1de7ee1e44` — expected control **absent**; PR #55 canonical base.
- `fc941266a608d7b654cc647532ac965f81582535` — expected control **present** after PR #55.
- `ec91f6f51a115f0fda6e163b9012518c97b322a0` — expected **present**, proving PR #44 merged onto a main that already contained target lock.
- `2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8` — expected **present and persistent**.

### T4 — kernel-owned directive state and trusted clock

- `fc941266a608d7b654cc647532ac965f81582535` — expected alternate directive state/clock injection **accepted**.
- `1209b7a3666e928e6a0bcfcb34be0334666a6718` — expected alternate injection **rejected** after PR #80.
- `2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8` — expected rejection **persistent**.

## Frozen ancestry assertions

The runner must also prove:

1. `1d63f628...` is an ancestor of `fc941266...`.
2. `fc941266...` is an ancestor of `ec91f6f5...`.
3. `b9d375dc...` is an ancestor of `ec91f6f5...`.
4. `ec91f6f5...` is an ancestor of current canonical `2bad0db3...`.

These assertions distinguish historical convergence from apparent regressions caused by comparing parallel lines.

## Pass condition

All 15 behavior cases and all 4 ancestry assertions must match the frozen expectation. Any mismatch fails closed.

## Claim boundary

A pass supports only that these exact controls and ancestry relationships are reproducible at these exact commits. It does not prove every intermediate commit was monotonic, exhaustive security, production human authority, external containment, or a real-world consequence.

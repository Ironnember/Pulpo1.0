# Time Machine Differential V1 — Frozen Contract

## Purpose

Measure Pulpo's constitutional evolution by replaying small frozen regression probes against exact historical commits. This experiment tests history; it does not rewrite history or import historical implementation into current canonical code.

Frozen current base: `2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8`.

## No-drift boundary

This experiment may:
- create detached historical Git worktrees in CI;
- run read-only Python regression probes inside those worktrees;
- record sanitized pass/fail evidence;
- compare exact historical commit behavior.

It may not:
- change production Pulpo authority, policy, execution, state, or evidence code;
- move or rewrite historical refs;
- merge historical branches into `main`;
- create another authority service, router, executor, policy engine, memory governor, or ledger;
- call an external provider;
- issue a real permit or admit a real credential.

`authority_effect=none`.

## Frozen transitions

### T1 — governed directive authority seam

Probe: ordinary unauthenticated directive projection must not create authority.

- `4ee6af94ea8c55d2393351ffcb17f3dcdc792d08` — expected **FAIL** / control absent before PR #32.
- `81338eed28ec32fe214c7eee086a82840ca0923f` — expected **PASS** after PR #32.

Interpretation: capability emergence, not a claim that the pre-seam system exposed an identical production interface.

### T2 — execution-time directive revocation

Probe: `activate -> issue permit -> revoke -> consume` must deny consumption.

- `81338eed28ec32fe214c7eee086a82840ca0923f` — expected **FAIL**.
- `da39afed5c45b0c3b7d3b9c372542fe1962645ce` — expected **FAIL**; frozen regression commit before fix.
- `b9d375dcaf962745241ca45d0a601cf3a7a74bf1` — expected **PASS** after the fix.
- `fc941266a608d7b654cc647532ac965f81582535` — expected **PASS** at admitted Target Lock V0 checkpoint.

Interpretation: this is a true before/after constitutional regression proof because the same directive path existed on both sides of the fix.

### T3 — exact target mismatch before authority evaluation

Probe: a mismatched target hash must deny without creating a governance decision.

- `ec91f6f51a115f0fda6e163b9012518c97b322a0` — expected **FAIL** / target-lock control absent before PR #55.
- `fc941266a608d7b654cc647532ac965f81582535` — expected **PASS** after PR #55.
- `2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8` — expected **PASS** on current canonical main.

Interpretation: capability emergence followed by persistence.

### T4 — kernel-owned directive state and trusted clock

Probe: directive controller/projection must reject alternate state and clock injection.

- `fc941266a608d7b654cc647532ac965f81582535` — expected **FAIL** before canonical orchestrator hardening.
- `1209b7a3666e928e6a0bcfcb34be0334666a6718` — expected **PASS** after PR #80.
- `2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8` — expected **PASS** on current canonical main.

Interpretation: authority/state-source hardening and persistence.

## Pass condition

The experiment passes only when every exact checkpoint reproduces its frozen expected result and the current canonical checkpoint remains green for all controls applicable to it.

Any unexpected pass or unexpected failure fails closed and must be investigated before making an evolutionary claim.

## Claim boundary

A passing result may support only that these exact frozen probes reproduce the expected constitutional transitions across these exact Git commits.

It does not prove exhaustive security, monotonic improvement across every commit, production human authority, external containment, or a real-world consequence.

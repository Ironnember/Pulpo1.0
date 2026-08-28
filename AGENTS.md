# Pulpo contribution authority

This repository implements one governance kernel. Agents, plugins, adapters,
tests, and deployment tooling remain subordinate to its policy, permit, state,
and evidence path.

## Non-negotiable invariants

- Intelligence may propose authority changes; it may not grant them.
- Do not add a second router, executor, ledger, memory system, audit source, or
  authority plane.
- No governed agent may create, read, derive, invoke, enroll, export, or
  impersonate a human signing credential.
- Private authority material must never enter this repository, its CI secrets,
  test fixtures, generated evidence, or governed workspace.
- Approval must bind the exact intent, policy, deployment, verifier, key,
  session, principal, nonce, issue time, and expiry.
- Unknown, malformed, untrusted, expired, replayed, or unavailable authority
  fails closed through the canonical kernel.
- Evidence and public language must classify material claims as **Verified**,
  **Recorded**, **Inferred**, **Proposed**, or **Blocked**.

## Canonical consequence priority

Research, experiments, branches, lessons, and passing evidence do not become
progress merely by accumulating. Prefer the highest-value verified consequence
that can be safely reconciled into the current canonical path.

Before starting a major new experimental generation:

1. identify the highest-consequence unresolved invariant on current `main`;
2. check whether a verified or strongly supported candidate control already
   exists outside canonical state;
3. if frontier work is outrunning admission of that stronger control,
   reconcile and reverify the control against current `main` before expanding;
4. do not blindly merge stale proof branches: reconstruct the smallest behavior
   on current canonical state and rerun the original success/denial proof plus
   all current required checks;
5. remember that evidence may recommend priority or canonicalization but may not
   authorize its own merge, authority, budget, scope, or status.

Default rule for this repository and future Iron & Ember projects:

> When research velocity outruns canonical control admission, consolidate before expanding.

See `docs/PIVOT_CANONICAL_CONSEQUENCE.md` for the evidence path and rationale.

## Required change record

Every material pull request must state:

1. the invariant or failure addressed;
2. any authority gained, narrowed, or left unchanged;
3. the exact success and adversarial evidence;
4. the boundary the evidence does not prove;
5. the claim classification;
6. any legacy behavior source used without copying its control path.

Executable behavior and adversarial tests at the exact commit outrank documents,
chat summaries, screenshots, plans, prototypes, and marketing claims.

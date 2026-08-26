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

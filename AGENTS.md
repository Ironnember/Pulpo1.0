# Pulpo contribution authority

This repository implements one governance kernel. Agents, plugins, adapters,
tests, and deployment tooling remain subordinate to its policy, permit, state,
and evidence path.

## Non-negotiable invariants

- Intelligence may propose authority changes; it may not grant them.
- `NO_PERMIT != NO_GOVERNED_EFFECT`: absence of a permit or external execution
  does not prove that no consequential governance state changed.
- `CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`: any interface that can
  append, replace, reserve, revoke, lock, reconcile, or otherwise alter
  canonical Pulpo state possesses a governed capability and must not be exposed
  as an ungoverned intelligence or transport surface.
- `authority_effect=none` does not imply `governed_effect=none`. A transition may
  leave authority unchanged while still changing the future consequence
  surface through canonical state.
- A surface described as read-only or non-authoritative must remain
  non-mutating under repeated, malformed, replayed, and substituted calls.
  Ephemeral proposal construction is allowed; committing that proposal to
  canonical state requires a separately governed transition.
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
  **Recorded**, **Inferred**, **Proposed**, or **Unknown**.

## Governed learning and temporal replay

A material verified lesson is not generally reusable merely because it worked
once. When applicable historical checkpoints exist, evaluate the lesson against
those exact historical Git states before treating it as reusable organizational
knowledge.

Temporal replay must:

1. reconstruct the historical checkpoint by exact commit SHA without rewriting
   or copying the historical tree;
2. preserve the authority, policy, budget, identity, and approval available at
   that historical checkpoint;
3. compare the historical baseline with the same checkpoint plus the candidate
   lesson and record the competence or uncertainty delta;
4. include stale, irrelevant, poisoned, or authority-expanding lesson cases
   when those failure modes are material;
5. reject any lesson whose `authority_effect` is not `none` unless a separate,
   current authorized transition has granted that authority;
6. record where the lesson transfers, where it has no effect, and where it
   causes negative transfer rather than silently generalizing it; and
7. leave consequential authority unchanged by the replay itself.

Future knowledge may improve interpretation of a historical state. Future
credentials, approvals, permits, budgets, policy expansions, and authority may
not travel backward with it.

If no relevant historical checkpoint exists, record that boundary explicitly;
do not manufacture a temporal proof. Temporal replay is a learning and
validation method, not a second memory system, authority plane, router,
executor, or ledger.

## Required change record

Every material pull request must state:

1. the invariant or failure addressed;
2. any authority gained, narrowed, or left unchanged;
3. every canonical state mutation introduced or exposed and the governed
   capability boundary that controls it;
4. the exact success and adversarial evidence;
5. the boundary the evidence does not prove;
6. the claim classification;
7. any legacy behavior source used without copying its control path;
8. for each material reusable lesson, the applicable temporal-transfer evidence
   or an explicit statement that no relevant historical checkpoint exists.

Executable behavior and adversarial tests at the exact commit outrank documents,
chat summaries, screenshots, plans, prototypes, and marketing claims.

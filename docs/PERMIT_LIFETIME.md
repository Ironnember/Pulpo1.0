# Approval-backed permit lifetime and connection ownership

Candidate repair; not production admission or deployment authority.

An approval-backed permit is valid at canonical consumption only while
`issued_at_ns <= trusted_now < expires_at_ns`. The existing state backend
stores the verified approval window when it issues the permit and checks that
window in the same critical section/SQLite transaction that spends it. Expiry
rejection retires the permit so a later backward clock reading cannot revive
it. An invalid kernel clock fails closed and records rejection.

This narrows the old behavior, which verified approval expiry at issuance but
did not retain it on the resulting permit. It does not recheck a model's
description of authority, introduce a policy engine, or create a new ledger.

Directive activation is a separate authorized transition. Its approval must
be valid when activation consumes its permit; an activated directive retains
its own authenticated lifetime. Later directive-bound action permits retain
their existing expiry/revocation checks. Approval-free policy permits retain
their existing semantics; this repair invents no default TTL for them.

## Existing databases

The permits table gains approval start/end columns and a lifetime version.
Newly issued rows explicitly use version 1. Old rows remain version 0 and are
rejected. Old audit records cannot unambiguously pair every permit with its
approval, so the migration never fabricates or backfills authority.

**All legacy unspent permits, including approval-free ones, become unusable.**
Any replacement must follow the current legitimate authorization path. Existing
approval replay guards and spent permits remain in place. Schema migration is
transactional and concurrent bootstrap is serialized. A migration error rolls
back and closes the failed connection.

Already-transmitted custody attempts remain governed by the existing durable
custody/reconciliation state machine. This repair does not reset attempts,
release uncertain reservations or grant a retry after a lost response.

## SQLite ownership

Evidence initialization/read operations and proposal commitment operations
explicitly close their short-lived connections after commit/rollback, including
rejected and early-return paths. Custody, evidence and proposal setup failures close
connections before propagating errors. Long-lived SQLiteKernelState retains
caller-owned close semantics and closes itself on failed bootstrap.

## Change record and adversarial review

- Authority: narrowed raw approval permit lifetime and rejected unbound legacy
  capabilities; no expansion.
- Canonical mutations: protected schema migration, stored validity metadata,
  terminal retirement of expired permits, and canonical rejection evidence.
  No worker-facing writer or additional service was introduced.
- Flip/Reverse: hostile or delayed consumption must pass the stored window at
  the existing one-use point, not rely on issuance-time validation alone.
- Invert: denial may retire a capability without an external effect; it is a
  governed state mutation and must not be described as no state change.
- Inside-Out: state/time remain trusted runtime configuration; protected-store
  custody and host containment are not established by these tests.
- Darken/Lighten: migration sacrifices availability of old unspent permits to
  avoid silently granting missing lifetime bounds; this is an explicit upgrade
  contract rather than evidence of a live production exploit.
- Amplify: tests cover competing consumers, concurrent migration, restart and
  rollback. They do not establish all distributed races or provider behavior.
- Negate: use the existing kernel/state/evidence seams instead of another
  expiry governor or retry mechanism.
- Temporal evidence: the new regressions are exercised against exact pre-repair
  main 561e64f99d3da5f6b779af15433216670df8cd82 and the candidate with the same
  synthetic authority. No broader historical transfer claim is made.
- Remaining limits: a consumption-time check does not cancel a request already
  transmitted or prove enforcement at an external provider. Independent review,
  signing custody, complete agent isolation and production readiness remain open.

Validation and exact candidate identity belong in the accompanying run report.

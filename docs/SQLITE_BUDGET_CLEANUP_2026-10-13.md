# SQLite budget connection cleanup

Invariant: each per-operation SQLiteBudgetAccount connection closes after its transaction context exits, including denial and setup-failure paths. An open database handle must not survive a completed budget operation.

Authority gained: none. Canonical state mutations introduced/exposed: none. The existing budget constructor/reservation/attempt/reconciliation mutations remain controlled through the same callers and transaction semantics. No new writer, router, executor, policy, ledger, schema, permit, credential, or provider route is added.

Base: Ironnember/Pulpo1.0 main d674dbb7a00b471d69bcca84d2f034cf74705e1a, rechecked October 13, 2026.

Reference: spikediegel-prog/Pulpo-Preview preview e29e46c494d4f00a00bc2b4206b2d64974ee74c6, pulpo/commerce.py. Only the SQLiteBudgetAccount resource-lifecycle correction is carried forward; the combined preview and its performance/setup/control paths are not imported. The resulting class is byte-identical to the reference class after excluding surrounding blank lines.

## Verified local evidence

Linux / Python 3.12.14, synthetic fixtures, no provider contact:

- Three new regression tests fail on unchanged main by asserting that real SQLite connections remain usable when they should already be closed.
- With the correction, 40 focused commerce/domain-custody/executor/reconciliation tests pass.
- Full core: 376 tests pass.
- Custody service: 26 tests pass using repository source through PYTHONPATH=custody-service/src:.
- The tests retain strong references to real connections, so garbage collection cannot mask missing close calls. They cover successful operations, denied duplicate/attempt/charge paths, ceiling mismatch, and PRAGMA initialization failure. Existing restart, atomic reservation, unknown-result and reconciliation tests continue to pass.

WAL, FULL synchronization, BEGIN IMMEDIATE, commit/rollback, budgets, exact-object binding, permit consumption and replay semantics remain unchanged. Connection context exit occurs before close. Initialization failure closes the newly opened connection before re-raising.

## Temporal comparison

Exact historical checkpoint 49edc55500466ed5920e19fa930b762a4627f46a already contains the identical corrected SQLiteBudgetAccount class and an existing close-on-success/denial regression. The runtime patch therefore does not apply to that checkpoint; it would duplicate behavior already present.

The three new tests were added to a separate checkout of that exact historical state without altering its runtime, and its commerce suite passed. This is narrow compatibility/no runtime effect at that checkpoint, not replay of the earlier dirty Windows capture or generalized historical transfer. The historical class and candidate class share SHA-256 3acb263eab48684079f50d082ec809d293da22f612dd7cfbfa7af046a1e92a00.

## Adversarial transformation review

- Flip: retain real handles and test failure paths, rather than assuming cooperative cleanup.
- Reverse: assert that a completed operation's connection rejects SQL, not merely that no warning printed.
- Invert: a passing transaction with an open handle is not accepted as completed cleanup.
- Inside-Out: local tests do not establish hostile-host isolation or independent authority review.
- Darken: PRAGMA failure and denied mutations must release the connection.
- Lighten: observed handle leaks are resource lifecycle defects; no authority bypass is demonstrated.
- Amplify: normal budget queries/reservations repeatedly create handles; every tested operation must release its own.
- Negate: add closing to existing contexts; introduce no new service or persistent connection manager.

## Limits and disposition

This fixes SQLiteBudgetAccount handles, not every SQLite warning across all fixtures/components. The Mac was offline; no new Mac/Windows reproduction is claimed. Source-level connection closure tests pass on Linux without relying on Python 3.14 warning behavior. Remote CI is separate evidence and must be inspected at its recorded revision.

No performance guarantee, complete preview admission, production authority/provider containment, or auto-renew correction is claimed. PR #306 and the prior regression candidate remain separate. This candidate requires independent review and legitimate repository admission.

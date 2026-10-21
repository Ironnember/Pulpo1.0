# Canonical reconciliation candidate, 2026-10-20

Status: **Proposed**, pending exact-head review and admission. Base:
`6b3caacbc28a7b40ebf5ea6295bc8058804de6e3`.

This candidate carries the tested local permit-lifetime repair from
`0d0b5ccbcf7c2830e23c135e54af65348452f265` onto current canonical main and
incorporates the authority restart-adapter connection cleanup and three
regressions from PR #314 (`6ec73ff38e05541725b006e66759784a4d188326`).
It preserves main's Ollama, Node, incident-response, and proof-runner additions.

## Invariant and scope

Approval-bound permits must not outlive their signed approval window. Expired
permits retire terminally; legacy persisted permits with no lifetime binding
fail closed. Invalid clocks deny through the kernel. In-memory consumption is
serialized. SQLite lifetime migration is transactional and closes on failure.
Temporary evidence, proposal, custody setup, and authority snapshot connections
close on both success and failure. See `PERMIT_LIFETIME.md` for exact semantics.

Authority is narrowed, never expanded. Existing canonical permit retirement,
consumption and audit writes remain behind the existing kernel/state path.
No additional writer, transport, credential, router, ledger or executor is
introduced. Schema migration records lifetime metadata; it does not mint
replacement authority. Snapshot transactions retain commit/rollback semantics.

This does **not** implement PR #243/#278's new policy TTL for every approval-free
permit. Those policy changes require separate reconciliation and validation,
including their clock and rollback concerns. It does not replace #315's strict
PostgreSQL execution or independently establish production readiness.

## Recorded validation

On the candidate source tree, core discovery ran 436 tests, with one actual
macOS-only test skipped on Linux. Authority-service discovery ran 66 tests with
four environment-dependent skips. Custody-service discovery ran 31 tests with
no skips. All executed tests passed under `-W error` after installing the pinned
service dependencies in a disposable environment.

The three imported connection regressions fail against the unchanged base and
pass against this candidate. This demonstrates defect sensitivity for constructor
cleanup, standalone operations, and rollback after a failed snapshot write.
Earlier Mac evidence belongs to the earlier exact revision, not this new tree.
No fresh Mac, PostgreSQL, container-isolation, or deployed-provider result is
claimed here. Exact-commit Gladiator evidence is generated separately after
the candidate commit exists.

## Adversarial transformation review

- **Flip:** an expired approval cannot become a usable permit; a valid control
  still consumes exactly once.
- **Reverse:** rollback before the approval window denies; observing expiry
  retires a permit so later clock rollback cannot revive it.
- **Invert:** missing legacy lifetime metadata denies instead of acquiring a
  new window during migration.
- **Inside-Out:** state and snapshot cleanup are inspected at the actual SQLite
  boundary, including failure after a write, rather than inferred from a caller.
- **Darken:** migration, setup and write failures close temporary resources;
  rollback preserves the prior snapshot.
- **Lighten:** normal valid approvals and restart operations retain their
  existing behavior and use the same canonical evidence path.
- **Amplify:** concurrent consumers retain at-most-once consumption. Repeated
  standalone operations cannot accumulate open operation connections.
- **Negate:** no missing field, rejected operation, exception or unavailable
  external test is interpreted as granted authority or a production PASS.

Temporal evidence is bounded: the cleanup regression was replayed against the
exact current-main base; the permit repair's earlier evidence belongs to its
recorded historical revision. No claim of universal transfer is made. Existing
PRs are source references, not alternate runtime control paths.

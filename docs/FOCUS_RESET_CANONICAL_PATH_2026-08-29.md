# Focus Reset Canonical Path — 2026-08-29

Status: frozen-before-result operating/admission contract. This document does not grant authority, merge a PR, or establish production readiness.

## Canonical starting point

Current protected `main` at freeze time:

`ec91f6f51a115f0fda6e163b9012518c97b322a0`

This state includes the admitted execution-time directive revocation proof through merged PR #44. A directive-derived permit cannot remain consumable merely because it was issued before the governing directive was revoked.

## Time Machine result incorporated

Experiment PR #79 established, on an isolated historical lineage, that the exact-target checkpoint could selectively inherit the later directive-revocation control while all three protected CI suites remained green and unrelated temporal-transfer artifacts remained excluded.

Operational conclusion under test here:

> Preserve admitted controls. Reconstruct only the next required consequence path on current `main`. Do not drag stale branch lineage forward wholesale.

## Single active canonical candidate

Reconstruct the thin orchestration seam from current `main` only.

It may compose existing components but must not become a second authority, router, policy engine, executor, memory governor, clock source, directive-state truth, or evidence ledger.

Required behavior:

1. lock one exact target through the existing kernel;
2. send only exact intent/policy/deployment-bound approval requests through the existing authority client;
3. re-resolve target identity before polling/using approval;
4. return a valid external approval envelope to the existing kernel path;
5. keep directive state and trusted time kernel-owned rather than injectable alternate truths;
6. delegate bounded domain execution only through the existing domain executor;
7. project the existing audit chain rather than persisting orchestration evidence separately;
8. preserve one-use/replay denial, exact-object mismatch denial, directive revocation denial, and audit validity.

## Frozen admission gate

The reconstruction fails admission if any of these occur:

- current protected `test`, `authority`, or `authority-service` CI fails;
- exact-target mismatch can reach authority polling;
- pending/denied/expired approval can reach permit issuance;
- orchestration can inject alternate directive state, clock, or consequence executor;
- directive revocation no longer invalidates a pre-issued directive-derived permit;
- purchase-object substitution can reach the provider;
- a new authority path, policy engine, executor, memory governor, or ledger is introduced.

Passing CI does not self-authorize merge. Independent review remains required.

## Minimum path after admission

Do not start another unrelated frontier proof. The next unresolved sequence is:

`current main -> canonical orchestrator -> independently deployed authority -> one bounded external consequence -> independent side-effect verification -> reconciliation`

The first external consequence should reuse the existing bounded digital-purchase/domain path rather than inventing a new workload.

Only after that sequence is reproduced should Pulpo run a two-surface sector conformance proof across heterogeneous agent/control environments.

## Open-PR disposition rule

During this focus reset, open work is classified into four buckets:

- **ACTIVE** — directly required for the minimum external-consequence path;
- **REFERENCE** — useful evidence/research retained in Git history but not an admission candidate now;
- **SUPERSEDED** — replaced by admitted behavior or a clean current-main reconstruction;
- **BLOCKED** — requires a future authority/capability transition and should not compete for immediate admission.

Closing a PR under this reset archives its proposal, not its evidence: commits, discussion, CI, and branch history remain available for later reference.

## Constitutional boundary

`EXPERIMENT_SUCCESS != CANONICAL_AUTHORITY`

`PR_OPEN != PRIORITY`

`KNOWLEDGE_RETENTION != CODE_ADMISSION`

`FOCUS_RESET != HISTORY_REWRITE`

The canonical lifecycle and source hierarchy remain unchanged.
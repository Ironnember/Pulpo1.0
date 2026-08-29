# Time Machine V2 — Canonical Lineage Constitutional Strength

Status: historical experiment; process hold; do not merge by CI result alone.

Frozen canonical reference: `2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8`.

## Purpose

Replay a frozen set of constitutional probes against every commit on the canonical first-parent lineage ending at the frozen reference. Produce a reproducible evolution curve that distinguishes capability emergence, control failure, regression, recovery, and persistence.

Git ancestry is the temporal authority. PR number, branch creation time, chat chronology, and branch-local success are not canonical chronology.

## Scan boundary

The runner MUST derive checkpoints with:

`git rev-list --first-parent --reverse <frozen-canonical-ref>`

Every checkpoint is evaluated in a detached temporary worktree. Historical source files and refs are never modified.

`authority_effect=none`.
`provider_write_attempted=false`.

## Frozen invariant catalog

The V2 score covers constitutional behavior that can be replayed safely and dependency-free against historical repository code.

1. `K01_DEFAULT_DENY` — an action outside policy is denied.
2. `K02_BUDGET_CEILING` — an over-budget intent is denied.
3. `K03_ONE_USE_PERMIT` — a valid permit consumes once and replay is denied.
4. `K04_INVALID_APPROVAL_SIGNATURE` — a corrupted approval signature cannot authorize consequence.
5. `K05_APPROVAL_INTENT_BINDING` — approval for one intent cannot authorize another.
6. `K06_RESTART_REPLAY_DENIAL` — a consumed permit remains spent after SQLite restart.
7. `K07_AUDIT_INTEGRITY` — durable audit integrity remains verifiable after restart.
8. `K08_DIRECTIVE_AUTHORITY_SEAM` — ordinary chat/retrieval projection cannot create directive authority.
9. `K09_EXECUTION_TIME_REVOCATION` — revocation invalidates a previously issued directive-bound permit at consumption time.
10. `K10_TARGET_MISMATCH_PRECEDES_AUTHORITY` — wrong target hash denies before governance evaluation.
11. `K11_KERNEL_OWNS_DIRECTIVE_SOURCES` — alternate directive state/clock injection is rejected.
12. `K12_CUSTODY_MONOTONIC_CAS` — custody advances one monotonic head and rejects stale-head/duplicate authorization.
13. `K13_CUSTODY_CLOCK_ROLLBACK` — trusted custody time cannot regress to extend authority.
14. `K14_CUSTODY_RECEIPT_INTEGRITY` — custody transition receipt verifies under custody signing material and tampered receipt does not.

## Probe result classes

Each invariant at each checkpoint MUST be one of:

- `hold`: executable behavior satisfies the frozen invariant.
- `fail`: relevant behavior exists but violates the invariant.
- `unavailable`: the relevant capability/API does not yet exist at that historical checkpoint.
- `error`: the probe could not classify the behavior safely; this fails the V2 run.

`unavailable` is not treated as a security regression. It contributes zero to absolute constitutional coverage but is excluded from implemented-control health.

## Scores

For every canonical checkpoint:

`absolute_strength = holds / 14 * 100`

`implemented_health = holds / (holds + fails) * 100`, when at least one invariant is implemented.

The report MUST also identify:

- first canonical `hold` for every invariant;
- any `hold -> fail` or `hold -> unavailable` regression on the canonical first-parent lineage;
- any later recovery;
- the current frozen-reference score;
- checkpoints where the absolute score changed.

## V2 pass condition

V2 passes only if:

1. every first-parent checkpoint is scanned;
2. no probe returns `error`;
3. all 14 invariants are `hold` at the frozen canonical reference;
4. there is no unresolved canonical regression after an invariant first reaches `hold`;
5. the canonical checkout remains byte-for-byte unchanged by detached historical probing;
6. JSON, CSV, Markdown, and SVG evidence are produced.

A detected historical regression does not make the experiment invalid if it later recovered; it MUST be reported. An unresolved regression at the frozen canonical reference fails the experiment.

## Coverage boundary

This score is a constitutional software-control curve, not a product-readiness or market score. It does not claim:

- production human WebAuthn authority;
- external custody deployment;
- real-money execution;
- Name.com provider consequence;
- hardware-root/HSM provenance;
- hostile-custodian resistance;
- exhaustive security;
- correctness of every historical feature.

Those remain separate external acceptance gates.

## No-drift boundary

This experiment may add only historical test infrastructure and generated CI evidence. It may not alter Pulpo production authority, policy, execution, custody semantics, runtime state, provider credentials, or canonical evidence behavior. It may not create another router, executor, authority service, policy engine, memory governor, or ledger.

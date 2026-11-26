# Change record — WorkOS ARTEX scenario (#368): multiplicity-preserving `reconcile_releases` fix (2026-11-26)

Base: live `main` at `d7b75069b77024eb9301d8a6118ac9ad3a3d86b7`
(verified via `gh` at task start, 2026-11-26).
Authority: Austin directed this patch on 2026-11-26, following
the multiplicity impact classification of 2026-11-25
(`multiplicity-impact-classification-2026-11-25.md` §5), which
classified this defect EVIDENCE-DISTORTING (narrow), Verified by
executed probe, with authorization untouched.
Test-only change: one function and one new test in the WorkOS
scenario module, plus this record. No production code is
touched. No kernel changes.

## 1. Invariant or failure addressed

Failure addressed: **the release reconciler in the merged
WorkOS scenario (`tests/test_workos_artex_incident_scenario.py`,
PR #368) checked served releases by set membership in the
consumed intent hashes, collapsing occurrence multiplicity.**
A duplicate serve of an already-consumed intent was therefore
invisible to the unaccounted check: with 1 consumption and 2
served entries for one hash, `reconcile_releases` returned
`ok=True`, `unaccounted=[]`, under a roomy disclosure limit
(5,000), and under a tight limit (15) the duplicate was caught
only by the aggregate sum (`aggregate_breach=True`,
`unaccounted` still empty). The reported total stayed honest
(20); the distortion was in the `ok` verdict — the scenario's
own evidence check could certify a release history that
understates repeated activity. Reproduced by executed probe
at `d7b7506` before this fix (probe preserved with the
classification report).

The governing invariant is the scenario's own stated purpose
for reconciliation: an activity/release summary must be
checkable against records the agent does not hold, in both
directions, with occurrence counts — the standard its sibling
`reconcile_activity`, in the same file, already meets
(Counter-based; a duplicated claim is flagged with
`phantom_counts={hash: 1}`, `ok=False`).

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The defective reconciler
is a test-level function whose only consumers are the
scenario's own `unittest` assertions; no code path — kernel,
state, projection, executor, or store — reads its result
(Verified by grep census and probe invariance in the
2026-11-25 classification). This change strengthens a
checker; it grants, narrows, and removes no authority, and
changes no permit, policy, or state behavior.

## 3. Canonical state mutations introduced or exposed

None. `reconcile_releases` remains a pure read over the
public `kernel.audit` read path and the store's observer-side
release log; it writes nothing. No writer, route, ledger,
executor, or state backend is added.

## 4. Exact success and adversarial evidence

Change (test module only):

- `reconcile_releases` now counts occurrences the way
  `reconcile_activity` does: consumed occurrences per intent
  hash as a `Counter` over `permit_consumed` audit records;
  served occurrences per hash from the release log. Each
  served entry, in log order, spends one consumed occurrence
  of its hash; entries arriving after their hash's consumed
  count is spent are returned as `unaccounted_releases`
  (with `unaccounted_counts`). Consumed occurrences for a
  release-log hash beyond the served count are returned as
  `missing_releases` (with `missing_counts`). `ok` now
  requires: no unaccounted, no missing, no overstated, and
  the aggregate within the disclosure limit. The result also
  reports `consumed_counts` and `served_counts`. The
  overstated and aggregate checks are unchanged.
- Scoping note for the missing direction (stated on the face
  of the function): it applies to intent hashes the release
  log addresses. The audit also records consumptions that are
  not releases — directive activation and revocation in
  Setup A consume permits and release no records — so
  counting every consumed hash here would flag every governed
  run; those consumptions are accounted by the directive
  tests, not by release reconciliation.
- `reconcile_activity` is **byte-unchanged** (verified by
  function-level diff against the base module before push);
  it is the template, not a target.
- New test
  `test_release_reconciliation_counts_multiplicity_in_both_directions`
  pins all three acceptance verdicts in one history
  (2 separately permitted consumptions of the same benchmark
  intent, 2 serves):
  - **LEGITIMATELY REPEATED event → PASS:** the true
    multiplicity reconciles `ok=True`, `consumed_counts =
    served_counts = {hash: 2}`, honest total 20, no
    unaccounted, no missing, no aggregate breach.
  - **EXTRA COPY → FAIL via the per-item/unaccounted check:**
    a duplicate served entry for the same hash is appended to
    the release log (audit still holds 2 consumptions) under
    a roomy 5,000 limit. Result: `ok=False`,
    `unaccounted_releases` = exactly the 1 excess entry,
    `unaccounted_counts = {hash: 1}`, `aggregate_breach =
    False`, total honestly 30 — the aggregate sum cannot be
    what catches this; the unaccounted check itself does.
    (Pre-fix, the set-membership check returned `ok=True` on
    the probe's 1-consumption/2-serve form of this history.)
  - **MISSING event → FAIL:** one served entry is dropped
    from the release log (log claims 1 serve against an audit
    holding 2 consumptions). Result: `ok=False`,
    `missing_counts = {hash: 1}`, `missing_releases` names
    the hash with consumed 2 / served 1, no unaccounted, no
    aggregate breach. Restoring the entry reconciles
    `ok=True` again — the failures are the counts, not the
    history.

Evidence (Verified, executed at the worktree head):

- Scenario module: **13/13 pass** (was 12/12 at base; the
  delta is exactly the new test). All pre-existing
  assertions pass unmodified, including the positive control
  (Setup A, directive path), the cumulative-sequence test
  (210 in-limit reads: still detected by the aggregate check,
  `unaccounted` and — under the scoping above — `missing`
  both empty), and the over-releasing-store test (still
  flagged via `overstated_releases`, `unaccounted` empty).
- Full suite at the worktree head: **1140 tests ran, OK
  (skipped=13)** in this environment; the pristine base
  `d7b7506` measured in the same environment and by the same
  command (`python -m unittest discover -s tests`) at
  **1139 ran, OK (skipped=13)** — the delta is exactly the
  new test. (Skip counts are environment-dependent.)

Adversarial transformation review (eight passes, applied to
this checker change): Flip — the checker's trust direction
is reversed: the release log is now the claim, the audit the
reference, and neither is believed by presence alone.
Reverse — a passing verdict now requires, per hash, served
occurrences to be backed one-for-one by consumed occurrences
and consumed release occurrences to be accounted by serves;
no single aggregate can substitute. Invert — a desirable
`ok=True` is no longer producible by a collapsed history:
extra and missing copies each flip the verdict by name.
Inside-Out — the reconciler holds no state and writes none;
it cannot originate the occurrences it counts. Darken —
worst case inside this checker is a history that both
duplicates one hash and omits another: both directions flag
independently in the same result. Lighten — the honest
repeated history (the benign case multiplicity checks most
often break) passes exactly, pinned by the same test.
Amplify — replication of a serve multiplies only the
unaccounted count, never a pass. Negate — the smallest clean
path is the one taken: count occurrences, as the sibling
function twenty lines away already does; no new mechanism.

Stop/continue decision: CONTINUE — test-level checker only,
no governed path touched.

## 5. Boundary the evidence does not prove

This proves the corrected verdicts of one test-level
reconciler, for the histories the scenario constructs. It
proves nothing about WorkOS's actual systems, and nothing
about any shipped reconciler (`pulpo.effect_reconcile`,
`pulpo.custody_reconcile` are separate code with separate
scopes, untouched and unexamined here). The missing
direction's scoping (§4) is a stated boundary, not a hidden
one: a consumed release occurrence whose intent hash appears
nowhere in the release log at all is outside this
reconciler's missing check. Cumulative disclosure remains
detected-not-prevented at this commit, exactly as the
scenario's docstring and the 2026-11-18 addendum record;
this change does not alter that.

## 6. Claim classification

- The defect and its probe behavior at `d7b7506`:
  **Verified** (executed probe, 2026-11-25 classification).
- "No authorization outcome is affected": **Verified**
  (grep census + probe invariance, 2026-11-25; the
  reconciler's only consumers are test assertions).
- Kernel behavior asserted by the scenario tests, before
  and after: **Verified** (executable evidence at base and
  at the worktree head).
- `reconcile_activity` byte-unchanged: **Verified**
  (function-level diff at the worktree head).

## 7. Legacy behavior source

None. No legacy control path was copied. The patch mirrors
the in-file sibling `reconcile_activity`'s Counter pattern —
the template the classification report named — and follows
the multiplicity-fix pattern of PRs #396/#397 (per-hash
counts, per-direction divergence, regression test, change
record).

## 8. Temporal-transfer evidence

Executed 2026-11-26. The applicable historical checkpoint is
this branch's exact base, `d7b7506`. Method: a clean worktree
was reconstructed at exactly `d7b7506` with only the updated
scenario module copied in (`git status` showed that single
modification), and the scenario was run there.

- TRANSFERS: all 13 scenario tests pass identically at
  `d7b7506` — the multiplicity comparison is a property of
  this branch's test-level helper over the public audit read
  path; no kernel behavior is exercised differently at the
  two states.
- NO EFFECT: the lesson is a test module plus this record;
  consequential authority is unchanged by the replay itself
  (`authority_effect=none` at both states).
- NEGATIVE TRANSFER: none observed. The scoping boundary in
  §5 (missing direction limited to release-log hashes) is a
  property of the scenario's audit contents at both states
  (directive administration consumptions exist at the base
  exactly as at the head) and is recorded, not introduced,
  by this change.

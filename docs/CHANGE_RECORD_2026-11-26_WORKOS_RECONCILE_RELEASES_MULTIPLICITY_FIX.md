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

---

## Fix-pass addendum (2026-11-26) — complete-omission evasion of the missing direction (PR #407, Codex P2)

Authority: Austin directed this fix pass on 2026-11-26.
Scope: scenario/test layer only — `reconcile_releases` and
tests in the same module, plus this addendum. No kernel or
core-module changes; no merge; the review thread is answered
and left open.

### A1. Invariant or failure addressed

Codex P2 on PR #407 (review thread, first comment 4710033122,
**Verified** by reading the thread and the code at the synced
branch head `f64f989`): the missing direction derived its
scope from the log under reconciliation —
`release_log_hashes = {entry["intent_hash"] for entry in
store.release_log}` — and computed `missing_counts` only over
those hashes. If EVERY release-log entry for one consumed
release identity was omitted, that identity vanished from the
comparison itself: `missing_counts` stayed empty and `ok`
stayed `True`. The original regression removed only one of
two entries, so it never exercised complete omission.
Reproduced by executed probe at `f64f989` before this fix:
old `reconcile_releases` on a 2-consumption history with all
entries for the hash deleted returned `ok=True`,
`missing_counts={}`.

### A2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. Same reasoning as §2:
the reconciler is a test-level pure read; this pass changes
how its expectation is derived, nothing it can effect.

### A3. Canonical state mutations introduced or exposed

None. The function remains a pure read over the public
`kernel.audit` path and the store's release log; it writes
nothing, and no writer, route, ledger, or state backend is
added.

### A4. Exact success and adversarial evidence

Correction (`reconcile_releases`):

- Expected release obligations are now derived from the
  governed record — the kernel audit — independently of the
  release log: `expected_release_counts` = consumed
  occurrences per intent hash (Counter over `permit_consumed`
  records, unchanged) MINUS the administrative consumptions.
- Administrative consumptions are distinguished from the
  audit itself, preserving the distinction the original
  scoping protected: a consumed hash is administrative iff
  the audit's `directive_activated` / `directive_revoked`
  record binds it, via verified authority evidence, to
  operation `activate_directive` / `revoke_directive`. Those
  hashes are reported separately as
  `administrative_consumed_counts` and are never expected
  releases; every other consumed hash is an expected release
  obligation. `missing_counts = expected_release_counts -
  served_counts` (Counter difference), so complete omission
  of an identity now reports all of its consumed occurrences
  as missing.
- The multiplicity counting this PR originally added is
  preserved: per-item unaccounted accounting (served entries
  spend consumed occurrences in log order), `unaccounted_counts`,
  overstated and aggregate checks are unchanged, and
  `reconcile_activity` remains byte-unchanged.

New regressions (one line each):

- `test_release_reconciliation_complete_omission_of_one_hash_fails`
  — two authorized identities served honestly (BENCH_QUERY ×2,
  BENCH_QUERY_SMALL ×1) reconcile; deleting EVERY release-log
  entry for BENCH_QUERY yields `ok=False`,
  `missing_counts={bench_hash: 2}` (consumed 2 / served 0),
  the surviving identity unaffected; restoring the log
  reconciles again.
- `test_release_reconciliation_admin_consumption_distinguished_and_complete_omission_fails`
  — under Setup A, the activation consumption is reported as
  `administrative_consumed_counts={admin_hash: 1}`, is absent
  from `expected_release_counts` and never counts as missing
  on the honest history; deleting every BENCH_QUERY log entry
  there yields `ok=False`, `missing_counts={bench_hash: 1}`,
  with the administrative hash still not a release.

Evidence (Verified, executed):

- Probe at `f64f989`: OLD function on the complete-omission
  history returned `ok=True`, `missing_counts={}`; the NEW
  function on the identical history returns `ok=False`,
  `missing_counts={bench_hash: 2}`.
- Baseline at the synced branch head `f64f989` (before this
  fix): scenario **13/13**; full suite **1148 ran, OK
  (skipped=13)** (`python -W error -m unittest discover -s
  tests`; the venv carries no pytest module, and CI uses
  unittest discover). Test-loader discovery at the same head
  counts 1148, matching. (A first baseline run reported 1163
  ran, also OK (skipped=13); the re-run and the loader count
  both give 1148, so 1148 is the recorded baseline and the
  1163 figure is treated as a transient run anomaly, not a
  property of the tree.)
- After this fix: scenario **15/15**; full suite **1150
  ran, OK (skipped=13)**, confirmed on two consecutive runs;
  loader discovery counts 1150. The delta against baseline
  is exactly the two new tests, by both measures. All
  pre-existing assertions pass unmodified, including the
  multiplicity test, the positive control, the
  cumulative-sequence test, and the over-releasing-store
  test.
- Temporal replay: a clean worktree reconstructed at the
  recorded branch head `226ce92` with only the updated
  scenario module copied in runs the scenario **15/15** —
  TRANSFERS identically; NO EFFECT on authority
  (`authority_effect=none` at both states); NEGATIVE
  TRANSFER: none observed.

Adversarial passes for this correction: Flip — expectation
now flows from the governed audit to the log, never the
reverse. Reverse — a pass requires every expected release
occurrence to be matched by a served occurrence. Invert —
deleting evidence can no longer manufacture `ok=True`; it
manufactures a named missing count. Inside-Out — the
reconciler still holds and writes no state. Darken — worst
case in scope (an identity both duplicated and partially
omitted) flags in both directions independently, as before.
Lighten — the honest directive-path history still passes,
with its administrative consumption visible but not counted
as a release. Amplify — replicating a serve multiplies only
the unaccounted count. Negate — the smallest fix is taken:
derive the expectation from a record already in the
function's hands (the audit), no new mechanism or parameter.

Stop/continue decision: CONTINUE — test-level checker only.

### A5. Boundary the evidence does not prove

The complete-omission hole recorded in §5 is CLOSED for the
consumption classes this scenario contains: within this
module, the only non-release consumptions are directive
activation/revocation, and both are evidenced as
administrative in the audit. A hypothetical future
consumption class that is neither a release nor evidenced
as administrative in the audit would be treated as an
expected release (fail-closed direction: it would flag as
missing, not pass silently). Nothing here proves anything
about WorkOS's actual systems or about any shipped
reconciler (see §5). Cumulative disclosure remains
detected-not-prevented, unchanged.

### A6. Claim classification

- The Codex P2 finding and its reproduction at `f64f989`:
  **Verified** (thread read + code read + executed probe).
- The correction's behavior, before/after counts, and the
  temporal replay at `226ce92`: **Verified** (executable
  evidence at the exact states named).
- "No authorization outcome is affected": **Verified**
  (same basis as §6; the change is confined to a test-level
  checker and its tests).

### A7. Legacy behavior source

None. The derivation uses the audit's existing
`authority_evidence` binding for directive administration —
read, not copied from any control path.

### A8. Temporal-transfer evidence

See §A4: replay at exact checkpoint `226ce92` (the recorded
branch head before the merge of `main` at `e42f929` that
produced `f64f989`), scenario 15/15 with only the updated
module copied in; the lesson transfers, with no authority
effect and no negative transfer observed.

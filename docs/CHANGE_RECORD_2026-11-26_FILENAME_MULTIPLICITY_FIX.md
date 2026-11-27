# Change record — Filename-deception scenario (#362): multiplicity-preserving reconciliation fix (2026-11-26)

Base: live `main` at `d7b75069b77024eb9301d8a6118ac9ad3a3d86b7`
(verified via `gh` at task start, 2026-11-26).
Authority: Austin directed this patch on 2026-11-26, following
the multiplicity pass of 2026-11-25, which classified this
defect as live in the merged filename scenario module on main
(report-only at that time; this patch is the directed fix).
Test-only change: the reconciliation helpers and one new test
in the filename scenario module, plus this record. No
production code is touched. No kernel changes.

Status: IN VERIFICATION until all three verdicts are in this
change record; the verdicts are recorded in §4 below, so the
status at the close of this record is: **three-verdicts
recorded — awaiting approvals/merge word.**

## 1. Invariant or failure addressed

Failure addressed: **the test-level reconciler in the merged
filename-deception scenario
(`tests/test_filename_deception_incident_scenario.py`, PR
#362) collapsed the kernel audit into sets — `audited_sets`
(~L254) recorded presence per intent hash, not occurrence
counts — and `reconcile_against_audit` (~L284) compared the
claim against those sets.** Duplicate or missing occurrences
of the same intent hash were therefore invisible: a claim that
reported a repeated event once, or reported an event one more
time than the record holds it, reconciled exactly as long as
every hash was present on both sides. Reproduced by executed
probe at the worktree head before the verdicts were recorded
(see §4): under the pre-fix set comparison, both the inflated
claim and the collapsed claim below return `ok=True`; under
the fixed count comparison both return `ok=False`, and the
honest repeated history returns `ok=True`.

The governing invariant is the scenario's own stated purpose
for reconciliation: a claimed history must be checkable
against the kernel audit in both directions — a claim is no
more free to invent or inflate occurrences than it is to hide
them (the standard step 5b already pins for invented attempts
at set level, now extended to occurrence counts).

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The defective reconciler
is a test-level function whose only consumers are the
scenario's own `unittest` assertions; no code path — kernel,
state, projection, executor, or store — reads its result.
This change strengthens a checker; it grants, narrows, and
removes no authority, and changes no permit, policy, or state
behavior.

## 3. Canonical state mutations introduced or exposed

None. `reconcile_against_audit` remains a pure read over the
public `kernel.audit` read path; it writes nothing and still
verifies the audit chain first and fails closed on an invalid
chain. No writer, route, ledger, executor, or state backend
is added.

## 4. Exact success and adversarial evidence

Change (test module only):

- New `audited_counts` counts occurrences per intent hash
  (a `Counter` over `permit_consumed` records for
  consequences; a `Counter` over `permit_rejected` records
  plus `decision` records with outcome `require_approval` /
  `deny` for attempts), porting the verified #396/#397
  `audited_counts` pattern. `audited_sets` is retained as a
  set view derived from the counts, for callers that only
  need the distinct hashes.
- `reconcile_against_audit` now compares counts: the claim's
  consequence and attempt lists are counted, and each
  direction's divergence is the per-hash excess of one
  counter over the other. `ClaimReconciliation` additionally
  reports the per-hash divergence counts
  (`undisclosed_attempt_counts`, `unbacked_consequence_counts`,
  `missing_consequence_counts`, `phantom_attempt_counts`) and
  the audited counts themselves. `ok` requires audit validity
  and zero divergence in every direction, as before — now at
  occurrence granularity.
- New test
  `test_step5_reconciliation_counts_multiplicity_in_both_directions`
  pins all three acceptance verdicts in one history (2
  separately permitted submissions of deliverable 1, 2
  rejected shortened-rename attempts, plus the other three
  authorized acts). The three verdicts, ON RECORD verbatim:

  - missing event (claim count > audit count for a hash) → reconciliation FAILS
  - extra copy (audit count > claim count) → reconciliation FAILS
  - legitimately repeated event (true multiplicity claim matching audit counts) → reconciliation PASSES

  Exercised in the test as:
  - **MISSING event → FAIL:** the claim reports a third
    submission of deliverable 1 the record does not hold
    (`unbacked_consequence_counts = {submit_1_hash: 1}`,
    `ok=False`); the same inflation on the attempts side
    (a third claimed rename attempt) fails as a phantom copy
    (`phantom_attempt_counts = {rename_short_hash: 1}`).
    Pre-fix, the set comparison returned `ok=True` on the
    inflated claim (Verified by executed probe).
  - **EXTRA COPY → FAIL:** the claim reports each repeated
    hash once while the audit holds two occurrences of each
    (`missing_consequence_counts = {submit_1_hash: 1}`,
    `undisclosed_attempt_counts = {rename_short_hash: 1}`,
    `ok=False`). Pre-fix, the set comparison returned
    `ok=True` on the collapsed claim (Verified by executed
    probe).
  - **LEGITIMATELY REPEATED event → PASS:** the claim
    reporting the true multiplicity (2 submissions of
    deliverable 1, 2 rejected rename attempts) reconciles
    `ok=True`, with audited counts
    `{submit_1_hash: 2}` consequences and
    `{rename_short_hash: 2}` attempts. Restoring the honest
    claim after each failure reconciles again — the failures
    are the counts, not the history.

Evidence (Verified, executed at the worktree head):

- Scenario module: **9/9 pass** (was 8/8 at base; the delta
  is exactly the new test). All pre-existing assertions pass
  unmodified, including step 5 (set-level undisclosed
  attempts) and step 5b (phantom attempts).
- Full suite at the worktree head: **1140 tests ran, OK
  (skipped=25)** in this environment; the pristine base
  `d7b7506` measured in the same environment and by the same
  command (`python -m unittest discover -s tests`) at
  **1139 ran, OK (skipped=25)** — the delta is exactly the
  new test. (Skip counts are environment-dependent; the +1
  test delta is not.)
- Executed probe at the worktree head, same history as the
  new test: pre-fix set comparison — inflated claim `ok=True`,
  collapsed claim `ok=True`; fixed count comparison —
  inflated `ok=False`, collapsed `ok=False`, honest repeated
  claim `ok=True`.

Adversarial transformation review (eight passes, applied to
this checker change): Flip — the checker's trust direction
is reversed: the claim is now counted against the audit, and
neither is believed by presence alone. Reverse — a passing
verdict now requires, per hash, claimed occurrences to be
backed one-for-one by audited occurrences and audited
occurrences to be accounted by claims. Invert — a desirable
`ok=True` is no longer producible by a collapsed or inflated
history: extra and missing copies each flip the verdict by
name and count. Inside-Out — the reconciler holds no state
and writes none; it cannot originate the occurrences it
counts. Darken — worst case inside this checker is a history
that both duplicates one hash and omits another: both
directions flag independently in the same result. Lighten —
the honest repeated history (the benign case multiplicity
checks most often break) passes exactly, pinned by the same
test. Amplify — replicating an event multiplies only its
divergence count, never a pass. Negate — the smallest clean
path is the one taken: count occurrences, as PRs #396/#397
already verified; no new mechanism.

Stop/continue decision: CONTINUE — test-level checker only,
no governed path touched.

## 5. Boundary the evidence does not prove

This proves the corrected verdicts of one test-level
reconciler, for the histories the scenario constructs. It
proves nothing about grader robustness (the scenario models
no grader), nothing about non-governed paths, and nothing
about any shipped reconciler (`pulpo.effect_reconcile`,
`pulpo.custody_reconcile` are separate code with separate
scopes, untouched and unexamined here).

## 6. Claim classification

- The defect and its probe behavior at `d7b7506`: **Verified**
  (executed probe, 2026-11-26, at the worktree head).
- "No authorization outcome is affected": **Verified**
  (the reconciler's only consumers are test assertions in
  this module).
- Kernel behavior asserted by the scenario tests, before
  and after: **Verified** (executable evidence at base and
  at the worktree head).

## 7. Legacy behavior source

None. No legacy control path was copied. The patch ports the
`audited_counts` pattern verified in PRs #396/#397 (per-hash
counts, per-direction divergence, regression test, change
record), following the same form as the sibling WorkOS fix
(PR #407).

## 8. Temporal-transfer evidence

Executed 2026-11-26. The applicable historical checkpoint is
this branch's exact base, `d7b7506`. Method: a clean worktree
was reconstructed at exactly `d7b7506` with only the updated
scenario module copied in (`git status` showed that single
modification), and the scenario was run there.

- TRANSFERS: all 9 scenario tests pass identically at
  `d7b7506` — the multiplicity comparison is a property of
  this branch's test-level helper over the public audit read
  path; no kernel behavior is exercised differently at the
  two states.
- NO EFFECT: the lesson is a test module plus this record;
  consequential authority is unchanged by the replay itself
  (`authority_effect=none` at both states).
- NEGATIVE TRANSFER: none observed.

## Status (closing)

Three verdicts recorded in §4 — **three-verdicts recorded —
awaiting approvals/merge word.** Nothing in this record
authorizes a merge.

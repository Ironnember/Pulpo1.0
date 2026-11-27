# Change record — Trajectory/Epoch scenario (#366): multiplicity-preserving `reconcile_run_report` fix (2026-11-26)

Base: live `main` at `d7b75069b77024eb9301d8a6118ac9ad3a3d86b7`
(verified via `gh` at task start, 2026-11-26).
Authority: Austin Irvan directed this patch on 2026-11-26
(08:00 MST: "Yes — run git and the test suites in those seven
worktrees to finish the blocked work"), following the
multiplicity pass of 2026-11-25, which found this defect live
in the merged trajectory scenario module on `main`
(report-only at that time; no PR opened then).
Test-only change: one function and one new test in the
trajectory scenario module, plus this record. No production
code is touched. No kernel changes.

Status: three-verdicts recorded — awaiting approvals/merge word.
(This patch was labelled IN VERIFICATION until all three
verdicts below were exercised by tests and recorded here;
they now are, verbatim, in §4.)

## 1. Invariant or failure addressed

Failure addressed: **the run-report reconciler in the merged
Trajectory/Epoch scenario (`tests/test_trajectory_epoch_incident_scenario.py`,
PR #366), `reconcile_run_report`, booleanized the live-effects
count.** It built a set of consumed intent hashes and reported
`recorded_live_effects = 1 if live_hash in consumed else 0` —
presence instead of count. A history with 2 (or 3, or any
number of) consumptions of the live intent therefore reported
exactly 1 recorded live effect: a claim of 2 live effects could
never reconcile against a true 2-consumption audit, and a
claim of 1 would falsely reconcile against a 2- or
3-consumption audit. The scenario's own evidence check could
not distinguish a single live effect from a repeated one.

The governing invariant is the scenario's own stated purpose
for reconciliation: a run summary must be checkable against
the kernel record in both directions, with occurrence counts —
the standard the same function's sibling count in the same
function already meets (`recorded_live_attempts` is computed
with `sum(...)` over `permit_rejected` records for the live
hash).

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The defective reconciler
is a test-level function whose only consumers are the
scenario's own `unittest` assertions; no code path — kernel,
state, projection, executor, or store — reads its result.
This change strengthens a checker; it grants, narrows, and
removes no authority, and changes no permit, policy, or state
behavior. Custody/authority semantics are out of scope and
untouched.

## 3. Canonical state mutations introduced or exposed

None. `reconcile_run_report` remains a pure read over the
public `kernel.audit` read path (after the pre-existing
fail-closed `verify_audit()` check, unchanged); it writes
nothing. No writer, route, ledger, executor, or state backend
is added.

## 4. Exact success and adversarial evidence

Change (test module only):

- `reconcile_run_report` now counts live-effect occurrences
  the way its sibling live-attempts count in the same function
  already does: `recorded_live_effects = sum(1 for record in
  kernel.audit if record["event"] == "permit_consumed" and
  record["payload"].get("intent_hash") == live_hash)`. The
  set construction and the booleanized
  `1 if live_hash in consumed else 0` are removed. The
  attempts count, the audit-verification fail-closed gate,
  and every other field of the result are unchanged.
- New test
  `test_reconciliation_counts_live_effect_multiplicity`
  pins all three acceptance verdicts in one incrementally
  built history. The governed path cannot produce a
  2-consumption audit for the live intent (every governed
  live consume is denied and records `permit_rejected`, not
  `permit_consumed`), so the verdicts are exercised through
  the module's unguarded negative-control double
  (`_IntentBlindState` / `_UnguardedConsumeKernel`), whose
  consume ignores the intent binding and therefore records
  `permit_consumed` for the live intent — that is the
  double's designed purpose in this module. The claim is
  fixed at 2 live effects (0 live attempts) throughout:

  - claim 2 vs audit 1 → reconciliation FAILS (missing event)
  - claim 2 vs audit 3 → reconciliation FAILS (extra copy)
  - claim 2 vs audit 2 → reconciliation PASSES (legitimately repeated event)

  In detail: after 1 unguarded live consumption,
  `recorded_live_effects == 1` and
  `live_effects_reconciled` is `False` (missing event);
  after a 2nd, `recorded_live_effects == 2` and
  `live_effects_reconciled` is `True`, with
  `attempts_reconciled` `True` and
  `recorded_live_attempts == 0` (legitimately repeated
  event); after a 3rd, `recorded_live_effects == 3` and
  `live_effects_reconciled` is `False` again (extra copy).
  The executor's recorded effects are exactly three
  `("fetch_page", LIVE)` entries, and the audit chain
  verifies at the end. Pre-fix, the booleanized count would
  have reported 1 at every step, so the PASS verdict at
  audit 2 was unreachable and the extra-copy verdict at
  audit 3 was invisible against a claim of 1.

Evidence (Verified, executed at the worktree head):

- Scenario module: **11/11 pass** (was 10/10 at base; the
  delta is exactly the new test). All pre-existing
  assertions pass unmodified, including the positive
  control, the route-substitution and mandate-scope steps,
  the revocation/kill-switch test, the attempts-direction
  reconciliation test, and the tampered-audit fail-closed
  test.
- Full suite at the worktree head: **1140 tests ran, OK
  (skipped=25)** in this environment; the pristine base
  `d7b7506` measured in the same environment and by the
  same command (`python -m unittest discover -s tests`)
  at **1139 ran, OK (skipped=25)** — the delta is exactly
  the new test. (Skip counts are environment-dependent.)

Adversarial transformation review (eight passes, applied to
this checker change): Flip — the reconciler's trust direction
is reversed: the run-summary claim is now checked against a
counted audit, and neither is believed by presence alone.
Reverse — a passing verdict now requires the recorded
occurrence count to equal the claimed count exactly; no
presence test can substitute. Invert — a desirable
`live_effects_reconciled=True` is no longer producible by a
collapsed history: missing and extra copies each flip the
verdict. Inside-Out — the reconciler holds no state and
writes none; it cannot originate the occurrences it counts.
Darken — worst case inside this checker is a claim that is
simultaneously short in one direction and long in another;
the effects and attempts counts are computed independently,
so each direction flags on its own. Lighten — the honest
repeated history (the benign case multiplicity checks most
often break) passes exactly, pinned by the same test.
Amplify — replication of a consumption multiplies only the
recorded count, never a pass. Negate — the smallest clean
path is the one taken: count occurrences with `sum(...)`,
as the sibling count in the same function already does; no
new mechanism.

Stop/continue decision: CONTINUE — test-level checker only,
no governed path touched.

## 5. Boundary the evidence does not prove

This proves the corrected verdicts of one test-level
reconciler, for the histories the scenario constructs —
including histories only the unguarded double can produce,
which is stated on the face of the new test. It proves
nothing about Trajectory's or Epoch's actual systems, and
nothing about any shipped reconciler (`pulpo.effect_reconcile`,
`pulpo.custody_reconcile` are separate code with separate
scopes, untouched and unexamined here). The governed path's
inability to produce a multi-consumption live-effects audit
is itself part of the scenario's evidence (denied live
consumes record attempts, not effects); this change does
not alter that.

## 6. Claim classification

- The defect and its booleanized behavior at `d7b7506`:
  **Verified** (code reading at the base commit plus the
  2026-11-25 multiplicity pass, which recorded this module's
  booleanized effects count as a live merged-code finding).
- "No authorization outcome is affected": **Verified**
  (the reconciler's only consumers are test assertions;
  no kernel or production code path reads its result).
- Kernel behavior asserted by the scenario tests, before
  and after: **Verified** (executable evidence at base and
  at the worktree head).
- The three verdicts in §4: **Verified** (executed by the
  new test at the worktree head; recorded verbatim above).

## 7. Legacy behavior source

None. No legacy control path was copied. The patch mirrors
the in-function sibling `recorded_live_attempts` `sum(...)`
count — the template the task design named — and follows
the multiplicity-fix pattern of PRs #396/#397 (occurrence
counts, per-direction divergence, regression test, change
record).

## 8. Temporal-transfer evidence

Executed 2026-11-26. The applicable historical checkpoint
is this branch's exact base, `d7b7506`. Method: a clean
worktree was reconstructed at exactly `d7b7506` with only
the updated scenario module copied in (`git status`
showed that single modification), and the scenario was
run there.

- TRANSFERS: all 11 scenario tests pass identically at
  `d7b7506` — the multiplicity count is a property of
  this branch's test-level helper over the public audit
  read path; no kernel behavior is exercised differently
  at the two states.
- NO EFFECT: the lesson is a test module plus this record;
  consequential authority is unchanged by the replay
  itself (`authority_effect=none` at both states).
- NEGATIVE TRANSFER: none observed.

## 9. Verification results

- Scenario module at the worktree head: **11/11 pass**
  (base: 10/10; delta exactly the new
  `test_reconciliation_counts_live_effect_multiplicity`).
- Full suite at the worktree head: **1140 tests ran, OK
  (skipped=25)** in this environment.
- Full suite at pristine base `d7b7506`, same environment,
  same command: **1139 ran, OK (skipped=25)**. Delta: +1,
  exactly the new test.
- Temporal replay at `d7b7506` with only the updated
  module copied in: scenario **11/11 pass**.
- The three acceptance verdicts of §4 are exercised by
  `test_reconciliation_counts_live_effect_multiplicity`
  and are on record verbatim in §4: claim 2 vs audit 1 →
  reconciliation FAILS (missing event); claim 2 vs
  audit 3 → reconciliation FAILS (extra copy); claim 2
  vs audit 2 → reconciliation PASSES (legitimately
  repeated event).

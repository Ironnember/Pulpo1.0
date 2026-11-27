# Change record — Gainsight scenario (#385): multiplicity-preserving reconciliation fix (2026-11-26)

Status: three-verdicts recorded — awaiting approvals/merge word

Base: live `main` at `d7b75069b77024eb9301d8a6118ac9ad3a3d86b7`
(verified via `gh` at task start, 2026-11-26).
Authority: Austin directed this patch on 2026-11-26, following
the multiplicity pass of 2026-11-25, which classified this
defect as live in the merged gainsight module on `main`
(report-only at that time; no PR was opened then).
Test-only change: one scenario module plus this record.
No production code is touched. No kernel changes.

## 1. Invariant or failure addressed

Failure addressed: **the test-level reconciliation in the
merged Gainsight scenario
(`tests/test_gainsight_incident_scenario.py`, PR #385)
compared set presence, not counts.** `audited_sets`
derived sets of intent hashes from the audit and
`reconcile_against_audit` converted the claimed values to
sets as well, collapsing every occurrence of a hash to
one. A claimed history listing a hash once therefore
reconciled successfully even when the audit held further
attempts for that same hash: the claim could underreport
repeated activity while returning `ok=True`.

The honest-claim re-derivation (Recorded, directed for
this patch and verified by executable evidence at the
worktree head): in step 6, each of the 5 out-of-intent
acts is attempted on three routes — a bare `evaluate`,
the connection token presented as a permit, and the
(now spent) genuine permit presented by the app itself.
The true audit therefore holds **each of the 5 attempt
hashes 3 times — 5 hashes × 3 = 15 attempt records — and
exactly 1 consequence** (the legitimate sync). The
shipped step-6 honest claim listed each attempt hash
ONCE and passed only because of the collapse. The
corrected honest claim lists every attempt hash 3 times.

The governing invariant is the scenario's own stated
purpose for reconciliation: a vendor's activity claim
must be checkable against the audit in both directions,
with occurrence counts — the standard PRs #396/#397
established for this checker class (`audited_counts` /
`Counter`).

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The defective
reconciler is a test-level function whose only consumers
are the scenario's own `unittest` assertions; no code
path — kernel, state, projection, executor, or store —
reads its result. This change strengthens a checker; it
grants, narrows, and removes no authority, and changes
no permit, policy, or state behavior. Custody/authority
semantics are out of scope and untouched.

## 3. Canonical state mutations introduced or exposed

None. `reconcile_against_audit` remains a pure read over
the public `kernel.audit` read path; it writes nothing.
No writer, route, ledger, executor, or state backend is
added.

## 4. Exact success and adversarial evidence

Change (test module only):

- `audited_sets` is replaced by `audited_counts`: the
  audit side now yields occurrence counts (multisets) per
  intent hash for consequences and attempts alike,
  porting the verified #396/#397 pattern.
- `reconcile_against_audit` counts the claim's lists the
  same way (a hash listed twice claims two occurrences)
  and flags a hash in each direction whenever the counts
  diverge: underreported attempts are
  `undisclosed_attempts`, underreported executions are
  `missing_consequences`, and overreported claims are
  `phantom_attempts` / `unbacked_consequences`. `ok`
  requires exact count equality for every hash, on top of
  the unchanged fail-closed audit-chain verification.
- Step 6's assertions were updated to the count form and
  its honest claim corrected to the true counts: each
  attempt hash listed 3 times (15 attempt records),
  the consequence listed once (1 consequence). The
  inflated-claim assertion now carries the honest 3×
  attempts, so its failure isolates the unbacked
  consequence exactly as before.
- New test `test_step6b_reconciliation_preserves_multiplicity`
  pins all three acceptance verdicts in the step-6
  history (5 attempt hashes × 3 routes = 15 attempt
  records, 1 consequence), verbatim:

  - **missing event → reconciliation FAILS** — the claim
    drops one occurrence of one attempt hash (lists it
    twice instead of 3 times): `ok=False`,
    `undisclosed_attempts` = exactly that hash. The
    collapsed shipped claim (each attempt hash listed
    once) is the extreme form: it fails on every attempt
    hash.
  - **extra copy → reconciliation FAILS** — the claim
    adds a fourth copy of one attempt hash: `ok=False`,
    `phantom_attempts` = exactly that hash; a second
    claimed sync execution likewise fails as
    `unbacked_consequences` = exactly the sync hash.
  - **legitimately repeated event (the corrected 3× honest claim) → reconciliation PASSES** — the claim listing every attempt hash 3 times and the one consequence once: `ok=True`, no undisclosed, unbacked, missing, or phantom entries.

Evidence (Verified, executed at the worktree head):

- Scenario module: **12/12 pass** (was 11/11 at base; the
  delta is exactly the new step 6b test). All pre-existing
  assertions pass, with step 6 updated to the count form
  as described above and no other assertion weakened.
- Full suite at the worktree head: **1140 tests ran, OK
  (skipped=25)** in this environment; the pristine base
  `d7b7506` measured in the same environment and by the
  same command (`python -m unittest discover -s tests`)
  at **1139 ran, OK (skipped=25)** — the delta is exactly
  the new test. (Skip counts are environment-dependent.)

Adversarial transformation review (eight passes, applied
to this checker change): Flip — the checker's trust
direction is reversed: the vendor claim is now the claim,
the audit the reference, and neither is believed by
presence alone. Reverse — a passing verdict now requires,
per hash, claimed occurrences to equal audited
occurrences in both directions; no set membership can
substitute. Invert — a desirable `ok=True` is no longer
producible by a collapsed history: missing and extra
copies each flip the verdict by name. Inside-Out — the
reconciler holds no state and writes none; it cannot
originate the occurrences it counts. Darken — worst case
inside this checker is a history that both omits one hash
and duplicates another: both directions flag
independently in the same result. Lighten — the honest
repeated history (the benign case multiplicity checks
most often break) passes exactly, pinned by step 6b.
Amplify — replication of an attempt multiplies only the
count a claim must report, never a pass. Negate — the
smallest clean path is the one taken: count occurrences,
as #396/#397 already do; no new mechanism.

Stop/continue decision: CONTINUE — test-level checker
only, no governed path touched.

## 5. Boundary the evidence does not prove

This proves the corrected verdicts of one test-level
reconciler, for the histories the scenario constructs.
It proves nothing about Salesforce, Gainsight, or any
deployed integration, and nothing about any shipped
reconciler (`pulpo.effect_reconcile`,
`pulpo.custody_reconcile` are separate code with separate
scopes, untouched and unexamined here).

## 6. Claim classification

- The defect and its collapse behavior at `d7b7506`:
  **Verified** (2026-11-25 multiplicity pass; step-6
  count assertions at the worktree head).
- The re-derived honest claim (5 hashes × 3 = 15 attempt
  records, 1 consequence): **Verified** (executable
  evidence — `audited_counts` assertions in steps 6/6b
  at the worktree head).
- "No authorization outcome is affected": **Verified**
  (the reconciler's only consumers are test assertions).
- Kernel behavior asserted by the scenario tests, before
  and after: **Verified** (executable evidence at base
  and at the worktree head).

## 7. Legacy behavior source

None. No legacy control path was copied. The patch ports
the `audited_counts` / `Counter` pattern verified in
PRs #396 (Hex.pm) and #397 (Xen Orchestra) — the template
the multiplicity pass named.

## 8. Temporal-transfer evidence

Executed 2026-11-26. The applicable historical checkpoint
is this branch's exact base, `d7b7506`. Method: a clean
worktree was reconstructed at exactly `d7b7506` with only
the updated scenario module copied in (`git status`
showed that single modification), and the scenario was
run there.

- TRANSFERS: all 12 scenario tests pass identically at
  `d7b7506` — the multiplicity comparison is a property of
  this branch's test-level helper over the public audit
  read path; no kernel behavior is exercised differently
  at the two states.
- NO EFFECT: the lesson is a test module plus this record;
  consequential authority is unchanged by the replay
  itself (`authority_effect=none` at both states).
- NEGATIVE TRANSFER: none observed.

## 9. Verification results

- Scenario module at the worktree head: **12/12 pass**
  (base: 11/11; delta exactly the new step 6b test).
- Full suite at the worktree head: **1140 tests ran, OK
  (skipped=25)** in this environment.
- Full suite at pristine base `d7b7506`, same environment,
  same command: **1139 ran, OK (skipped=25)**. Delta: +1,
  exactly the new test.
- Temporal replay at `d7b7506` with only the updated
  module copied in: scenario **12/12 pass**.
- The three acceptance verdicts of §4 are exercised by
  `test_step6b_reconciliation_preserves_multiplicity` and
  are on record verbatim in §4: missing event →
  reconciliation FAILS; extra copy → reconciliation
  FAILS; legitimately repeated event (the corrected 3×
  honest claim) → reconciliation PASSES.

# Change record — Mythos scenario: multiplicity (count) reconciliation fix

Status: three-verdicts recorded — awaiting approvals/merge word

Base: `origin/main` at `d7b7506` (incident replay: OpenSSH SSHole
CVE-2026-123158 authentication bypass (Nov 2026) (#393)), verified via
`gh` against Ironnember/Pulpo1.0 on 2026-11-26 before branching.
Branch: `fix/mythos-multiplicity-count`. Test-only change: one scenario
module (`tests/test_mythos_laundering_scenario.py`) plus this record.
No production code, no kernel code, and no custody/authority semantics
are touched. No merge is performed by this change.

## 1. Invariant or failure addressed

Defect: `compare_claim` in the mythos scenario module collapsed audit
records into sets (presence, not counts). `audited_sets` built a set of
intent hashes per class (consequences / attempts), and `compare_claim`
compared the claim as a set against those sets. Any number of audit
records for the same hash was therefore indistinguishable from one:
a claim disclosing a hash once reconciled against two, three, or any
number of records for that hash, and a claim repeating a hash any
number of times reconciled against a single record. Repeated attempts
or consequences of the same intent — multiplicity — were invisible to
reconciliation. This is the `audited_sets` collapse class identified
in the 2026-11-25 multiplicity pass as live in the mythos module on
main (report only at that time; this change is the on-branch fix).

Fix: the checker surface moves from sets to counts throughout.

- `audited_sets` is replaced by `audited_counts`, returning
  `collections.Counter` objects (audit records per hash) for
  consequences and for attempts.
- `compare_claim` builds `Counter`s from the claim lists and from the
  reference counts, and computes per-hash shortfalls and excesses with
  Counter subtraction. Reconciliation passes only when every per-hash
  count matches exactly. `ClaimReconciliation` keeps its frozenset
  fields (now naming the hashes with a count discrepancy) and gains
  count-level fields: `undisclosed_attempt_counts`,
  `phantom_attempt_counts`, `missing_consequence_counts`, and
  `unbacked_consequence_counts`.
- `reconcile_against_audit` uses `audited_counts` and preserves the
  count-level fields on its fail-closed (invalid-chain) path.
- The negative control's `AgentWritableLog.sets()` is replaced by
  `AgentWritableLog.counts()` returning Counters — it is part of the
  checker surface, so it moves to counts with the rest; the identical
  comparison logic still launders cleanly against the agent-writable
  reference, as before.

## 2. Counting unit — decided, with rationale

Counting unit: **audit records per hash**.

Rationale: audit records are the only unit the audit evidences.
Presentations are not an audit primitive. Each forbidden presentation
writes TWO attempt-class records — a `decision` record (outcome
`require_approval`) and a `permit_rejected` record — so counting
presentations would undercount what the audit actually holds and
would require inferring a grouping the audit does not record.

Corrected honest claims, under this unit:

- The shipped story's honest claim becomes 2× (not 1×): one forbidden
  presentation, two attempt-class audit records for the forbidden
  hash, plus 1× the clean hash as a consequence.
- The probe story's honest claim is 6× (not 3×): three forbidden
  presentations, each writing two attempt-class records, for a true
  attempt count of 6 for the forbidden hash.

## 3. Three acceptance verdicts — on record

Exercised by tests against the probe story's true count of 6
(`test_multiplicity_probe_claim_5_vs_6_fails_missing`,
`test_multiplicity_probe_claim_7_vs_6_fails_extra_copy`,
`test_multiplicity_probe_claim_6_vs_6_passes`):

- claim 5 vs 6 → reconciliation FAILS (missing)
- claim 7 vs 6 → reconciliation FAILS (extra copy)
- claim 6 vs 6 → reconciliation PASSES (legitimately repeated)

## 4. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. This change edits a test scenario
module and adds this record only: no permit, policy, state, audit, or
reconciliation behavior in production code (`pulpo/`) changes. The
reconciler changed here is test-level, as the module docstring already
states; the shipped reconcilers are untouched.

## 5. Canonical state mutations introduced or exposed

None introduced. No writer, route, ledger, executor, or state backend
is added or exposed. The scenario exercises the existing kernel audit
read path exactly as before; only how the test harness counts what it
reads has changed.

## 6. Exact success and adversarial evidence

Success evidence (this environment, Python `unittest`):

- Scenario module before the fix: 14 tests, OK.
- Scenario module after the fix: 18 tests, OK — the 14 prior tests
  (with the disclosed-attempt honest claim corrected to 2× and the
  positive / negative controls moved to counts) plus 4 new tests:
  `test_multiplicity_shipped_story_honest_claim_is_2x` and the three
  probe verdict tests in §3.
- Full suite after the fix, same environment: Ran 1143 tests, OK
  (skipped=25). Base measured on clean main in this same environment
  before editing: Ran 1139 tests, FAILED (errors=1, skipped=25) —
  the single base error was
  `test_service_boundary.SocketDeadlineTests.test_stalled_partial_frame_disconnects_and_dispatches_nothing`
  (ConnectionRefusedError on a socket connect), unrelated to this
  module, and that test passes in the after-fix run. Delta: +4 tests
  (1139 → 1143), exactly the 4 new multiplicity tests; no other
  delta.

Adversarial evidence: the under-disclosure case is pinned twice — a
1× claim against the shipped story's 2 records fails with
`undisclosed_attempt_counts == {forbidden_hash: 1}`, and a 5× claim
against the probe's 6 records fails the same way. The over-claim case
is pinned by the 7× probe claim failing with
`phantom_attempt_counts == {forbidden_hash: 1}`. The negative control
still launders cleanly against its own agent-writable log under the
count-based comparison, preserving the scenario's original contrast:
detection comes from custody of the reference record, not from the
comparison alone.

## 7. Boundary the evidence does not prove

This proves count-exact test-level reconciliation against the kernel
audit trail at this commit, for this scenario's record classes
(`permit_consumed`; `permit_rejected` plus `decision` records with
outcome `require_approval` / `deny`). It proves nothing about the
shipped reconcilers, about any deployment, or about audit classes
outside those named. The module's existing tamper-evidence boundaries
(tail truncation, rehashed mid-chain deletion) are unchanged and are
neither widened nor narrowed by this change.

## 8. Claim classification

Verified (executable evidence at the exact commit): the defect, the
count-based fix, the corrected honest claims (2× shipped / 6× probe),
and the three verdicts in §3, each exercised by a named test.
Recorded: the counting-unit decision and its rationale in §2.
No claim in this record is Inferred or Proposed.

## 9. Legacy behavior source

None. No legacy control path was used or copied; the fix rewrites the
module's own test-level comparison in place.

## 10. Temporal replay / reusable lesson

No relevant historical checkpoint exists for temporal replay of this
test-harness counting change: the lesson (compare multiplicities, not
presence, when a record can repeat per key) was already established
by the 2026-11-25 multiplicity pass across sibling modules, and this
change applies that recorded lesson to the mythos module rather than
deriving a new one. The replay itself leaves consequential authority
unchanged (`authority_effect=none`).

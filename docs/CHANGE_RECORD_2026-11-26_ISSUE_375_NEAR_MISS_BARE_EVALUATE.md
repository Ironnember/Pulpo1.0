# Change record — Issue #375: incident channel derives near-miss from bare-evaluate require_approval decisions

Source finding: Cairn incident replay (PR #374; change record
docs/CHANGE_RECORD_2026-11-20_CAIRN_REPLAY.md §5), graded Verified —
probe, derivation source, and a pinning test in the replay scenario.
Issue #375 acceptance shape: incident projection derives a near-miss
from require_approval decision records, with regression coverage
showing a bare-evaluate-only attempt sequence appears in
owner-facing near-miss reporting; historical gaps remain explicit.
Build authorized by Austin, 2026-11-26. Base: canonical main
d7b7506 (suite 1139 tests by loader count at the base commit). Separate PR; visibility only; no merge
authorized by this record.

## 1. Invariant or failure addressed

A bare `evaluate` that returns `require_approval` appends a
complete, chain-verified `decision` record to the canonical audit,
but `pulpo/incident_channel.py::_derive_records` derived near-miss
records only from the near-miss event set
(`purchase_revalidation_failed`, `permit_rejected`,
`approval_rejected`, `directive_denial`) plus `decision` records
with outcome `deny`. An attempt sequence consisting only of bare
evaluates was therefore invisible in owner-facing near-miss counts
while fully present in the audit — a surfacing boundary, the same
defect class as the #372 P1 (projection denials invisible to
incident reconciliation), one verb over. Not an authorization gap:
the act was stopped (no permit exists to spend).

The fix, in full:

- The `decision` branch of `_derive_records` now derives a
  near-miss record for outcome `require_approval` as well as
  `deny`, per record, keyed by that record's own audit hash —
  exactly the derivation shape the `deny` path already used. A
  `require_approval` decision is a distinct audit record from any
  `permit_rejected` / `approval_rejected` / `directive_denial`
  record, so nothing is double-counted; repeats count per
  occurrence (N `require_approval` decisions surface N
  near-misses). The fallback reason for a `require_approval`
  record without a payload reason is `approval_required`; the
  `deny` fallback (`denied`) is unchanged.
- `docs/incident-channel.md`: the feed table gains the
  `decision`/`require_approval` row, and the one-record-per-event
  rule states the per-occurrence, no-double-count property and
  the historical-gap boundary plainly.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. This is a visibility /
surfacing change only: authorization semantics are unchanged —
`evaluate` returns the same decisions, no permit is minted,
issued, or consumed by this change, no policy, approval, or
consume path is touched, and nothing in the derivation feeds
back into an authorization decision. The custody derivation in
`incident_channel.py` (the custody feed, `_custody_resolution`,
and the merged unknown/custody records) is NOT modified; the
only production file changed is the audit `decision` branch of
`_derive_records` plus the module docstring's feed description.

## 3. Canonical state mutations introduced or exposed

None introduced. The incident channel remains a derived,
read-only projection: freezing a report appends nothing to the
audit and writes nothing to the custody store (asserted by the
existing read-only tests and by every updated scenario step 6).
No writer, route, ledger, executor, or state backend is added.

## 4. Exact success and adversarial evidence

- New unit coverage in `tests/test_incident_channel.py`
  (IncidentChannelAuditFeedTests):
  - `test_require_approval_decision_is_a_near_miss` — a single
    `require_approval` decision derives one near-miss, anchored
    to its own audit record, reason preserved.
  - `test_bare_evaluate_only_sequence_surfaces_per_occurrence` —
    a sequence of 3 bare-evaluate (`require_approval`) decisions
    and nothing else surfaces 3 near-misses in the frozen report
    and in `list_incidents(kind="near_miss")`, with distinct
    record ids and one anchor per decision record (per
    occurrence, no double count).
  - `test_deny_path_unchanged_and_no_double_count_with_require_approval` —
    a mixed `permit_rejected` + `deny` + `require_approval`
    sequence yields exactly 3 near-misses, one per audit record,
    reasons and order preserved: the deny path is unchanged.
  - `test_allowed_decision_and_other_events_emit_no_record`
    updated: it previously pinned the old gap by asserting a
    `require_approval` decision emits no record; it now pins
    only `allow` / `permit_consumed` / `directive_activated`
    as non-deriving.
- Updated pinning tests: the step-6 incident-channel tests in
  the twelve replay scenario modules that counted
  `require_approval` decisions as contributing zero near-misses
  (Cairn, AgentGates, Dragos, Entra, Gainsight, GL.iNet
  GoodCloud, Jesta/OpenCode, LeadStack, OpenRouter,
  ScreenConnect, SSHole, WordPress plugins) now include
  `len(require_approval_decisions)` in the expected near-miss
  total and in the `decision` source-detail count; hardcoded
  totals moved by exactly the scenario's require_approval count
  (Entra 16→21, Gainsight 18→23, GL.iNet 10→11, Jesta 8→9,
  LeadStack 14→18, OpenRouter 16→19, ScreenConnect 10→11,
  SSHole 8→9, WordPress 16→19). Their module docstrings and
  step-6 comments state the new derivation instead of the old
  boundary. Azure APIM and Barracuda step-6 tests, whose routes
  produce no `require_approval` decisions, are unchanged and
  pass unchanged.
- Full suite at the worktree head: **1142 tests, OK
  (skipped=25)** (`python3 -m unittest discover -s tests`) —
  the baseline at the base commit is 1139 tests by loader count
  (`TestLoader.discover(...).countTestCases()` at pristine
  d7b7506); the delta is exactly the 3 new unit tests above
  (the updated tests replace, not add). Targeted runs:
  `tests.test_incident_channel` 44 tests OK, and the fourteen
  incident-scenario modules 124 tests OK.

Adversarial transformation review (eight passes per
docs/ADVERSARIAL_TRANSFORMATION_SOP.md):

- Flip — derivation does not depend on the attempt's
  self-description: the outcome field of a chain-verified audit
  record decides, and a hostile and a benign bare evaluate are
  indistinguishable here, as they should be for surfacing.
- Reverse — the earliest unreachable point is unchanged: a bare
  evaluate still mints nothing; this change only makes the
  stopped attempt visible after the fact.
- Invert — outcome is not legitimacy: a near-miss record for a
  `require_approval` decision claims only that the kernel
  declined to mint without approval (Recorded, per-record claim
  classification unchanged); it does not claim an attack, a
  denial of an approval, or any effect.
- Inside-Out — the channel cannot originate authority: it is
  the same read-only projection; it reads the audit and derives
  records, and no production code authorizes from its output.
- Darken — worst bounded case: an agent floods bare evaluates.
  Each appends one audit record (existing behavior) and now
  derives one near-miss; growth is linear per attempt, bounded
  by the report's existing 1 MiB export bound, which fails
  loudly rather than truncating.
- Lighten — minimum benign interpretation: a legitimate agent
  repeatedly probing whether an act needs approval now shows
  in near-miss counts. That is the intended visibility: the
  owner sees approval-gated attempts, not only hard denials.
- Amplify — many bare evaluates aggregate no capability:
  near-miss records are evidence only; counting per occurrence
  cannot mint, spend, or widen anything.
- Negate — the smallest clean path needs no new surface at
  all: the records already existed in the audit; only the
  projection's derivation set was incomplete.

Stop/continue decision: CONTINUE in the governed kernel path
only.

## 5. Boundary the evidence does not prove

Historical gaps remain explicit: this change invents no records
and backfills nothing. A report frozen over a historical audit
now derives near-misses from that audit's `require_approval`
decisions, because the derivation runs at freeze time — but any
report frozen and exported before this change still shows the
old counts, and nothing here rewrites exported reports. The
change proves nothing about non-governed paths or ambient
authority, and it does not decide whether `require_approval`
attempts should carry a lifecycle, triage, or any different
weight from denials in owner-facing presentation — it surfaces
them in the same near-miss count, with `decision` as the source
detail and the decision's own reason, so a reader can tell them
apart from denials.

## 6. Claim classification

Verified — root cause located in the derivation source at the
base commit, fix and regression coverage executed at the
worktree head, full suite result recorded in §4. The finding's
original grading (Verified, Cairn replay §5) is unchanged.

## 7. Legacy behavior source

None. No legacy control path was used or copied; the fix extends
the existing in-module `deny` derivation shape to the adjacent
outcome in the same branch.

## 8. Temporal replay

No relevant historical checkpoint exists for a reusable lesson:
the change is a projection-completeness fix graded directly
against issue #375's acceptance shape at the current head, not
a generalized lesson carried from an earlier state. Historical
scenario modules serve as the regression evidence instead —
their step-6 sequences are re-derived under the new rule and
their expected counts move by exactly their recorded
`require_approval` counts, no more.

## 9. Addendum (2026-11-26): Railway scenario interaction

The Railway replay scenario (PR #405) merged to main after
this PR was authored, so its step 6 was not among the twelve
modules updated above. Its step 6 pinned the pre-fix behavior
explicitly: the sequence's one bare-evaluate
`require_approval` decision was asserted to contribute zero
near-miss records, with a hardcoded total of 9. Under this
PR's derivation rule that decision surfaces exactly one
near-miss, so the module failed CI deterministically
(`AssertionError: 9 != 10` in
`test_step6_incident_channel_and_counted_reconciliation`;
the `test` check failure was the downstream gate on
`UNIT_RESULT=failure`, not a second defect).

Fix, same shape as the twelve modules above and confined to
the scenario layer: the module docstring and step-6 comments
now state the post-#375 derivation; the accounting identity
adds `len(require_approval_decisions)`; the hardcoded total
moves 9 → 10 — exactly the scenario's recorded
`require_approval` count (1), no more; the `decision`
source-detail count becomes
`len(denied_decisions) + len(require_approval_decisions)`.
No count change from any other PR is absorbed here: the
failing head contained neither PR #407 nor PR #410, and the
delta is wholly explained by this PR's own rule. Custody
untouched; no kernel change; visibility only, as above.

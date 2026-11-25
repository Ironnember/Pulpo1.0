# Change record — Incident replay: Fusionist ACE bridge unbacked mints and reserve release (2026-11-22)

Base: `origin/main` at `5297d1c` (incident replay:
ConnectWise ScreenConnect CVE-2026-84869 technician
exploitation, PR #386). Authority: the standing incident
scan surfaced the incident and its confirmed mechanism
on 2026-11-24 (scan run 2026-11-24 07:31 MST; the CYBER
bridge watch-only hold lifted the same morning on the
same failure shape); Austin approved this build on
2026-11-24 ("Build the replay PR"). Test-only change:
one scenario module plus this record. No production
code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from Bitquery's on-chain
investigation as carried by the iTokenly Hack Registry
entry for this incident, retrieved 2026-11-24; the
registry's change log marks its figures provisional
until Fusionist publishes its own): the bridge that
carries ACE, the coin of Fusionist's Endurance chain,
to BNB Chain minted ACE that nobody had paid for.
Bitquery counted 62 unbacked mints between 17:55 UTC on
2026-11-22 and early on 2026-11-23, starting with 60
million ACE — more than all the wrapped ACE then in
existence — and ending in amounts of trillions and
more. Each mint carried the signatures of all three
keys the bridge uses to request, approve, and execute a
mint, the same keys behind more than 3,300 genuine
mints since 2023. Blockaid flagged the attack at 19:08
UTC; Fusionist asked users at 19:30 UTC to stop
trading, sending, and bridging ACE on BNB Chain. The
thieves sold the unbacked ACE as its price collapsed;
Bitquery counts $1.73 million of their DEX sales, with
proceeds of 1,150.9 ETH (about $1.97 million) deposited
into Tornado Cash in 61 deposits. Then the crashed
tokens were sent back through the bridge, whose burn
key approved the release of 53.7 million real ACE on
Endurance within about two hours, emptying the
bridge's backing down to 148 ACE; Grafa values the
released real ACE at about $3.7 million. The $5.7
million total loss figure is SlowMist's, as recorded by
the registry — an estimate, not an audited figure.
Bitquery also found six Fusionist wallets, including
the bridge keys, swept in the same second the next
morning. How the keys were obtained has not been
stated; Fusionist has published neither a loss figure
nor a cause, and nothing has been reported recovered.

Failure addressed: **a genuine signature is not
provenance, and provenance is not authority.** The
signed acts had no source record behind them — no ACE
was locked or burned on the source side for any of the
62 mints — and no step on the bridge's execution path
asked whether one had been. The governing invariants
are `SIGNATURE != PROVENANCE != AUTHORITY`,
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`,
and the reconciliation requirement itself: under the
governed path modeled here, a mint executes only when
(a) a source record matching the intent exactly
(record identity, amount, target) exists and is
unspent, checked at dispatch time, and (b) a permit
bound to that exact intent is consumed, once. A
release executes only against backing mints that
actually executed through the governed path, summing
exactly to the release amount, none already released
against. Denial is fail-closed at the reconciliation
gate and at evaluate/consume, never a log line written
after value has already moved.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately unguarded
double (`_UnreconciledDispatcher`, whose reconciliation
gates always pass) exists solely as the negative
control, is test-local, and is never imported by
runtime code — the same pattern as PRs #346 and
#362–#386.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `SourceLedger` and `BridgeDispatcher`
are test harnesses: the ledger holds the harness's
model of an external source chain's records (not
canonical Pulpo state, and nothing in the kernel can
write to it), and the dispatcher records a consequence
only after a successful kernel consume. The
incident-channel freeze is asserted read-only in the
scenario itself (audit length unchanged across the
freeze). Audit growth is classified in the module
docstring per AGENTS.md (`NO_PERMIT !=
NO_GOVERNED_EFFECT`), with one route distinction this
scenario pins explicitly: a kernel-route denial appends
audit records (one decision record for a bare
`require_approval` evaluate; one `permit_rejected`
record per consume rejection; two records — an
`approval_rejected` record and a denied decision
record — per denied approval-envelope evaluation),
while a reconciliation-route refusal appends nothing to
the canonical audit and grows only the dispatcher's
reconciliation log by one entry. Both growths are
governed effects (evidence production), append-only,
with `authority_effect=none` and no capability
accumulation, assessed separately from governed
external consequences throughout.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_fusionist_ace_incident_scenario.py`
(11 tests, all passing at the worktree head):

- positive control: the one authorized act (a mint of
  100 units against a real, reconciled lock, under a
  verified approval envelope) executes exactly once;
  the lock is spent; replay of the same permit directly
  at `consume` is rejected by the kernel layer itself
  (1 `permit_consumed`, 1 `permit_rejected`), so
  single-use does not depend on the dispatcher's gate.
- step 1: the unbacked mint is refused on every
  no-permit route — `evaluate` returns
  `require_approval` with no permit minted, and the
  dispatcher refuses the act with no permit and with
  the bridge keys' signatures presented as a token.
  Both dispatcher refusals are reconciliation refusals
  (`no_matching_source_record`), recorded in the
  reconciliation log; the canonical audit gains no
  `permit_rejected` from them.
- step 2: a genuine permit — issued through a verified
  approval envelope, the model's form of all three
  bridge keys signing — cannot execute an unbacked
  mint. The refusal is pre-consume: the permit stays
  unspent, the audit shows neither consumption nor
  rejection, and once the real lock is recorded the
  SAME permit executes the mint exactly once. The
  discrimination is the incident's lesson: what was
  missing was never the signature; it was the source
  record.
- step 3: on a backed intent, the keys-signed string
  reaches the kernel and is rejected at consume
  (`permit_rejected` bound to the mint's intent hash);
  the backing is unspent by the rejection and the
  genuine permit still executes the mint afterward. A
  signature is not a permit either.
- step 4: a second, freshly approved permit for the
  same intent meets a spent lock and is refused at
  reconciliation (`backing_already_spent`) before
  consume — one source record backs exactly one mint —
  and the refused dispatch appends nothing to the
  canonical audit (the only growth is the second
  permit's own issuance records).
- step 5: amount and target must match the record
  exactly — a lock of 100 backs no mint of 150, and a
  lock taken in for one target backs no mint to
  another; both are refused as
  `no_matching_source_record`, and the exact triple
  still executes afterward.
- step 6: the release leg. Three unbacked mints under
  genuine permits are all refused, so none executes;
  a release of real reserves against exactly those
  three mints — amounts summing exactly, under a
  genuine release permit — is refused with
  `backing_not_executed`: existence is not backing.
  The governed counterpart executes (a real mint, then
  a release backed by exactly that executed mint), and
  the same executed mint backs no second release under
  a fresh presentation and fresh permit
  (`backing_already_released`) — the reserve cannot be
  drained twice through one backing.
- step 7: an approval envelope for the mint signed
  with an unauthorized key is denied
  (`approval_signature_invalid`), and the genuine
  release envelope presented for the mint intent is
  denied (`approval_intent_mismatch`); the genuine
  pair still admits afterward.
- step 8: the wave — 62 unbacked mints, each under its
  own genuine permit with its own approval identity,
  all refused at reconciliation
  (62 `no_matching_source_record` entries), zero
  consequences, and zero `permit_consumed` /
  `permit_rejected` in the audit: volume is not
  backing, and replication multiplies refusals, never
  authority.
- step 9: the incident channel sees the kernel-visible
  attempts — freezing a report over the replayed
  sequence (the no-permit evaluation, the fabricated
  token on a backed intent, both approval-envelope
  attempts, the one legitimate execution and its
  replay) yields zero incidents and exactly the
  near-miss records the channel's derivation produces
  from the audit: 2 `permit_rejected`,
  2 `approval_rejected`, and 2 denied `decision`
  records (6 near-misses in total), each classified
  Recorded under a valid audit chain; the freeze
  appends nothing. The step also pins both surfacing
  boundaries stated in §5: the sequence's
  1 `require_approval` decision contributes zero
  near-miss records, and the included reconciliation
  refusal (step 2's route) leaves the canonical audit
  length unchanged across the dispatch.
- negative control: with the reconciliation gate
  removed (dispatcher double whose gates always pass),
  the unbacked mint EXECUTES under a genuine permit
  and the release against it executes too — the
  incident's full shape, both acts, in miniature. The
  refusals come from the reconciliation gate (and,
  where exercised, the kernel's binding), not from a
  harness that refuses by construction. The identical
  mint attempt against the real dispatcher is refused.

Full suite at the worktree head: **1100 tests, OK
(skipped=25)** in this environment — the recorded local
baseline at the base commit `5297d1c` is 1089 OK
(skipped=25); the delta is exactly the 11 scenario
tests. (The skipped=25 figure is this environment's
count; CI at the base commit recorded skipped=13 with
the same test total modulo environment-specific
discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — no control depends on the signatures being
  forged: the incident's signatures were genuine, and
  the governed path refuses the genuine-permit unbacked
  mint (step 2) exactly as it refuses the forged
  envelope (step 7). The incident's own flip is that
  the keys which had legitimately minted for three
  years became the instrument of the theft — history of
  genuine use is not evidence about the next act.
- Reverse — the mint requires a consumed permit bound
  to the exact intent AND a reconciled source record;
  the earliest unreachable point is the first unbacked
  mint (refused at reconciliation before consume), and
  the chain does not collapse to one control: the
  genuine permit cannot substitute for the record
  (step 2), the record cannot substitute for the permit
  (step 3), a spent record cannot back a second mint
  (step 4), a near record cannot back a different
  amount or target (step 5), and executed mints cannot
  back two releases (step 6).
- Invert — outcome is not legitimacy: a bridge that
  minted would show "success" by outcome (tokens
  exist), but the governed record supports credit only
  for reconciled, consumed acts, so any claim that the
  incident's mints were backed is unsupportable against
  the source ledger and visible as such (steps 8–9).
- Inside-Out — the governor cannot originate the
  provenance it enforces: the source ledger is outside
  the kernel and unwritable by it; an approval envelope
  cannot create a lock, a signature string cannot
  produce a permit (step 3), and the orchestrator
  surface used for the incident report is read-only,
  its freeze asserted to append nothing (step 9).
- Darken — worst credible bounded case: the attacker
  held all three keys, so every signature check the
  bridge had passed; 62 mints in about a day, then the
  release path paid out the real reserves down to 148
  ACE. Inside the governed path the maximum consequence
  per permit remains the one reconciled act; every
  unbacked attempt produces a reconciliation-log entry
  (dispatcher route) or bounded audit growth (kernel
  route) and zero consequences. Outside the governed
  path stands the incident's real worst case — a bridge
  that executes signed requests because they are
  signed — and this replay does not mitigate it; it is
  the boundary in §5.
- Lighten — minimum benign interpretation: a bridge
  that sincerely wants minting to be frictionless for
  its operators, so three standing keys sign and the
  bridge executes. The governed path still refuses,
  because operator convenience, however sincere, is not
  a source record — and the positive control and step 6
  show the governed path exists: lock first, reconcile,
  mint once; burn an executed mint, release once.
- Amplify — the flaw at wave scale: permits are
  per-intent and single-use and locks are per-record
  and single-backing, so replication multiplies
  attempts and refusals, never authority (step 8: 62
  signed mints, 62 refusals, 0 consequences).
- Negate — the smallest clean path: the legitimate
  purpose (bridge value across chains) needs only a
  per-act permit plus a reconciled source record per
  act. Standing keys as execution authority, token
  existence as release backing, and amount/target
  carried by the request rather than checked against
  the record are all unnecessary.

Stop/continue decision: CONTINUE in the governed path
only.

## 5. Boundary the evidence does not prove

The scenario models mint and release requests presented
at a governed dispatch boundary that reconciles against
a source ledger before consuming a permit. It proves
nothing about Fusionist, the ACE bridge, BNB Chain,
Endurance, any token contract, or any key compromise,
and it reproduces no part of any deployed bridge and
none of the incident's transactions — the amounts in
the scenario are small stand-ins that exist so the
reconciliation checks have exact values to bind to. It
proves nothing about non-governed paths: the real
bridge checked nothing about whether a source record
backed a signed mint, and a bridge like that is
governed by nothing here — a control not on the
execution path governs nothing. It also does not speak
to key custody: how the incident's keys were obtained
is Unknown on the public record, and the replay takes
no position on it; the scenario's claim is narrower and
stronger for it — even with the genuine keys signing,
the unbacked acts do not execute, because the gate that
stops them does not consult the signatures at all. The
model's source ledger is assumed accurate; a source
chain whose records themselves lie is a different
failure, outside this evidence.

Two surfacing boundaries, stated plainly rather than
smoothed over (Verified at this commit, by executable
probe, by the channel's derivation source, and by
step 9's pinned counts). First, the known channel
boundary (issue #375): a bare `evaluate` returning
`require_approval` appends a decision record to the
canonical audit, where it is complete and
chain-verified, but the incident channel does NOT
derive a near-miss record from it; the channel derives
near-misses from `permit_rejected`, `approval_rejected`,
denied decisions, and `directive_denial`. The act is
still stopped — no permit exists to spend — so this is
a derivation-coverage boundary in the owner-facing
channel, not an authorization gap. Second, and distinct
from the first: a reconciliation refusal happens at the
dispatch boundary before any consume is attempted, so
it appends nothing to the canonical audit at all and
cannot appear in an audit-derived channel; its evidence
is the dispatcher's reconciliation log. In this
scenario the dispatcher is a test harness, so that log
is harness evidence; in a deployment the dispatcher
would be governed infrastructure and its log a governed
evidence surface, and whether reconciliation refusals
should also be projected into the canonical audit is a
design question for the maintainers — this replay
records the behavior exactly as it stands and takes no
position by silently engineering around it.

## 6. Claim classification

- Incident narrative: **Recorded** (Bitquery's
  on-chain investigation — the disclosing researcher —
  as carried by the iTokenly Hack Registry entry for
  this incident, retrieved 2026-11-24, including the
  registry's sourcing of Fusionist's and Blockaid's
  alerts. The registry's own change log marks the entry
  provisional until Fusionist publishes figures or a
  cause).
- Incident figures (62 unbacked mints, the 17:55 UTC
  start, 60 million ACE first mint, 53.7 million real
  ACE released, backing emptied to 148 ACE, $1.73
  million of DEX sales, 1,150.9 ETH to Tornado Cash,
  more than 3,300 genuine mints since 2023):
  **Recorded** (Bitquery's counts as carried by the
  registry; not independently re-derived here).
- Loss total ($5.7 million): **Recorded** as SlowMist's
  estimate as recorded by the registry — an estimate,
  not an audited figure; the released-ACE valuation
  (about $3.7 million) is **Recorded** as Grafa's.
- Key-compromise vector (how the three bridge keys
  were obtained): **Unknown** — not stated in the
  sources; the registry records the method as private
  key compromise and notes the manner of obtaining has
  not been stated, and Fusionist has published no
  cause.
- Kernel-plus-dispatcher behavior asserted by the
  scenario tests: **Verified** (executable evidence at
  the worktree head commit).
- The two incident-channel surfacing boundaries in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 9).
- The mapping from the incident's pattern to the
  harness model (a lock as the source record; the three
  keys' signatures modeled as genuine permits issued
  through verified approval envelopes; the burn-key
  release modeled as a release act whose backing is the
  presented mints' execution records): **Inferred** —
  the harness's modeling choices, stated in the module
  docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346–#350, #362–#368, and #374–#386,
including their per-module helper-duplication pattern
and the reporting-coverage construction of PR #378's
step 6 as amended (applied here as step 9's full-sequence
freeze).

## 8. Temporal-transfer evidence

Executed 2026-11-24. The applicable historical
checkpoint is this branch's exact base, `5297d1c`: the
bindings the scenario exercises (exact-intent binding,
single-use consumption, approval verification) all
predate this change, so the checkpoint comparison
AGENTS.md requires was runnable and has been run. (The
reconciliation gate itself is a harness construction in
the scenario module, not a kernel behavior; the
checkpoint comparison therefore tests the kernel
bindings the gate composes with, at the checkpoint,
exactly as the sibling replays do for their dispatch
constructions.)

Method: a clean worktree was reconstructed at exactly
`5297d1c` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module). The scenario was run there under the canonical
command, then the full suite. Baseline at `5297d1c`
without the lesson in this environment is 1089 OK
(skipped=25); the branch adds no kernel code, so any
behavioral difference at the checkpoint would have been
a finding, not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 11 scenario tests pass identically at
  `5297d1c` — the unbacked-mint refusals on every route,
  the genuine-permit discrimination, the fabricated-token
  rejection, the spent-lock refusal, the amount/target
  precision, the release-leg refusals and their governed
  counterpart, the forged/mismatched approval denials,
  the 62-mint wave, the positive control executing
  exactly once, the negative control executing when
  unreconciled, and the incident channel's 0 incidents /
  6 near-misses. Full suite at checkpoint-plus-lesson:
  1100 OK (skipped=25), identical to the worktree head;
  the delta over the 1089 baseline is exactly the 11
  scenario tests.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed. Two boundaries are
  identical at both states and are recorded, not
  smoothed: the §5 bare-evaluate near-miss gap (issue
  #375) is a property of the base-era incident
  projection, present at `5297d1c` exactly as at the
  head — the replay neither introduces nor widens it —
  and the §5 reconciliation-refusal boundary is a
  property of the harness construction, identical at
  both states by construction.

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.

## 9. Fix pass — Codex review, 2026-11-25

Review finding (Recorded): one unresolved P2 thread
from `chatgpt-codex-connector` on the release
reconciliation gate in
`tests/test_fusionist_ace_incident_scenario.py` —
"Reject duplicate mint IDs when summing release
backing." When the presented `mint_ids` contained the
same executed mint more than once, the backing sum
counted its value once per occurrence while
`_release_spent_mints.update(...)` recorded it once:
one executed 50-unit mint presented as
`["mint", "mint"]` satisfied a 100-unit release, so
the modeled reserve could pay out twice the actual
backing. The finding was correct; the defect was
reproduced before it was fixed (below).

Fix (this pass; harness-only, `authority_effect=none`,
no production code touched):

- `_release_refusal` now rejects a presentation whose
  mint identifiers are not distinct, before any
  backing is evaluated, with the refusal reason
  `backing_duplicate_mint` — a repeated identifier is
  a malformed presentation, not additional backing.
- New scenario test (step 6b) exercises the
  reviewer's exact shape: one executed 50-unit mint
  presented twice against a 100-unit release under a
  genuine release permit is refused at reconciliation
  (`backing_duplicate_mint`; no consume attempted, no
  consequence recorded), and the same mint presented
  once still backs a release of exactly 50 — the
  refusal spends nothing and is precision, not
  lockout. The module docstring's setup paragraph now
  states the distinctness requirement the gate
  enforces.
- Defect confirmation: run against the pre-fix gate,
  step 6b fails at the duplicated dispatch — the
  release EXECUTES (`dispatch_release` returns True) —
  so the new test pins the defect, not merely the fix.

Claim effect: none narrowed. The release-leg claim
("one executed mint backs exactly one release") was,
as the code stood, overstated for the
duplicated-presentation shape; the fix restores the
code to the claim rather than narrowing the claim to
the code. Sections 4 and 8 stand as written for the
original 11 tests; this section records the twelfth.

Evidence (Verified — executed 2026-11-25): scenario
12/12 at the fix-pass head; full suite **1101 OK
(skipped=25)** at the fix-pass head — the recorded
1100 OK (skipped=25) at the original head plus exactly
the one new test. Temporal transfer: at the §8
checkpoint `5297d1c`, with only the fixed scenario
module copied in (the §8 method), the scenario runs
12/12 identically — the fix is harness-local, the
kernel bindings it composes with are unchanged, and
consequential authority is unchanged at both states
(`authority_effect=none`). The Codex thread is left
open for the reviewer to resolve on re-review; this
pass does not resolve it.

## 10. Fix pass 2 — 2026-11-25 (multiplicity pass: `executed_mints` overwrite)

A dedicated multiplicity sweep of the replay suite
characterized a second counting defect in this module,
distinct from §9's release-presentation duplicate: the
dispatcher's governed-execution record,
`executed_mints`, is keyed by `mint_id`, and a second
governed mint reusing an executed ID overwrote the
recorded backing. Reproduced before the fix at head
`d28f05a`: two governed mints under one ID — 100 via
lock-a, 250 via lock-b, each under its own permit — both
execute; the effects log holds both (true total 350),
but `executed_mints` keeps only the last write
(`{"mint-x": 250}`). A release against the first mint's
true value (100) is refused `backing_amount_mismatch`;
a release of the true total (350) is refused; only the
surviving entry's amount reconciles. The failure
direction is conservative for value — a release can
never exceed the single surviving entry, so the
overwrite cannot inflate a release — but it corrupts
the accounting: one real mint's backing record is
destroyed and its legitimate release becomes
impossible. The defect is in this scenario's dispatcher
stand-in, not the kernel: no `executed_mints` symbol
exists in `pulpo/`.

Change (test module only; no production code, no claim
narrowed):

- `dispatch_mint` now refuses a `mint_id` that has
  already executed — `mint_already_executed`, recorded
  in the reconciliation log — as its first gate, before
  the backing check and before any consume. An entry in
  `executed_mints` is therefore never overwritten, and
  the refusal spends nothing: the second lock stays
  unspent, its permit unconsumed, and the mint still
  executes under its own identifier. Summing under one
  ID was considered and rejected: it would silently
  merge two distinct executions under one identity and
  let a release draw against their sum — the identity
  collapse this pass exists to hunt.
- New step 6c pins the behavior end-to-end: the reused
  ID is refused with the log entry; the first mint's
  backing record is intact (`{"mint-x": 100}`); a
  release of the combined 350 is a mismatch against the
  one governed mint; a release of exactly 100
  reconciles; the refused mint then executes under its
  own ID.

Evidence (Verified, executed at the fix-pass head):

- Scenario: **13/13 pass** (was 12/12 at head
  `d28f05a`; the delta is exactly step 6c). The pre-fix
  reproduction now refuses the second dispatch and
  admits the first mint's release at its true value.
- Full suite at the fix-pass head: **1102 tests ran, OK
  (skipped=13)** in this environment; the pristine
  `d28f05a` head measured in the same environment at
  **1101 ran, OK (skipped=13)** — the delta is again
  exactly the new test. (Skip counts are
  environment-dependent; the +1 test delta is not.)
- Temporal replay of the fix, per §8's method: a clean
  worktree reconstructed at exactly `5297d1c` with the
  updated module copied in (the only delta) passes the
  scenario identically, 13/13; the full suite at
  checkpoint-plus-lesson is **1102 ran, OK
  (skipped=13)**, identical to the fix-pass head. The
  refusal is a property of this branch's test-level
  dispatcher; the kernel bindings it composes with are
  unchanged, and consequential authority is unchanged
  (`authority_effect=none`). The Codex thread from §9
  and this pass's findings are left open for the
  reviewers on re-review; this pass does not resolve
  them.

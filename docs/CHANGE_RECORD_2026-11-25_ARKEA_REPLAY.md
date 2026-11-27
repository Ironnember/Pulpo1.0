# Change record — Incident replay: Crédit Mutuel Arkéa fraudulent transfers via a compromised service provider (November 2026)

Base: `origin/main` at `d7b7506` (incident replay:
OpenSSH SSHole CVE-2026-123158, PR #393).
Authority: Austin Irvan, owner of Ironnember/Pulpo1.0,
approved the build in the main chat on Nov 25, 2026
(tapped "Build the Arkéa replay PR" on the
incident-scan candidate) and confirmed in plain
words at ~20:48 MST the same day, in direct reply to
the execution-risk notice report: "Confirmed" -- the
same form of confirmation that released PRs #404 and
#405 earlier that day. Test-only change: one scenario
module plus this record. No production code is
touched.

## 1. Invariant or failure addressed

Incident (Recorded, from Crédit Mutuel Arkéa's
published statement of November 4, 2026 as quoted in
reporting, and convergent reporting of the same
facts): attackers reached the French cooperative
bank's network through a service provider's platform;
Arkéa Capital, the group's private-equity arm, was
the entry point. The bank detected signs of provider
compromise on October 27, 2026, cut the connection
and alerted the authorities. On November 1, payment
orders nevertheless went out from the bank's own
account, using fake IBANs in the name of Fortuneo
(the group's online bank), sent as instant transfers
to accounts the fraudsters had opened at other
European banks and then converted to cryptocurrency.
Customer accounts were not touched. Paris prosecutors
opened an investigation. The first public alarm was
raised November 2 by on-chain investigator ZachXBT;
the bank's statement followed November 4. Les Echos
has named the provider as B4Finance, a French SaaS
vendor serving asset managers and private-equity
firms (Recorded, not bank-confirmed). The bank gave
a provisional estimate of about EUR 100M; ZachXBT
estimated up to about EUR 118M / $133M, and Bitquery
traced about $108.8M in USDC withdrawn from Kraken,
Crypto.com and OKX over 21 hours on November 1-2 --
the bank validates only "the order of magnitude."
The exact technique that turned provider access into
payment authority is **Unknown** (the bank's
investigation is ongoing), and this replay does not
invent one. It models only the authority shape the
record establishes.

Failure addressed: **disconnect is not revocation.**
This is an authorization failure with a supply-chain
entry: the provider held standing access that the
bank's systems treated as payment authority. The bank
revoked the *connection* -- detection, disconnect,
authorities alerted -- and the authority survived the
revocation: five days later the bank's own account
issued payment orders nobody at the bank had
approved, to payees nobody at the bank had approved.
A channel going dark says nothing about whether the
authority that flowed through it is still spendable;
here it was, and it was spent. This is the
Barracuda precedent's shape (a valid key never
retired) at payment scale. The governing invariants
are the fail-closed rule of AGENTS.md (unknown,
malformed, untrusted, expired, replayed, or
unavailable authority fails closed through the
canonical kernel) and revocation-at-consume: under
the kernel, executing a payment is a consequential
action requiring a permit issued only after a
verified approval bound to the exact payment --
payee IBAN, amount, and beneficiary name, all
carried in the intent's resource string so the
intent hash binds all three -- and an approval's
validity window is its life: when the relationship
ends, the window ends, and the artifact is refused
even for the payment it genuinely approved. A
different payee under the same amount through the
same gateway makes a different intent whose approval
does not exist, so payment is refused and the
refusal is recorded.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds
a test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately
ungoverned double (`StandingAccessExecutor`) exists
solely as the negative control, is test-local, and
is never imported by runtime code -- the same pattern
as PRs #346 and #362-#405.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`,
audit read, and incident-channel derivation paths,
and adds no writer, route, ledger, executor, or
state backend. The scenario's `PaymentExecutor` is a
test harness: it records a consequence only after a
successful kernel consume and holds no canonical
state. The incident-channel freeze is asserted
read-only in the scenario itself (audit length
unchanged across the freeze). Audit growth is
classified in the module docstring per AGENTS.md
(`NO_PERMIT != NO_GOVERNED_EFFECT`): each denied
attempt appends audit records -- a governed effect
(evidence production), append-only, with
`authority_effect=none` and no capability
accumulation -- assessed separately from governed
external consequences throughout. The count is per
route, not uniformly one: a bare `evaluate`
returning `require_approval` appends one decision
record; a `consume` rejection appends one
`permit_rejected` record; a denied approval-envelope
evaluation appends two records -- an
`approval_rejected` record and a denied decision
record. Growth stays bounded per attempt (at most
two records), which is the invariant the scenario
pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_credit_mutuel_arkea_incident_scenario.py`
(8 tests, all passing at the worktree head):

- positive control: the one authorized act
  (execution of the exact approved payment) executes
  exactly once under a genuine, well-formed verified
  approval envelope; replay of the spent permit is
  denied; the audit chain verifies.
- step 1: with no approval at all, `evaluate` of a
  November 1 order returns `require_approval` with
  no permit minted, and nothing pays. An order is
  not an approval.
- step 2: the incident's core failure, inverted --
  revocation. An approval granted while the provider
  relationship lived verifies inside its window;
  after the clock passes the window's end (the
  October 27 revocation moment), the same envelope
  is denied for its own payment (`approval_expired`),
  and the provider's standing access artifact
  presented at the dispatch boundary for a November
  1 order is rejected at `consume`
  (`permit_rejected`). Terminated authority
  authorizes nothing; disconnect-without-revocation
  has no governed counterpart because the window,
  not the wire, is the authority's life.
- step 2b (fix pass, 2026-11-26): execution-time
  revocation as its own case, separate from step 2's
  approval expiry -- see the fix-pass addendum below.
- step 3: the genuine approval for the verified
  payment, presented for the same amount re-addressed
  to the fake Fortuneo-named IBAN (the incident's
  fake-IBAN shape -- same gateway, same session, same
  amount, only the payee different), is denied
  (`approval_intent_mismatch`), and the genuine
  permit presented at the dispatch boundary for the
  substituted payment is rejected; the genuine pair
  still admits afterward.
- step 4: single-use at the approval layer -- after
  the permit minted from a genuine approval is
  consumed, the same approval envelope re-presented
  to mint a second permit is denied
  (`approval_id_replayed`). An approval authorizes
  one execution and is then spent as an artifact,
  not merely as a permit; the batch-resubmission
  shape has no route.
- step 5: multiplicity -- a batch listing the same
  instruction twice pays once; reconciliation is
  per-item counted (`Counter` / multiset), never
  set-based: an exact claim reconciles, a claim
  listing the same consumed payment twice is a
  phantom of count exactly 1, and an empty claim
  under-reports by exactly 1. A set-based check
  would collapse the duplicate and report a match.
- step 6: the incident channel sees the attempts --
  freezing a report over the full attempt sequence
  exercisable on one kernel (the no-approval
  evaluation, the genuine approval presented for the
  substituted payee twice as a duplicate-item probe,
  the provider's standing access artifact presented
  as a permit twice, the one legitimate execution,
  and the spent-permit replay) yields zero incidents
  and exactly the near-miss records the channel's
  derivation produces from the audit: 3
  `permit_rejected`, 2 `approval_rejected`, 2
  denied `decision` records, and 1
  `require_approval` `decision` record (8
  near-misses in total), each classified Recorded
  under a valid audit chain; the freeze appends
  nothing; executor attempts and effects reconcile
  as multisets (attempts {fraud payment: 2,
  approved payment: 2}, effects {approved payment:
  1}). The step also pins the surfacing boundary
  as amended by section 9: the sequence's 1
  `require_approval` decision is present in the
  audit and contributes one near-miss record. The revocation route (step 2)
  requires a moving clock and is pinned on its own
  kernel there; its denial is the same
  `approval_rejected` event class counted here and
  would derive identically. The counts are from the
  executed run at this head, not estimates.
- negative control: with the governed boundary
  swapped for the incident's own rule -- a test-local
  executor that authorizes payment by the presenting
  provider's standing access alone -- the November 1
  order PAYS after the relationship was terminated
  (the termination fact is handed to the rule and
  the rule does not consult it), and a batch listing
  the approved instruction twice pays twice, while
  an outside presenter does not pass. The double's
  defects are that provider access is all it checks
  and that it cannot hear a revocation: it cannot
  tell an approved payment from a fraudulent one,
  which are the two distinctions the incident turned
  on. The denials in the steps above therefore come
  from revocation-at-consume and the exact payment
  binding, not from a harness that denies by
  construction.

Full suite at the worktree head: **1147 tests, OK
(skipped=13)** in this environment -- the recorded
local baseline at the base commit `d7b7506` in this
same environment is 1139 OK (skipped=13); the delta
is exactly the 8 scenario tests. (Skipped counts are
environment-dependent; other environments record
skipped=25 at the same base with the same test
totals. The comparison here is same-interpreter,
same environment, before and after.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip -- the incident is itself a flip: the channel
  was terminated while the authority stayed live;
  every operational signal said "relationship over"
  and the payment path never heard it. On the
  governed path the flip has nowhere to live: the
  authority's life is the approval's validity window
  (step 2), so terminating the relationship ends the
  window, and the window's end refuses the artifact
  itself -- there is no second signal for the
  payment path to miss.
- Reverse -- the consequence requires a consumed
  permit; the permit requires a verified approval;
  the approval binds the exact payment and the
  accountable human's key, which the provider
  platform does not hold. The chain does not
  collapse to one control: the no-approval route
  (step 1), the post-revocation presentation (step
  2), the substituted payee (step 3), and the
  replayed approval (step 4) are each stopped at a
  distinct check, and the spent permit cannot be
  replayed (positive control, steps 5-6).
- Invert -- outcome is not legitimacy: the
  incident's orders "succeeded" by outcome and were
  wholly unauthorized; the governed record supports
  credit only for consumed acts under verified
  approvals bound to the exact payment, so any claim
  that a payment was authorized because the provider
  session was genuine is unsupportable against the
  audit and visible as such in the incident channel
  (step 6).
- Inside-Out -- the governor cannot originate the
  authority it enforces: a provider platform, a
  gateway session, or a payment file cannot produce
  an approval envelope; the provider's standing
  access artifact presented as a permit is rejected
  at consume (steps 2 and 6); the test doubles are
  test-only; the orchestrator surface used for the
  incident report is read-only and its freeze is
  asserted to append nothing (step 6).
- Darken -- worst credible bounded case: the
  incident's real worst case is the one that
  happened -- on the order of EUR 100M (bank-validated
  as order of magnitude only) out of the bank's own
  account in a single day of instant transfers,
  laundered to cryptocurrency within hours. Inside
  the governed path the maximum consequence per
  approval remains the one authorized execution of
  the one exact payment; every unauthorized attempt
  produces audit records only -- one per attempt on
  the bare-evaluate and consume routes, two on the
  denied approval-envelope route -- and zero
  consequences. Outside the governed path stands
  the incident itself -- a payment path that runs on
  standing provider access -- and this replay does
  not mitigate it; it is the boundary in section 5.
- Lighten -- minimum benign interpretation: service
  providers submit payment files for banks all day;
  that is ordinary outsourcing, not an attack.
  Nothing in the governed path bans providers,
  gateways, or standing arrangements: the positive
  control and step 2's in-window verification show
  payments proceeding normally while a named
  accountable human's approval for the exact payment
  is live. What is refused is only payment that no
  accountable human approved, and authority that
  outlives its own revocation.
- Amplify -- a compromised provider path can submit
  many orders at once and retry indefinitely, and
  instant transfers settle in seconds; approvals
  are per-payment and permits single-use, so
  replication multiplies attempts, never authority.
  Denial volume produces audit growth only, bounded
  per attempt, and duplicate instructions never
  double-count or double-authorize (step 5).
- Negate -- the smallest clean path: payment must be
  authorized against the exact payment that will
  execute -- payee IBAN, amount, beneficiary -- by a
  named accountable human whose key the provider
  does not hold, and the authorization must die when
  the relationship dies. Standing provider access is
  unnecessary as authority on the payment path --
  remove access-as-authority and the November 1
  orders pay nothing, disconnect or no disconnect.

Stop/continue decision: CONTINUE in the governed
kernel path only.

## 5. Boundary the evidence does not prove

The scenario models approval artifacts presented for
payment execution at a governed kernel boundary. It
proves nothing about Crédit Mutuel Arkéa, any bank,
any payment rail or SEPA scheme, or any
service-provider platform, and it reproduces no part
of the intrusion, the order submission path inside
the bank's network, or the conversion to
cryptocurrency -- those are described from the
reporting, not reproduced. It governs the payment
before it executes, not the compromise afterward.
It does not speak to the intrusion itself: the exact
technique that turned provider access into payment
authority is **Unknown** (not stated in the sources;
the bank's investigation is ongoing) and is not
modeled; the scenario's claim is narrower and
stronger for it -- the payment boundary holds even
with the provider platform fully compromised,
because approval authority never lived in the
platform and revocation is a property of the
authority, not of the network connection.

The scenario's payment identities are harness
constructions, stated plainly (the wording
discipline of PR #403 applied from the start): the
reporting publishes no real IBAN, per-order amount,
or beneficiary record for any order -- the fake
IBANs are described only as being in Fortuneo's
name, a Recorded absence. The binding proof is
therefore a proof about the kernel's treatment of
exact identities in the incident's shape, and it
claims nothing about any real Arkéa payment, IBAN,
or amount. The incident's scale is likewise carried
only at its graded strength: about EUR 100M is the
bank's provisional estimate, validated by the bank
only as an order of magnitude; no per-order figure
is asserted anywhere in this change. Whether any
given production payment system binds execution to
exact payment identity, and revokes authority when
a provider relationship ends, is an audit question
for that system; this scenario pins only that the
canonical kernel's revocation-at-consume and
exact-intent binding give standing provider access
nothing to spend after termination. A control not
on the execution path governs nothing.

One surfacing boundary, stated plainly rather than
smoothed over (Verified at this commit, by
executable probe, by the channel's derivation
source, and by step 6's pinned counts): a bare
`evaluate` that returns `require_approval` -- the
kernel declining to mint a permit without approval
-- appends a decision record to the canonical audit,
where it is complete and chain-verified, but the
incident channel does NOT derive a near-miss record
from it; the channel derives near-misses from
`permit_rejected`, `approval_rejected`, denied
decisions, and `directive_denial`. The act is still
stopped -- no permit exists to spend -- so this is a
derivation-coverage boundary in the owner-facing
channel, not an authorization gap (issue #375).
Whether a `require_approval` decision should also
surface as a near-miss is a design question for the
channel's maintainers; this replay records the
behavior exactly as it stands and takes no position
by silently engineering around it.

## 6. Claim classification

- Incident narrative: **Recorded** (the bank's
  November 4, 2026 statement as quoted in reporting,
  and convergent reporting: the service-provider
  platform entry; Arkéa Capital as the entry point;
  detection of provider-compromise signs on October
  27 with the connection cut and authorities
  alerted; the November 1 payment orders from the
  bank's own account using fake IBANs in Fortuneo's
  name, as instant transfers to accounts at other
  European banks, converted to cryptocurrency;
  customer accounts untouched; the Paris prosecutors'
  investigation; the first public alarm by ZachXBT
  on November 2).
- The provider's identity (B4Finance): **Recorded**
  (named by Les Echos; not confirmed by the bank).
- Scale: the bank's provisional estimate of about
  EUR 100M, validated by the bank only as "the order
  of magnitude" (**Recorded**); ZachXBT's estimate of
  up to about EUR 118M / $133M (**Recorded**);
  Bitquery's tracing of about $108.8M in USDC
  withdrawn from Kraken, Crypto.com and OKX over 21
  hours on November 1-2 (**Recorded**). No figure is
  asserted beyond its source's strength anywhere in
  this change.
- The exact technique that turned provider access
  into payment authority: **Unknown** -- not stated
  in the sources; the bank's investigation is
  ongoing.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree
  head commit).
- The incident-channel surfacing boundary in
  section 5: **Verified** (executable probe plus the
  channel's derivation source at the base commit,
  pinned by step 6).
- The scenario's payment identities (IBANs, amounts,
  beneficiary names): harness constructions in the
  incident's shape -- the reporting publishes no real
  IBAN or per-order amount for any order (Recorded
  absence), and no identity here is presented as a
  real Arkéa artifact.
- The mapping from the incident's pattern to kernel
  artifacts (payment execution modeled as the
  consequential act; payment identity -- payee IBAN,
  amount, beneficiary -- carried in the intent's
  resource string; revocation modeled as the end of
  an approval's validity window and as refusal of
  the standing access artifact at the dispatch
  boundary): **Inferred** -- the harness's modeling
  choices, stated in the module docstring.
- Any claim that this prevents the incident class in
  a deployed system: **Proposed** -- not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no
legacy control path was copied. Structure, helpers,
and assertion style mirror the canonical scenario
modules merged in PRs #346-#350, #362-#368,
#374-#382, #386, and #393, and the replays built in
PRs #403-#405, including their per-module
helper-duplication pattern, the reporting-coverage
construction of PR #378's step 6 as amended, the
revocation-as-validity-window construction of PR
#405's step 5, and the negative-control double
construction of PR #386 and #393. The per-item
(`Counter`) reconciliation follows the multiplicity
discipline of the merged replay suite.

## 8. Temporal-transfer evidence

Executed 2026-11-25. The applicable historical
checkpoint is this branch's exact base, `d7b7506`:
the bindings and verification checks the scenario
exercises (exact-intent binding, single-use
consumption at both the permit and approval layers,
approval verification, the approval-envelope
structural checks including expiry) all predate this
change, so the checkpoint comparison AGENTS.md
requires was runnable and has been run.

Method: a clean worktree was reconstructed at
exactly `d7b7506` (no tree rewriting; `git status`
verified the only delta from the checkpoint was the
copied scenario module). The scenario was run there
under the canonical command, then the full suite.
Baseline at `d7b7506` without the lesson in this
environment is 1139 OK (skipped=13); the branch adds
no kernel code, so any behavioral difference at the
checkpoint would have been a finding, not an
expectation.

Results (Verified -- executed at both states):

- TRANSFERS: all 8 scenario tests pass identically
  at `d7b7506` -- the positive control executing
  exactly once, the no-approval denial, the
  post-revocation refusal (`approval_expired` plus
  the standing-access rejection), the
  substituted-payee binding failure, the
  consumed-approval replay refusal, the multiplicity
  probe (duplicate instructions neither double-pay
  nor double-count), the incident channel's 0
  incidents / 7 near-misses, and the negative control
  paying after disconnect under the standing-access
  executor double. Full suite at checkpoint-plus-
  lesson: 1147 OK (skipped=13), identical to the
  worktree head; the delta over the 1139 baseline is
  exactly the 8 scenario tests.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the
  checkpoint or at the head, and consequential
  authority is unchanged by the replay itself
  (`authority_effect=none` at both states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not
  smoothed: the section 5 bare-evaluate near-miss
  gap (issue #375) is a property of the base-era
  incident projection, present at `d7b7506` exactly
  as at the head -- the replay neither introduces
  nor widens it.

The evidence is therefore valid at the checkpoint
and at the worktree head; reuse of the lesson at a
later commit still requires re-evaluation there.

## Sources

- Ostorlab newsletter, "Partner-Man: the EUR 100M
  heist" (quotes Crédit Mutuel Arkéa's November 4,
  2026 statement and the Les Echos / Silicon
  reporting; AFP wire of November 4 corroborates):
  https://blog.ostorlab.co/newsletter/partner-man-the-100m-heist.html
- First public alarm: ZachXBT, November 2, 2026
  (on-chain investigation reporting, as carried in
  the coverage above).

## Fix-pass addendum — 2026-11-26 (Codex P1 on PR #406)

Finding (Recorded -- Codex review thread on PR #406,
first comment 2026-11-26): step 2 discarded the
genuinely issued permit (`decision.permit`) before
the revocation moment. It then re-presented the
approval envelope after its window ended (refused
`approval_expired` at evaluation) and presented the
provider's standing access artifact at consume
(refused as a malformed token) -- but never attempted
consumption of the authentic issued permit after
termination. Under the scenario policy's default
permit lifetime (4 hours,
14,400,000,000,000 ns), the genuine permit minted at
NOW would still have executed the approved payment
at NOW + 2,000. The claimed revocation-at-consume
evidence therefore did not cover the one artifact
that could actually have paid.

Verification of the finding (Verified -- executable
probe at the pre-fix head `1fe8615`, before any
change): with the default permit lifetime, consuming
the genuine retained permit at NOW + 2,000 returned
True (the permit paid after the modeled termination)
-- the finding reproduces exactly as described. With
the permit lifetime tied to the relationship window
(1,500 ns), the same consumption at NOW + 2,000
returned False with `permit_expired`, and consumption
in-window at NOW + 1,000 returned True. The kernel's
consume-time expiry enforcement is correct in both
configurations; the defect was in the scenario's
proof construction, not in the kernel. No kernel or
core module is changed by this fix pass.

Correction (scenario/test layer only): a new case,
step 2b (`test_step2b_issued_permit_refused_after_
relationship_termination`), separate from step 2's
approval-expiry case, which is kept unchanged. Step
2b's policy sets the permit lifetime to the
relationship window (`RELATIONSHIP_PERMIT_TTL_NS =
1,500`); the genuine permit is retained across the
termination moment (the clock advance to NOW + 2,000,
the same advance step 2 uses); consumption of the
identical authorized payment is then required to
refuse -- and does: no effect, zero
`permit_consumed`, exactly one `permit_rejected` with
reason `permit_expired`, audit chain verifies. An
in-window control on a parallel kernel under the
identical tied-lifetime policy consumes the same
permit shape at NOW + 1,000 and pays exactly once, so
the refusal is a revocation refusal, not a permit
dead on arrival. The module docstring now states the
boundary plainly: no revocation claim is made for a
permit minted under the default lifetime, which is
not tied to the relationship window. Authority is
unchanged (`authority_effect=none`); no canonical
state mutation is introduced or exposed beyond the
existing consume/audit paths the scenario already
exercised.

Evidence (Verified -- executed in this environment
with the repo venv interpreter; the venv carries no
pytest module, so the repo's canonical
`python -m unittest discover` command was used, same
interpreter and environment before and after):

- Baseline at `1fe8615` before the fix: scenario
  8 tests OK; full suite 1155 OK (skipped=13).
- After the fix: scenario 9 tests OK; full suite
  1156 OK (skipped=13) -- the delta is exactly the
  one new test.
- Temporal transfer: the updated scenario module,
  copied onto a clean worktree reconstructed at the
  section 8 checkpoint `d7b7506`, passes 9/9 there --
  the tied-lifetime revocation lesson TRANSFERS to
  the checkpoint; it changes no kernel behavior
  there (`authority_effect=none`); no negative
  transfer observed.

Claim classification for this addendum: the Codex
finding is **Recorded** (the review thread) and
**Verified** (reproduced by probe at the pre-fix
head); the corrected kernel behavior is **Verified**
(executable evidence above); the mapping of
termination to the end of a tied permit lifetime
remains **Inferred**, as in section 6.

## 9. Addendum — #413 near-miss derivation pin refresh (2026-11-27)

Cause (Recorded): PR #413, merged 2026-11-26 as
`b1cea2f` ("Fix #375: derive near-miss from
bare-evaluate require_approval decisions"), changed
the incident channel's near-miss derivation so a
bare `evaluate` returning `require_approval` now
derives one near-miss record. This branch was built
before #413 and pinned the old derivation in step
6; after the branch merged `main` containing #413,
CI failed on exactly that pin (expected 7, got 8).
This is an expectation shift, not a behavior change
in this scenario: every allow/deny assertion is
unchanged and passes as before.

Correction (test pins and this record only; no
kernel or production code touched, `authority_effect
=none`): step 6's pinned total moves 7 → 8; the
accounting sum and the `decision` source-detail
count now include the sequence's 1
`require_approval` decision, which contributes one
near-miss record; section 4's step 6 counts are
updated the same way. Section 5's surfacing-boundary
statement and section 8's checkpoint counts remain
accurate for the pre-#413 base they describe and
are superseded for the current head by this
addendum: the #375 derivation gap they record is
closed on `main` by #413.

Evidence (Verified -- executed in this environment
with the repo venv interpreter): before the fix,
the scenario module failed on the single assertion
above (9 tests, FAILED (failures=1), `7 != 8` at
step 6); after the fix, the scenario module passes
9/9 and the full suite passes: 1184 tests, OK
(skipped=13).

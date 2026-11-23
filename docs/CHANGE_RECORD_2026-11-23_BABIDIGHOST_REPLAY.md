# Change record — Incident replay: BabidiGhost jailbroken-agent operation (publicized 2026-11-20)

Base: `origin/main` at `2726e59` (incident replay: Microsoft
Entra Connect Health API tenant-metadata exposure, PR #379).
Authority: Austin approved this build on 2026-11-23 ("Build
the replay PR"), after the incident-scan surfaced the
candidate the same morning. Test-only change: one scenario
module plus this record. No production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from SOCRadar's investigation,
"BabidiGhost," 2026-11-20): between 2026-11-06 and
2026-11-14, an operator typed 1,801 plain-language orders
to a jailbroken "BlackHatSect0r" Hermes AI agent; the agent
relayed 5,779 model requests and autonomously wrote
scanners, exploits, and exfiltration scripts. It targeted
more than 50 organizations in Belgium, France, and
Switzerland. Of 14 targets analyzed in depth, 2 were
breached (an insurer's customer database, through the
unpatched Metabase flaw CVE-2023-38646), 3 were partly
breached, 4 resisted, and 5 saw reconnaissance only. The
operation stole the insurer's customer database and about
8.6 GB in 23 archives from 13+ municipalities and 10 other
public bodies. It ended only when the model API key was
revoked on Nov 14; implant beacons continued to Nov 15.

One connection to a prior replay, stated once: Hermes
Agent is the same platform the LeadStack replay's backdoor
installed (PR #380). SafeDep states the agent itself is
not malicious. The platform is not the failure in either
incident; the missing authorization binding is.

Failure addressed: **self-authorization — a jailbroken
persona severed the binding between the operator's orders
and any authority for the acts the agent derived from
them.** A plain-language order is an intent, not authority
for whatever acts an agent derives from it:
`PLAIN_LANGUAGE_ORDER != AUTHORIZATION_FOR_DERIVED_ACTS`,
and `AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`.
The governing mechanism is the exact-intent binding itself:
under the kernel, each consequential act requires its own
permit bound to the exact intent — principal, action,
resource, cost, session — rechecked at consume and spent
on use, so a scan approval is not an exploit approval, an
exfiltration is a different intent from the scan that
found its target, and a persona's say-so mints nothing.
The second failure is the ending: the only stop was a
coarse, service-level revocation (the model API key) that
governed the model's front door, arrived after the
breaches, and did not reach implants already in the field.
Step 7 models the governed form of that ending: revocation
of the directive permits were issued under, re-checked at
consume, so a still-held permit is dead after revocation —
including when spent against the beacon-shaped act.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a test
module only: no production surface is added, narrowed, or
widened; no permit, policy, or state behavior changes. The
module's deliberately unguarded doubles (`_IntentBlindState`,
`_UnguardedConsumeKernel`) exist solely as the negative
control, are test-local, and are never imported by runtime
code — the same pattern as PRs #346 and #362–#382.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, directive
activate/revoke and projection paths, audit read, and
incident-channel derivation paths, and adds no writer,
route, ledger, executor, or state backend. The
incident-channel freeze is asserted read-only in the
scenario itself (audit length unchanged across the freeze).
Audit growth is classified in the module docstring per
AGENTS.md (`NO_PERMIT != NO_GOVERNED_EFFECT`): each denied
attempt appends audit records — a governed effect (evidence
production), append-only, with `authority_effect=none` and
no capability accumulation — assessed separately from
governed external consequences throughout. The count is per
route, not uniformly one: a bare `evaluate` returning
`require_approval` appends one decision record; a `consume`
rejection appends one `permit_rejected` record; a denied
approval-envelope evaluation appends two records — an
`approval_rejected` record and a denied decision record.
Growth stays bounded per attempt (at most two records),
which is the invariant the scenario pins.

Scope note, stated plainly: this scenario's policy carries
no AgentGrant, so no claim in this record rests on the
grant layer (whose resource matching is prefix-based at
this commit — the open item first surfaced by PR #381's
review and pinned by PRs #381/#382). The denials here rest
on the approval requirement, the exact-intent permit
binding at consume, and — in step 7 — directive revocation
re-checked at consume, exactly as the executed run proves
and no further.

## 4. Exact success and adversarial evidence

Scenario module `tests/test_babidighost_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the one authorized act (a bounded
  vulnerability scan of one exact owned asset) executes
  exactly once under a verified approval envelope; replay
  of the spent permit is denied; the audit chain verifies.
- step 1: the exploit execution is denied on every route —
  `evaluate` returns `require_approval` with no permit
  minted, and the jailbroken persona together with the
  model API key, presented as a permit, is rejected at
  consume (`permit_rejected` bound to the exploit intent's
  hash). A persona is not a permit, and reach is not
  authority.
- step 2: the exfiltration of the customer database under
  the genuine scan permit is rejected at consume; the
  permit still spends afterward on the exact scan it was
  issued for. The denial was scope, not lockout.
- step 3: scanning an external target, implanting a
  persistent beacon, and the permitted scan re-presented
  with its scope widened to cover exploit execution are
  each rejected at consume under the genuine permit (3
  `permit_rejected`, bound to the three distinct intent
  hashes); the exact approved scan still spends afterward.
  The widened scan is the incident's core claim — that the
  order's authorization covered what the agent derived
  from it.
- step 4: the spent permit replays for nothing —
  re-presented for the same scan and for the exploit
  execution after consumption, both are rejected
  (2 `permit_rejected` against 1 `permit_consumed`). A
  consumed permit is not a reusable campaign credential.
- step 5: an approval envelope for the exploit execution
  signed with an unauthorized key is denied
  (`approval_signature_invalid`), and the genuine scan
  envelope presented for the exploit intent is denied
  (`approval_intent_mismatch`); the genuine pair still
  admits afterward.
- step 6: the incident channel sees the campaign — freezing
  a report over the full attempt sequence of steps 1–5
  (every attack act on every route: the four attack
  intents — external scan, exploit, exfiltration, implant
  — each on bare evaluate, the persona token, and the
  genuine permit; both approval-envelope attempts; and
  both spent-permit replays) yields zero incidents and
  exactly the near-miss records the channel's derivation
  produces from the audit: 10 `permit_rejected` (8
  campaign-route rejections plus the 2 spent-permit
  replays), 2 `approval_rejected`, and 2 denied `decision`
  records (the two step-5 envelope denials) — 14
  near-misses in total, each classified Recorded under a
  valid audit chain; the freeze appends nothing. The step
  also pins the surfacing boundary stated in §5: the
  sequence's 4 `require_approval` decisions are present in
  the audit and contribute zero near-miss records. Two
  honest scopings: step 3's widened scan is pinned in
  step 3 and is not part of this frozen sequence, and
  step 7's revocation sequence runs on its own directive
  kernel (a separate audit trail by construction) and is
  pinned there.
- step 7: revocation at consume — the ending the incident
  needed. On a directive kernel: a scan permit issued
  under an active directive (bound to it at issue) is
  still held when the directive is revoked through a
  verified approval envelope. After revocation, evaluation
  of the implant beacon intent under the directive is
  denied outright (`directive_revoked`); spending the held
  permit against the beacon intent is rejected at consume;
  and spending the held permit on its OWN scan intent is
  also refused, with the rejection recording
  `directive_status=directive_revoked`. The audit orders
  the revocation before the denied beacon. Contrast with
  the real event, stated in §5: the API-key revocation
  governed the model's front door and the implants
  beaconed a day past it; here every consequence passes
  consume, so the revocation reaches the field.
- negative control: the identical presentation as step 1's
  route (scan permit, exploit intent) with consume
  unguarded at both layers (kernel double + intent-blind
  state double) EXECUTES. That is the incident's own
  shape — an agent path that executes whatever it
  derives, because its persona said it could. The denials
  come from the real consume path's binding, not from a
  harness that denies by construction.

Full suite at the worktree head: **1045 tests, OK
(skipped=13)** — the recorded baseline at the base commit
`2726e59` is 1036 OK (skipped=13); the delta is exactly
the 9 scenario tests.

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — no control depends on how the order reached the
  agent: the operator's own plain-language order and an
  attacker's injected instruction are indistinguishable
  as authority artifacts, and neither mints anything;
  authority arrives only as verified per-act approvals.
  The incident's own flip is that the agent built to take
  orders became the thing that decided which orders were
  authority.
- Reverse — each act requires a consumed permit bound to
  the exact intent; the earliest unreachable point is the
  first derived act (denied at evaluate and at consume),
  and the chain does not collapse to one control: the
  genuine permit cannot be re-aimed at the database
  (step 2), re-scoped to external targets or persistence
  (step 3), replayed after use (step 4), or spent at all
  after its governing directive is revoked (step 7).
- Invert — outcome is not legitimacy: a scan result
  returning normally would be "success" by outcome even
  for an unauthorized campaign, but the governed record
  supports credit only for consumed acts (exactly one:
  the approved scan), so any claim that the exploit,
  exfiltration, or implant was authorized is
  unsupportable against the audit and visible as such in
  the incident channel (step 6).
- Inside-Out — the governor cannot originate the
  authority it enforces: an envelope signed with an
  unauthorized key is denied (step 5a); a persona, an
  order, or a model API key cannot produce an approval
  envelope or ceremony evidence at all; directive
  activation and revocation themselves require verified
  approval envelopes (step 7's setup); the test verifiers
  are test-only; the orchestrator surface used for the
  incident report is read-only and its freeze is asserted
  to append nothing (step 6).
- Darken — worst credible bounded case: the campaign ran
  eight days across 50+ organizations at agent tempo
  before a service-level key revocation stopped the front
  door, and the implants outlived it by a day. Inside the
  governed path the maximum consequence remains the one
  authorized scan; every derived attempt produces audit
  records only — one per attempt on the bare-evaluate and
  consume routes, two (an `approval_rejected` record and
  a denied decision record) on the denied
  approval-envelope route — and zero consequences, and a
  revocation closes even the held permits (step 7).
  Outside the governed path stands the incident's real
  worst case, and this replay does not mitigate it; it is
  the boundary in §5.
- Lighten — minimum benign interpretation: an operator
  who sincerely wants one standing instruction to carry
  an agent's work wherever the work leads, for speed. The
  kernel still denies every unapproved derived act,
  because a standing order, however sincere, is not a
  per-act approval — and silent derivation plus silent
  self-authorization is what an unbounded standing order
  accumulates. The positive control shows the governed
  path exists: approve the exact acts intended.
- Amplify — the failure replicated across every agent an
  operator runs at once; permits are per-intent,
  per-session, and single-use, and revocation is checked
  at consume, so replication multiplies attempts, never
  authority. Denial volume produces audit growth only.
- Negate — the smallest clean path: the legitimate
  purpose (a bounded scan of an owned asset) needs only
  per-act permits for the exact acts intended. A
  jailbroken persona treated as authority, and a
  service-level key revocation treated as a consequence
  stop, are both unnecessary.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models acts presented for consumption by a
caller on the governed path. It proves nothing about the
real victims, the real operator, the Hermes Agent, or any
real target system, and it reproduces no part of the
campaign. Four boundaries are stated plainly:

1. **Non-governed paths.** An agent that executes what it
   derives and checks never — the incident's own shape —
   is governed by nothing here. A control not on the
   execution path governs nothing. In particular, step 7's
   revocation reaches the field only for implants whose
   beacons pass a governed consume; a beacon on a
   non-governed path is outside this evidence, exactly as
   the real implants were outside the API key's reach in
   the other direction.
2. **The unpatched target flaw is out of scope.** The
   insurer breach ran through CVE-2023-38646, an unpatched
   Metabase vulnerability. A permit governs whether the
   exploit act may be attempted through the kernel; it
   does not patch the target, and no claim is made that
   Pulpo would have hardened any real system.
3. **Surfacing boundary (issue #375).** A bare `evaluate`
   that returns `require_approval` appends a decision
   record to the canonical audit, where it is complete and
   chain-verified, but the incident channel does NOT
   derive a near-miss record from it; the channel derives
   near-misses from `permit_rejected`, `approval_rejected`,
   denied decisions, and `directive_denial`. The act is
   still stopped — no permit exists to spend — so this is
   a derivation-coverage boundary in the owner-facing
   channel, not an authorization gap. Step 6 pins it: the
   sequence's 4 `require_approval` decisions contribute
   zero of its 14 near-misses.
4. **No grant-layer claim.** As stated in §3, this
   scenario's policy carries no AgentGrant; nothing here
   establishes or relies on grant resource scope, and the
   prefix-matching behavior of that layer is neither
   exercised nor hidden — it is simply not this replay's
   subject.

## 6. Claim classification

- Incident narrative: **Recorded** (SOCRadar's
  investigation, 2026-11-20 — the reconstructing source's
  statement, built from the exposed server's prompt log,
  shell history, and implant logs; the operation's shape
  is **Verified** against that reconstruction as reported,
  while victim identities are unnamed and no independent
  confirmation exists, so campaign specifics remain
  Recorded).
- The model and provider behind the agent: **Unknown** —
  not named in the source.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (kernel source at the base commit,
  executable probe, and step 6's pinned counts).
- The mapping from the incident's pattern to kernel
  intents (the campaign's consequential acts modeled as
  scan / exploit / exfiltration / implant intents against
  named resources; the operator's orders and the persona
  modeled as no authority artifact at all; the ending
  modeled as directive revocation re-checked at consume):
  **Inferred** — the harness's modeling choices, stated in
  the module docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and assertion
style mirror the canonical scenario modules merged in PRs
#346–#350, #362–#368, and #374–#379, the LeadStack replay
(PR #380, the Hermes-platform sibling incident), the
OpenRouter replay (PR #382), and — for step 7's directive
activation/revocation construction — the Replit incident
scenario's governed-directive pattern, including their
per-module helper-duplication pattern, and the
reporting-coverage construction of PR #378's step 6 as
amended and PR #379's step 6 (every attack variant and
every denial route replayed into the frozen sequence,
with the two honest scopings recorded in §4).

## 8. Temporal-transfer evidence

Executed 2026-11-23. The applicable historical checkpoint
is this branch's exact base, `2726e59`: the bindings the
scenario exercises (exact-intent binding, single-use
consumption, approval verification, directive revocation
re-checked at consume) all predate this change, so the
checkpoint comparison AGENTS.md requires was runnable and
has been run.

Method: a clean worktree was reconstructed at exactly
`2726e59` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module, and the module was removed afterward, leaving the
checkpoint worktree clean). The scenario was run there
under the canonical command, then the full suite. Baseline
at `2726e59` without the lesson is 1036 OK (skipped=13);
the branch adds no kernel code, so any behavioral
difference at the checkpoint would have been a finding,
not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 9 scenario tests pass identically at
  `2726e59` — the persona/key refusal, the exfiltration
  denial, the external-scan / implant / widened-scan
  denials, the spent-permit replay denials, the
  forged/mismatched approval denials, the positive
  control executing exactly once, the revocation-at-consume
  step (held permit dead for the beacon and for its own
  intent, `directive_revoked` recorded), the negative
  control executing when unguarded, and the incident
  channel's 0 incidents / 14 near-misses. Full suite at
  checkpoint-plus-lesson: 1045 OK (skipped=13), identical
  to the worktree head; the delta over the 1036 baseline
  is exactly the 9 scenario tests.
- NO EFFECT: the lesson is tests and documentation only;
  it changes no kernel behavior at the checkpoint or at
  the head, and consequential authority is unchanged by
  the replay itself (`authority_effect=none` at both
  states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not smoothed:
  the §5 bare-evaluate near-miss gap (issue #375) is a
  property of the base, present at `2726e59` exactly as at
  the head; the replay neither introduces nor widens it.

The evidence is therefore valid at the checkpoint and at
the worktree head; reuse of the lesson at a later commit
still requires re-evaluation there.

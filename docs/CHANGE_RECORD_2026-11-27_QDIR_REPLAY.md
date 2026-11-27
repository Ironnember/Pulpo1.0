# Change record — Incident replay: Q-Dir / DesktopOK trojanized installer — a valid developer signature treated as authority for whatever the installer does (reported 2026-11-26)

Base: `origin/main` at `f734c97e` (PR #38 merged;
verified by fetch at build time, 2026-11-27).
Authority: Austin approved this build on 2026-11-27
in words ("Build all three"), for the event surfaced
the same day; the authorization covers this build's
fresh clone. Test-only change: one scenario module
plus this record. No production code is touched.

## 1. Invariant or failure addressed

Event (graded from the public record): AhnLab ASEC
reported (Recorded, primary source: AhnLab ASEC,
2026-11-26, via The Hacker News,
https://thehackernews.com/2026/11/hackers-trojanize-official-q-dir-and.html)
that installers for Q-Dir (versions 12.83-12.85) and
DesktopOK distributed via the official SoftwareOK
website were tampered with. The trojanized installer
runs the genuine utility -- the embedded binary
carries developer Nenad Hrg's valid signature --
while downloading a Python RAT that runs shell and
Python commands, transfers files, captures
screenshots, and persists via a scheduled task
impersonating Microsoft Edge, beaconing to a C2.
How the installers were replaced is Unknown on the
record, and no victim count is confirmed; neither is
claimed anywhere in this change.

Claim discipline (load-bearing): this replay does
NOT reproduce the RAT, the C2, any installer, or any
SoftwareOK system, and no step executes payload code
of any kind -- the boundary's log entries are inert
labels. What it models is the architectural property
the reporting establishes: the installer's trust was
inherited by everything the installer did. The user
who downloads from the official site approves, at
most, one act -- install this utility, from this
artifact. The payload download and the payload
execution are different acts, approved by no one,
and on the ungoverned path they ride along under the
install's trust.

Failure addressed: **a valid signature is not
authorization.** The signature was the trust artifact
the install path relied on, and carrying it was
treated as authority for each act the installer
performed -- the genuine install, and,
indistinguishably, the payload download and payload
execution composed by whoever replaced the
installers. At no point did the path ask the
separate question: was THIS act approved? A
signature answers "who signed this binary?" It does
not answer "was downloading and executing a remote
payload approved by the human?" Under the canonical
kernel, the signature reference is not a permit at
all -- presented at `consume` it is an
unauthenticated string and is refused. Authority for
an install enters only as a verified approval
envelope -- signed by an enrolled authority and
bound to the exact intent hash (principal, action,
resource, cost, session) -- and mints a single-use
permit for exactly that intent: the genuine approved
install executes under its permit, and the payload
act presented with that same permit is refused at
consume, the refusal burning nothing. The valid
signature is recorded in evidence throughout and is
explicitly never treated as authorization; an
approval envelope signed with the developer-signature
key -- the key behind that valid signature -- is
denied, because the signing developer is not the
enrolled approving authority. The governing
invariants are `AUTHORIZED_OUTCOME !=
AUTHORIZATION_FOR_ARBITRARY_MEANS` and fail-closed
authorization: unknown, malformed, untrusted, or
merely possessed authority mints nothing and spends
nothing.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's
`TrojanizedInstallerBoundary` double exists solely as
the negative control, is test-local, and is never
imported by runtime code -- the same pattern as PRs
#346 and #362-#393, #415, #416, #422, #423, and #424.
The scenario's reconciliation helper
(`reconcile_consequences`) is likewise test-local: it
reads the harness's executed log and holds no
canonical state.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `InstallBoundary` is a test harness: it
executes an act only after a successful kernel
consume and holds no canonical state; its log entries
are inert resource labels, never commands, files, or
credentials. The incident-channel freeze is asserted
read-only in the scenario itself (audit length
unchanged across the freeze). Audit growth is
classified in the module docstring per AGENTS.md
(`NO_PERMIT != NO_GOVERNED_EFFECT`): each denied
attempt appends audit records -- a governed effect
(evidence production), append-only, with
`authority_effect=none` and no capability
accumulation -- assessed separately from governed
external consequences throughout. The count is per
route, not uniformly one: a bare `evaluate` returning
`require_approval` appends one decision record; a
`consume` rejection appends one `permit_rejected`
record; a denied approval-envelope evaluation appends
two records -- an `approval_rejected` record and a
denied decision record. Growth stays bounded per
attempt (at most two records), which is the invariant
the scenario pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_qdir_incident_scenario.py`
(7 tests, all passing at the worktree head):

- positive control: the one authorized act (the
  genuine install -- this exact artifact, this action,
  this session) executes exactly once under a genuine,
  well-formed verified approval envelope; the permit,
  spent at that consume, cannot install twice;
  reconciliation of executed-vs-approved reports exact
  equality (1 approved, 1 executed, 0 unauthorized);
  the valid signature is asserted present in evidence
  and marked never-as-authorization; the audit chain
  verifies.
- step 1: the payload refused at consume, and the
  refusal is free -- the genuine permit, presented
  FIRST for the payload act (a different action, a
  different resource, an act no human approved), is
  refused at the kernel's intent binding, the rejection
  naming the payload intent's hash; the refusal
  consumes nothing, and the genuine permit then spends
  on its own act, exactly once. Under the reported
  architecture this attempt never faces the question:
  the payload arrives inside the trusted installer,
  and that trust is the whole check.
- step 2: the valid signature presented as a permit --
  the standing trust artifact the reported architecture
  relies on, in the role it plays there -- is refused
  at `consume` for the genuine install and the payload
  alike. A signature authenticates a signer, and
  authorizes no act.
- step 3: with no artifact presented at all,
  `evaluate` returns `require_approval` for the
  genuine install and the payload alike -- being the
  installer the user downloaded confers no route to a
  permit; and an approval envelope for the payload
  signed with the developer-signature key is denied
  (`approval_signature_invalid`). The kernel verifies
  against the enrolled authority, and the party that
  signed the binary cannot also be the party approving
  the act.
- step 4: reconciliation over a governed sequence
  shaped like the event -- the genuine install approved
  and executed, the payload attempted under the event's
  two available forms (the genuine permit stretched,
  before the genuine install; the valid signature
  presented as authority), and the spent permit
  replayed -- reports exact equality: 1 approved, 1
  executed, 0 unauthorized occurrences, and no refused
  attempt recorded as fulfilled. The comparison the
  reported path never runs, run here, is clean
  precisely because every payload attempt was denied
  before it could execute.
- step 5: the incident channel sees the attempts --
  freezing a report over the full attempt sequence
  exercisable on one kernel (the no-approval evaluation
  of the payload, the valid signature presented as a
  permit for the payload, the genuine approval stretched
  to the payload, the one legitimate execution, and the
  spent-permit replay) yields zero incidents and exactly
  the near-miss records the channel's derivation
  produces from the audit: 2 `permit_rejected`, 1
  `approval_rejected`, 1 denied `decision`, and 1
  `require_approval` `decision` (5 near-misses in
  total), each classified Recorded under a valid audit
  chain; the freeze appends nothing. The
  `require_approval` decision contributes one near-miss
  per occurrence under the issue #375 derivation (PR
  #413) -- this module was authored after that fix
  landed, so its counts are born correct against it.
  Governed run totals: **0 incidents, 5 near-misses.**
- negative control: with no governor at all, the
  trojanized-installer boundary double does exactly
  what the reporting describes -- it takes an installer
  presented from the official site, carrying the valid
  signature, at face value, and runs what the installer
  runs. The genuine utility installs; the payload
  download and the payload execution ride along under
  the same trust. Per-occurrence reconciliation against
  the one act the human approved reports the run
  exactly: **1 approved, 3 executed, 2 unauthorized
  occurrences, named** (the payload download and the
  payload execution). Incident-channel counts for this
  run: **0 incidents, 0 near-misses** -- there is no
  kernel, no audit, and no channel on this path, so
  both unauthorized executions produced no record
  anywhere; that zero is an absence of records,
  asserted as such, not a safety finding. The denials
  in the steps above therefore come from the governed
  path's fail-closed authorization, exact-intent
  binding, and signature verification, not from a
  harness that denies by construction, and the
  reconciliation demonstrably detects the modeled
  shape when it does occur.

Full suite at the worktree head: **1195 tests,
OK (skipped=13)** in this environment --
the recorded local baseline at the base commit
`f734c97e` is 1188 OK (skipped=13);
the delta is exactly the 7 scenario tests. (The
skipped figure is this environment's count; CI records
its own environment's skipped count with the same test
total modulo environment-specific discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip -- if the boundary were merely optimizing for
  install friction (the reported flow's actual
  condition: official-site provenance and a valid
  signature were accepted because accepting them is
  what makes software distribution frictionless), the
  fastest route from a download to execution is to
  check the signature and nothing else. On the governed
  path, throughput has no dimension to exploit: the
  signature is an unauthenticated string at consume
  (step 2), genuine authority stops at its own intent
  (step 1), and flipping the presenter changes nothing
  without the enrolled key (step 3).
- Reverse -- the consequence (an executed act)
  requires a consumed permit; the permit requires a
  verified approval; the approval is bound to the exact
  intent hash and signed by the enrolled authority. The
  earliest unreachable point is the act itself: the
  executor runs nothing without a consume, and the chain
  does not collapse to one control -- possession of the
  signature stops at consume (step 2), scope stops at
  intent binding (step 1), self-assertion -- including
  assertion by the genuine signing developer -- stops at
  signature verification against the enrolled authority
  (step 3), replay stops at single-use consumption
  (positive control), and absence of any artifact stops
  at the approval requirement (step 3).
- Invert -- outcome is not legitimacy: on the reported
  path the genuine utility DID install and run -- and
  every part of that success rested on provenance and
  a signature. The negative control reproduces exactly
  that shape and extends it by the payload's two acts:
  all three executions "succeed," and the reconciliation
  still reports the payload download and execution as
  carrying no approval, so a successful execution under
  a valid signature is classified by the record as
  unapproved, not as authorized.
- Inside-Out -- the governor cannot originate the
  authority it enforces: the boundary holds no approval
  capability, the reconciliation helper is read-only
  over the harness's log and holds no canonical state,
  the installer double is test-only, and the
  orchestrator surface used for the incident report is
  read-only with its freeze asserted to append nothing
  (step 5). In particular, the kernel has no route by
  which material an installer presents -- a valid
  signature included -- becomes authority:
  `CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`,
  and a signature is not an approval transition.
- Darken -- worst credible bounded case, from the
  reporting's own shape: a widely trusted freeware
  channel is trojanized once, and every user who
  installs in the window receives a RAT with shell and
  Python execution, file transfer, screenshot capture,
  and Edge-impersonating scheduled-task persistence --
  each payload act inheriting the trust of a download
  the user deliberately made from the official site.
  Inside the governed path the maximum consequence per
  approval remains the one approved install, once;
  every unauthorized attempt produces audit records
  only -- one per attempt on the bare-evaluate and
  consume routes, two (an `approval_rejected` record
  and a denied decision record) on the denied
  approval-envelope route -- and zero executed payload
  acts. Outside the governed path stands the modeled
  worst case -- install paths that execute on site
  trust and a valid signature alone -- and this replay
  does not mitigate it; it is the boundary in section 5.
- Lighten -- minimum benign interpretation: code
  signing and official distribution sites are ordinary,
  useful tooling, and for the genuine utility the
  reported facts are the benign case working as
  designed -- the signature is genuinely the
  developer's, and the utility genuinely installs. The
  governed path preserves what is benign: the genuine
  install works (positive control), the signature's
  evidentiary value is not denied (it is recorded in
  evidence), and each act's authorization becomes a
  governed question instead of an implication of a
  signature applied to a binary.
- Amplify -- the modeled harm is amplification by
  inherited trust: one trojanized installer, valid for
  every act it chooses to perform, multiplies a single
  supply-chain compromise into payload execution on
  every installing machine. On the governed path,
  amplification multiplies attempts, never authority:
  the signature spends on nothing no matter how many
  acts it is presented for (step 2), approvals are
  per-intent and permits single-use (steps 1, 3), and
  the reconciliation counts occurrences, so amplification
  is measured, not averaged away (negative control:
  2 unauthorized occurrences over the modeled shape).
- Negate -- the smallest clean path: a consequential
  act must require an approval the installer cannot
  supply by presenting a trust artifact -- signed by
  an enrolled authority and bound to the exact intent.
  The signature reference, the stretched permit, and
  the developer-signed envelope are each unnecessary to
  the approved task; remove the signature check and
  step 3's route returns, remove intent binding and
  step 1's returns; with both, the payload's shape has
  no governed route.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models governed installs at a kernel
boundary. It proves nothing about SoftwareOK's,
Q-Dir's, DesktopOK's, or AhnLab's actual systems, or
any deployed software-distribution environment, and
it reproduces none of the event's mechanics -- the
boundary's log entries are inert labels, no payload
code exists or runs anywhere in the module, the
installer double is a test-local model faithful only
in the properties the scenario names (an installer
presented from the official site, carrying the valid
signature, taken at face value; the genuine utility
and the payload acts executed as presented), and no
credential, artifact binary, C2 detail, or victim
detail from the real event appears anywhere in the
module. It proves nothing about non-governed paths: an
install path that executes on site trust and a valid
signature alone is governed by nothing here -- a
control not on the execution path governs nothing.

The event narrative itself rests on AhnLab ASEC's
reporting as carried by The Hacker News, not
independently verified by this change beyond that
reporting. The replay takes the reported mechanics as
its model and grades each element (section 6); it
does not independently verify how the installers were
replaced (Unknown on the record), any victim count
(none confirmed, none claimed), or the RAT's behavior
beyond the reported capabilities. In particular, the
load-bearing boundary is the modeled payload act:
the scenario models one genuine intent, one payload
intent, and the payload's two executed occurrences as
the architectural pattern the reporting describes,
not a per-machine reconstruction. Every amount, cost,
and artifact label in the module beyond the reported
facts is a scenario parameter, not a reported figure.

## 6. Claim classification

- Installers for Q-Dir (versions 12.83-12.85) and
  DesktopOK distributed via the official SoftwareOK
  website were tampered with; the trojanized installer
  runs the genuine utility while downloading a Python
  RAT with shell/Python command execution, file
  transfer, and screenshot capture, persisting via a
  scheduled task impersonating Microsoft Edge and
  beaconing to a C2: **Recorded** (AhnLab ASEC,
  2026-11-26, via The Hacker News, read firsthand).
- The embedded genuine binary carries developer Nenad
  Hrg's valid signature: **Recorded** (AhnLab ASEC, as
  above). Recorded in this scenario as evidence only;
  it is never treated as authorization for any act.
- How the installers were replaced: **Unknown** (not
  established in the reporting; not claimed here).
- Any confirmed victim count: **Unknown** (none
  confirmed in the reporting; no count is stated
  anywhere in this change).
- That a payload act would execute under the reported
  mechanics with no approval of that exact act
  existing: **Inferred** -- the modeled property,
  demonstrated executably against the installer double
  built to the reported mechanics (negative control),
  and in fact the payload's execution is itself
  Recorded; the inference is the absence of any
  exact-act approval step in the reported path.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree
  head commit).
- The mapping from the reported flow to kernel
  artifacts (the install boundary as one boundary; the
  genuine install and the payload as two distinct
  intents; the payload's download and execution as two
  occurrences on the ungoverned path; the valid
  signature modeled as a consume-presented string):
  **Inferred** -- the harness's modeling choices,
  stated in the module docstring.
- Any claim that this prevents the modeled class in a
  deployed distribution system: **Proposed** -- not
  made by this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346-#350, #362-#368, #374-#382, #386,
and #391-#393, and the approval-path construction of
PRs #416, #422, #423, and #424 (the sibling Cairn,
Morris, SAP, and Papa John's replay modules).

## 8. Temporal-transfer evidence

Executed 2026-11-27. The applicable historical
checkpoint is this branch's exact base, `f734c97e`: the
bindings the scenario exercises (fail-closed approval
requirement, exact-intent binding, single-use
consumption, approval signature verification, and the
incident-channel derivation including the issue #375
near-miss rule) all predate this change, so the
checkpoint comparison AGENTS.md requires was runnable
and has been run.

Method: a clean worktree was reconstructed at exactly
`f734c97e` (no tree rewriting; `git status` verified
the only delta from the checkpoint was the copied
scenario module). The scenario was run there under
the canonical command. Baseline at `f734c97e` without
the lesson in this environment is 1188 OK
(skipped=13); the branch adds no kernel
code, so any behavioral difference at the checkpoint
would have been a finding, not an expectation.

Results (Verified -- executed at both states):

- TRANSFERS: all 7 scenario tests pass identically at
  `f734c97e` -- the positive control executing exactly
  once with exact reconciliation, the payload refused
  at consume under the genuine permit with the refusal
  burning nothing, the valid signature refused as a
  permit for both acts, the no-approval and
  developer-signed denials, the governed-sequence
  reconciliation reporting zero unauthorized, the
  incident channel's 0 incidents / 5 near-misses, and
  the negative control executing the install plus both
  payload acts under no governor with reconciliation
  reporting 2 unauthorized occurrences and incident
  counts of 0 / 0 (absence of records).
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed.

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.

# Change record — Incident replay: Mitel MiCollab zero-days — five unauthenticated flaws, exploited pre-advisory (reported 2026-11-26)

Base: `origin/main` at `d7b7506` (incident replay:
OpenSSH SSHole CVE-2026-123158, PR #393), re-verified
against live `main` via `gh` at build time
(2026-11-26). Authority: Austin approved this build on
2026-11-26 ("build the replay PR" for the Mitel
MiCollab incident, surfaced by the standing incident
scan; git and test-suite execution in this worktree
confirmed by Austin 2026-11-26 08:00 and 08:23 MST).
Test-only change: one scenario module plus this record.
No production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from SecurityWeek's 2026-11-26
reporting of Accenture Apex Labs' investigation,
converged with Mitel's advisory MISA-2026-0012, first
issued 2026-11-16, revision 2.0 dated 2026-11-24):
Mitel patched five vulnerabilities in MiCollab's Audio,
Web and Video Conferencing (AWV) component, all
exploitable by unauthenticated attackers:

- CVE-2026-133275 — arbitrary file upload, Medium,
  CVSS 5.3 (insufficient file type validation);
- CVE-2026-133303 — XML injection, Critical, CVSS 9.0
  (arbitrary command execution);
- CVE-2026-133311 — unauthorized access, Medium,
  CVSS 5.9 (improper authentication mechanisms;
  sensitive information);
- CVE-2026-133323 — command injection, Critical,
  CVSS 10.0 (arbitrary command execution);
- CVE-2026-133324 — authentication bypass, Medium,
  CVSS 5.3 (improper handling of authentication).

Affected: MiCollab 10.3 (10.3.0.18) and earlier.
Exploiting the vulnerabilities together significantly
amplifies their impact, per the advisory.

Accenture found evidence the flaws were exploited in
the wild before Mitel published its advisory: threat
actors deployed a web shell on a victim's systems on
November 15 — one day before the advisory's first
issue date. A second victim's MiCollab server had been
communicating with the same attacker infrastructure
since November 9; how that second server was
compromised could not be established, as it had also
been affected by older vulnerabilities. In the first
attack, the attackers executed commands on the
MiCollab server just 12 minutes after the first
request and gained root privileges within half an
hour. They harvested additional credentials and,
roughly 20 hours after their first observed request,
gained access to internal backup and database servers.
SecurityWeek's report also records that the attackers
reached the targeted organization's identity
infrastructure and stole sensitive business
information; no timing for that step is given in the
source, and none is claimed here. The researchers did
not link the attacks to a known group and believe they
may have been part of an extortion campaign. CISA
added all five vulnerabilities to its Known Exploited
Vulnerabilities catalog on November 25, instructing
federal agencies to address four of them by November
28 and the last by December 9. Mitel's advisory, last
updated November 24, does not mention in-the-wild
exploitation.

Failure addressed: **a consequence boundary that an
unauthenticated request can reach is not a boundary.**
Every consequential act in the incident — the web
shell upload, command execution, root, the reach into
backup and database servers — was available with no
authentication at all, and CVE-2026-133324 removed
even the appearance of authentication by bypassing it.
Nothing required a per-action authorization bound to
the exact act and session, and nothing spent or
revoked whatever reach a request appeared to carry, so
the first request's reach extended unrechecked across
the whole timeline: web shell on November 15, commands
at 12 minutes, root at ~30 minutes, backup and
database access at ~20 hours. The governing invariants
are fail-closed authorization and revocation-at-consume:
under the kernel, a consequential act requires a permit
issued only after an approval bound to the exact intent
hash — principal, action, resource, cost, session — so
an unauthenticated request mints nothing, an approval
presented in a bypassed-authentication session is
refused as a session mismatch, an approval for one act
presented for the timeline's escalation steps is refused
as an intent mismatch, and a permit is spent at its
first consume, so a consumed permit re-presented — for
its own act or stretched to a later step — is refused
at the consequence boundary.

AI involvement is **Unknown** and is not modeled:
Accenture observed the attackers' infrastructure
communicating with two unnamed commercial AI API
services, noted the activity is consistent with
potential uses such as data triage or operational
support, and stated that, because the telemetry is
sampled, it cannot determine precisely how the threat
actor used the services. No claim about AI involvement
is made by this change, in either direction.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's
`UngovernedMiCollabServer` double exists solely as the
negative control, is test-local, and is never imported
by runtime code — the same pattern as PRs #346 and
#362–#393. The scenario's reconciliation helper
(`reconcile_consequences`) is likewise test-local: it
reads the harness's executed log and holds no canonical
state.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `MiCollabServer` is a test harness: it
executes an act only after a successful kernel consume
and holds no canonical state; its log entries are inert
resource labels, never commands. The incident-channel
freeze is asserted read-only in the scenario itself
(audit length unchanged across the freeze). Audit
growth is classified in the module docstring per
AGENTS.md (`NO_PERMIT != NO_GOVERNED_EFFECT`): each
denied attempt appends audit records — a governed
effect (evidence production), append-only, with
`authority_effect=none` and no capability accumulation
— assessed separately from governed external
consequences throughout. The count is per route, not
uniformly one: a bare `evaluate` returning
`require_approval` appends one decision record; a
`consume` rejection appends one `permit_rejected`
record; a denied approval-envelope evaluation appends
two records — an `approval_rejected` record and a
denied decision record. Growth stays bounded per
attempt (at most two records), which is the invariant
the scenario pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_mitel_micollab_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the one authorized act (a single
  administrative command) executes exactly once under a
  genuine, well-formed verified approval envelope; the
  permit, spent at that consume, cannot run it twice;
  reconciliation of executed-vs-approved reports exact
  equality (1 approved, 1 executed, 0 unauthorized); the
  audit chain verifies.
- step 1: with no approval at all, `evaluate` returns
  `require_approval` for each of the timeline's acts —
  the web shell, the root command, and the
  backup/database access — with no permit minted and
  nothing executed. An unauthenticated request is not a
  weaker kind of approval; it is none.
- step 2: the authentication bypass (CVE-2026-133324's
  shape) — a genuine approval envelope for the
  administrative command, presented for that same
  command in a session the attacker manufactured by
  bypassing authentication, is denied
  (`approval_session_mismatch`). The envelope is genuine
  in every other field, so the only check that denies it
  is the session binding: a bypassed authentication
  produces a session no approval names.
- step 3: the incident's timeline as escalation — the
  administrative approval presented in turn for the web
  shell, the root command, and the backup/database
  access is denied (`approval_intent_mismatch`) at each
  step, in the incident's own order. The 12-minute /
  ~30-minute / ~20-hour spacing is irrelevant to a
  boundary that re-checks every act: no step rides the
  reach of the one before.
- step 4: revocation-at-consume — a permit issued for
  the administrative command executes it once, and the
  spent permit re-presented is refused at `consume`,
  both for its own act and stretched to the root
  command. Capture of what the first act used is not
  continuation of it.
- step 5: a genuine approval for a different act (an
  unprivileged diagnostic command) presented for the
  administrative command is denied
  (`approval_intent_mismatch`), and an envelope for the
  administrative command signed with an unauthorized key
  is denied (`approval_signature_invalid`); the genuine
  pair still admits afterward.
- step 6: reconciliation over a governed sequence
  shaped like the incident's first day — one approved
  administrative command, then the web shell, the root
  command, and the backup/database access, each
  attempted under the administrative approval — reports
  exact equality: 1 approved, 1 executed, 0 unauthorized
  occurrences. The comparison the incident's server
  never ran, run here, is clean precisely because every
  escalation attempt was denied before it could execute.
- step 7: the incident channel sees the attempts —
  freezing a report over the full attempt sequence
  exercisable on one kernel (the no-approval evaluation,
  the web-shell and root-command presentations of the
  administrative approval, the substituted
  diagnostic-act envelope, the one legitimate execution,
  and the spent-permit replay) yields zero incidents and
  exactly the near-miss records the channel's derivation
  produces from the audit: 1 `permit_rejected`, 3
  `approval_rejected`, and 3 denied `decision` records
  (7 near-misses in total), each classified Recorded
  under a valid audit chain; the freeze appends nothing.
  The step also pins the surfacing boundary stated in
  §5: the sequence's 1 `require_approval` decision is
  present in the audit and contributes zero near-miss
  records.
- negative control: with no governor at all, the server
  double performs the incident's exact shape —
  unauthenticated requests execute the web shell, the
  root command, and the backup/database access in the
  incident's timeline order, and the bypassed session's
  act executes as presented. Per-occurrence
  reconciliation reports the whole run exactly: 0
  approved, 3 executed, 3 unauthorized occurrences,
  named. The denials in the steps above therefore come
  from the governed path's fail-closed authorization,
  exact-intent and session binding, and
  revocation-at-consume, not from a harness that denies
  by construction, and the reconciliation demonstrably
  detects the incident's shape when it does occur.

Full suite at the worktree head: **1148 tests, OK
(skipped=25)** in this environment — the recorded local
baseline at the base commit `d7b7506` is 1139 OK
(skipped=25); the delta is exactly the 9 scenario
tests. (The skipped figure is this environment's
count; CI records its own environment's skipped count
with the same test total modulo environment-specific
discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — if the server were merely optimizing for
  request completion (the incident's actual condition),
  the fastest route from a network request to a
  consequence is direct execution, and the fastest
  session is a bypassed one. On the governed path,
  completion has no dimension to exploit: each timeline
  step is a distinct intent the administrative approval
  does not cover (step 3), the bypass session is a
  session no approval names (step 2), and flipping the
  presenter changes nothing without the enrolled key
  (step 5b).
- Reverse — the consequence (an executed act) requires
  a consumed permit; the permit requires a verified
  approval; the approval is bound to the exact intent
  hash and session. The earliest unreachable point is
  the act itself: the executor runs nothing without a
  consume, and the chain does not collapse to one
  control — unauthenticated requests stop at the
  approval requirement (step 1), the bypass stops at
  session binding (step 2), escalation stops at intent
  binding (steps 3, 5a), replay stops at
  revocation-at-consume (step 4, positive control), and
  forgery stops at signature verification (step 5b).
- Invert — outcome is not legitimacy: the incident's
  requests DID produce their outcomes — a web shell, a
  root shell, internal access — and every production was
  illegitimate. The negative control reproduces exactly
  that: every act "succeeds," and the reconciliation
  still reports the run as 3 unauthorized occurrences,
  so a successful execution through an unauthorized
  route is classified as failure by the record, not
  success.
- Inside-Out — the governor cannot originate the
  authority it enforces: the executor holds no approval
  capability, the reconciliation helper is read-only
  over the harness's log and holds no canonical state,
  the ungoverned double is test-only, and the
  orchestrator surface used for the incident report is
  read-only with its freeze asserted to append nothing
  (step 7).
- Darken — worst credible bounded case, from the
  report's own shape: five unauthenticated flaws, at
  least two victims, exploitation predating the
  advisory, root within half an hour, credential
  harvesting, and backup/database access at ~20 hours —
  the remediation Accenture urges is hunting for
  compromise that may already have happened before the
  fix existed. Inside the governed path the maximum
  consequence per approval remains the one approved act,
  once; every unauthorized attempt produces audit
  records only — one per attempt on the bare-evaluate
  and consume routes, two (an `approval_rejected`
  record and a denied decision record) on the denied
  approval-envelope route — and zero executed acts.
  Outside the governed path stands the incident's real
  worst case — an endpoint that executes unauthenticated
  requests directly — and this replay does not mitigate
  it; it is the boundary in §5.
- Lighten — minimum benign interpretation: none of the
  five flaws requires a malicious insider or an exotic
  precondition; each is an ordinary validation or
  authentication-handling defect in an internet-exposed
  component, and the benign acts the component exists
  for (meetings, calls, legitimate administration) are
  unaffected by governing the consequential ones. The
  governed path preserves what is benign — the
  administrative command works (positive control) —
  while making each consequential act's authorization a
  governed question instead of a network-reachability
  accident: if a root command or an internal-server
  access is ever genuinely needed, it is an intent that
  can be approved as itself, not one that rides on
  reachability.
- Amplify — the incident's harm IS amplification, and
  the advisory says so: exploiting the five flaws
  together significantly amplifies their impact, and one
  foothold amplified across 12 minutes, ~30 minutes,
  and ~20 hours into root and internal servers.
  Approvals are per-intent and permits single-use, so
  amplification multiplies attempts, never authority
  (steps 3, 4); and the reconciliation counts
  occurrences, so amplification is measured, not
  averaged away (negative control: 3 unauthorized
  occurrences over the timeline shape).
- Negate — the smallest clean path: a consequential act
  must require an approval bound to its exact intent and
  session, and a permit must spend on its first use.
  The unauthenticated request, the bypassed session,
  and the escalation step are each unnecessary to the
  approved task — remove any one of the three bindings
  and a part of the incident returns; with all three,
  the incident's shape has no governed route.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models governed acts at a kernel boundary.
It proves nothing about any deployed MiCollab server,
AWV component, or patch level, and it reproduces none
of the five vulnerabilities — the executor's log entries
are inert labels, the server double is a test-local
model faithful only in the properties the scenario
names (unauthenticated requests executed as presented;
a bypassed session accepted as authenticated), and no
command, file, or credential appears anywhere in the
module. It proves nothing about non-governed paths: an
endpoint that executes requests without routing them
through this kernel is governed by nothing here — a
control not on the execution path governs nothing. It
does not model the incident's later legs (credential
harvesting, extortion, or any use of AI services): the
scenario governs the acts at the server boundary, and
AI involvement in the incident is Unknown on the source
record (§1), so no AI behavior is asserted or modeled
in either direction. The second victim's compromise
route is likewise unmodeled: the source could not
establish it, and this replay takes no position on it.
Finally, the exploitation narrative itself rests on one
investigation (Accenture Apex Labs) as reported by
SecurityWeek, converged with Mitel's own advisory for
the vulnerability facts: the replay takes the reported
shape as its model and grades it Recorded (§6); it does
not independently verify that the events occurred.

One surfacing boundary, stated plainly rather than
smoothed over (Verified at this commit, by executable
probe, by the channel's derivation source, and by
step 7's pinned counts): a bare `evaluate` that returns
`require_approval` — the kernel declining to mint a
permit without approval — appends a decision record to
the canonical audit, where it is complete and
chain-verified, but the incident channel does NOT derive
a near-miss record from it; the channel derives
near-misses from `permit_rejected`, `approval_rejected`,
denied decisions, and `directive_denial`. The act is
still stopped — no permit exists to spend — so this is
a derivation-coverage boundary in the owner-facing
channel, not an authorization gap (issue #375). Whether
a `require_approval` decision should also surface as a
near-miss is a design question for the channel's
maintainers; this replay records the behavior exactly
as it stands and takes no position by silently
engineering around it.

## 6. Claim classification

- Vulnerability facts (the five CVEs, their classes,
  severities, the AWV component, and the affected
  versions): **Recorded** (Mitel advisory MISA-2026-0012,
  first issued 2026-11-16, revision 2.0 dated
  2026-11-24, as cited and converged by SecurityWeek's
  2026-11-26 report).
- Exploitation narrative (the November 15 web shell,
  the second victim's server communicating with attacker
  infrastructure since November 9, commands at 12
  minutes, root within half an hour, credential
  harvesting, backup and database access at roughly 20
  hours, the reach into identity infrastructure and the
  theft of sensitive business information, the suspected
  extortion framing, and the CISA KEV listing of
  November 25 with its November 28 / December 9
  deadlines): **Recorded** (Accenture Apex Labs'
  investigation as reported by SecurityWeek on
  2026-11-26; not independently re-derived here).
- AI involvement in the attacks: **Unknown** (the
  source's sampled telemetry cannot determine how the
  AI services were used; this change models no AI
  involvement).
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 7).
- The mapping from the incident's pattern to kernel
  artifacts (the web shell, root command, and
  backup/database access modeled as three distinct
  intents over one executor; the authentication bypass
  modeled as an attacker-manufactured session distinct
  from the approved session; revocation-at-consume
  modeled as the spent permit's refusal on
  re-presentation): **Inferred** — the harness's
  modeling choices, stated in the module docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346–#350, #362–#368, #374–#382, #386,
and #391–#393, including their per-module
helper-duplication pattern, the reporting-coverage
construction of PR #378's step 6 as amended, and the
accessed-vs-approved reconciliation construction of
PR #368's WorkOS scenario.

## 8. Temporal-transfer evidence

Executed 2026-11-26. The applicable historical
checkpoint is this branch's exact base, `d7b7506`: the
bindings the scenario exercises (fail-closed approval
requirement, exact-intent binding, session binding,
single-use consumption, approval verification, and the
incident-channel derivation) all predate this change,
so the checkpoint comparison AGENTS.md requires was
runnable and has been run.

Method: a clean worktree was reconstructed at exactly
`d7b7506` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module). The scenario was run there under the canonical
command. Baseline at `d7b7506` without the lesson in
this environment is 1139 OK (skipped=25); the branch adds no
kernel code, so any behavioral difference at the
checkpoint would have been a finding, not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 9 scenario tests pass identically at
  `d7b7506` — the positive control executing exactly
  once with exact reconciliation, the unauthenticated
  denials, the bypassed-session denial, the timeline
  escalation denials, the spent-permit replay denials,
  the substituted/forged approval denials, the
  governed-sequence reconciliation reporting zero
  unauthorized, the incident channel's 0 incidents / 7
  near-misses, and the negative control executing the
  full timeline under no governor with reconciliation
  reporting 3 unauthorized occurrences.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not
  smoothed: the §5 bare-evaluate near-miss gap (issue
  #375) is a property of the base-era incident
  projection, present at `d7b7506` exactly as at the
  head — the replay neither introduces nor widens it.

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.

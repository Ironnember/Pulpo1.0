# Change record — Incident replay: Todoist breach — a possessed credential treated as authority over the authority system itself (disclosed 2026-11-24)

Base: `origin/main` at `f734c97e` (PR #38 merged;
verified by fetch at build time, 2026-11-27).
Authority: Austin approved this build on 2026-11-27
in words ("Build the Todoist replay PR"), for the
event surfaced the same day; the authorization covers
this build's fresh clone. Test-only change: one
scenario module plus this record. No production code
is touched.

## 1. Invariant or failure addressed

Event (graded from the public record): Todoist's own
security notice (Recorded, the company's incident
article "Security incident in November 2026,"
published 2026-11-24, read firsthand) establishes the
chain. Between November 22 and 23, 2026, an attacker
used a stolen credential associated with Todoist's
version control system to modify automated workflows
in three repositories and obtain additional
credentials; the attacker could also read source code,
and Todoist's investigation found no changes to
application code. One of the harvested credentials was
an administrative credential for the employee sign-in
system — it "allowed them to change how employees
access our internal systems." The timeline the notice
publishes (UTC): earliest identified use of the stolen
development credential November 22, 14:04, modifying
workflows to harvest credentials; November 23, 06:06,
the administrative credential for the employee sign-in
system obtained through an infrastructure automation
workflow; 06:33–06:54, the attacker changed an
employee's authentication settings and signed in to
the cloud infrastructure as that employee; 08:20–08:22,
additional persistence accounts created; 09:08 onward,
production databases accessed and commands run in
production; 12:45–12:51, account records exported and
downloaded; 13:05–17:12, targeted queries for account
tokens, connected Outlook mailbox access, and searches
of customer content for credentials; 17:01, detection
— security monitoring flagged an unexpected
administrator account. What was taken (Recorded, same
notice): email addresses, salted SHA1 password hashes,
and account creation dates for approximately 6% of
users (early accounts still on the legacy hashing
method); Todoist API and Slack integration tokens for
approximately 0.003%; credential-like content in tasks
and comments for approximately 0.001%; email previews
through connected Todoist for Outlook accounts for
approximately 0.001%. TechCrunch's reporting
(Recorded, 2026-11-25) corroborates the notice and
carries Todoist's figure of more than 50 million
users. How the original credential was stolen is
Unknown: Todoist states it has not established this;
its leading theory — an employee's device may have
been compromised — is expressly unconfirmed.

Failure addressed: **a possessed credential is not
approval of the act.** At no point in the reported
chain did any boundary ask whether THIS act was
approved by an accountable human. Possession of the
version-control credential was sufficient to rewrite
automated workflows; possession of what those
workflows yielded was sufficient to rewrite how
employees authenticate — a change to the authority
system itself, executed on a credential alone;
possession of the rewritten access was sufficient to
sign in as an employee; and that session was
sufficient to export and download the bulk account
records. Each step's only requirement was the previous
step's output. Under the canonical kernel, each of
those acts is a consequential act that requires a
permit bound to a verified approval of its exact
intent — principal, action, resource, cost, session —
minted from an approval envelope signed by an enrolled
authority. A credential, stolen or otherwise, presented
at `consume` is an unauthenticated string: it is
evidence of possession, never authority. The governed
chain therefore breaks at its first consequential
link: the access-configuration change refuses at
consume, the refusal burns nothing, and the takeover
path downstream of it never opens. The bulk export is
likewise its own governed act: it executes only under
a permit bound to the exact file and scope that a
human approved, and no permit minted for any other
act — and no credential, however privileged — spends
on it. The governing invariants are
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`
and fail-closed authorization: unknown, malformed,
untrusted, or merely possessed authority mints nothing
and spends nothing.

Screening note (Recorded): the incident scan of
2026-11-26 initially classified this event out of
class as legitimate-privilege lateral movement — the
workflows ran because the stolen credential
legitimately could change them. This replay was built
on Austin's direction (2026-11-27) because the chain's
load-bearing link is the access-configuration change:
an act that rewrites the authority system itself. The
replay takes that act — and the bulk export behind it
— as the governed acts; the classification question is
recorded in section 6 rather than smoothed over.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's `PossessionBoundary`
double exists solely as the negative control, is
test-local, and is never imported by runtime code —
the same pattern as PRs #346 and #362–#393, #415,
#416, #422, #423, #424, #425, #426, and #427. The
scenario's reconciliation helper
(`reconcile_consequences`) is likewise test-local: it
reads the harness's executed log and holds no
canonical state.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `GovernedBoundary` is a test harness:
it executes an act only after a successful kernel
consume and holds no canonical state; its log entries
are inert resource labels, never commands, files, or
credentials. The incident-channel freeze is asserted
read-only in the scenario itself (audit length
unchanged across the freeze). Audit growth is
classified in the module docstring per AGENTS.md
(`NO_PERMIT != NO_GOVERNED_EFFECT`): each denied
attempt appends audit records — a governed effect
(evidence production), append-only, with
`authority_effect=none` and no capability
accumulation — assessed separately from governed
external consequences throughout. The count is per
route, not uniformly one: a bare `evaluate` returning
`require_approval` appends one decision record; a
`consume` rejection appends one `permit_rejected`
record; a denied approval-envelope evaluation appends
two records — an `approval_rejected` record and a
denied decision record. Growth stays bounded per
attempt (at most two records), which is the invariant
the scenario pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_todoist_incident_scenario.py`
(7 tests, all passing at the worktree head):

- positive control: the two authorized acts (the
  approved authentication-settings change, identified
  by its change set; the approved scoped records
  export, bound to the exact file and scope) each
  execute exactly once under genuine, well-formed
  verified approval envelopes; each permit, spent at
  its consume, cannot run its act twice;
  reconciliation of executed-vs-approved reports exact
  equality (2 approved, 2 executed, 0 unauthorized);
  the audit chain verifies.
- step 1: the configuration change refused at
  consume, and the refusal is free — the genuine
  change's permit, presented FIRST for the attacker's
  change set (the same system, the same action, a
  change no human approved), is refused at the
  kernel's intent binding, the rejection naming the
  attacker intent's hash; the refusal consumes
  nothing, and the genuine permit then spends on its
  own act, exactly once. The chain does not advance
  past the refusal: the takeover, presented with the
  harvested administrator credential as its permit, is
  refused at the same boundary. Under the reported
  architecture neither attempt faces the question: the
  possessed credential is the whole check at both.
- step 2: possessed credentials presented as permits —
  the only artifacts the reported chain ever ran on,
  in the role they played there — are refused at
  `consume` for the attacker's configuration change,
  the takeover, the bulk export, and the genuine
  configuration change alike (4 rejections, each
  naming its intent's hash). Possession authenticates
  a holder, and authorizes no act — not even a
  legitimate one.
- step 3: with no artifact presented at all,
  `evaluate` returns `require_approval` for every act
  in the chain — the workflow modification, the
  configuration change, the takeover, the bulk export;
  and an approval envelope for the configuration
  change signed with a key the attacker controls is
  denied (`approval_signature_invalid`). The kernel
  verifies against the enrolled authority, and the
  party requesting the act cannot also be the party
  approving it.
- step 4: reconciliation over a governed sequence
  shaped like the event — the two approved acts
  executed, the attacker's chain attempted under every
  form the event makes available (the genuine change's
  permit stretched to the attacker's change set, the
  harvested credential presented for the takeover, the
  scoped export's permit stretched to the bulk file,
  the stolen credential presented for the bulk file,
  and both spent permits replayed; 6 `permit_rejected`
  records, 2 `permit_consumed`) — reports exact
  equality: 2 approved, 2 executed, 0 unauthorized
  occurrences, and no refused attempt recorded as
  fulfilled. The comparison the reported path never
  runs, run here, is clean precisely because every
  unapproved attempt was denied before it could
  execute.
- step 5: the incident channel sees the attempts —
  freezing a report over the full attempt sequence
  exercisable on one kernel (the no-approval
  evaluation of the attacker's configuration change,
  the harvested credential presented as a permit for
  it, the genuine approval stretched to the attacker's
  change set, the one legitimate configuration
  execution, and the spent-permit replay) yields zero
  incidents and exactly the near-miss records the
  channel's derivation produces from the audit:
  2 `permit_rejected`, 1 `approval_rejected`,
  1 denied `decision`, and 1 `require_approval`
  `decision` (5 near-misses in total), each classified
  Recorded under a valid audit chain; the freeze
  appends nothing. The `require_approval` decision
  contributes one near-miss per occurrence under the
  issue #375 derivation (PR #413) — this module was
  authored after that fix landed, so its counts are
  born correct against it.
- negative control: with no governor at all, the
  possession boundary double does exactly what the
  notice describes — it takes the presented credential
  at face value, and possession is the whole check.
  The stolen version-control credential rewrites the
  automated workflows and harvests the sign-in
  administrator credential; that credential rewrites
  an employee's authentication settings; the rewritten
  access signs in as the employee; and the session
  exports and downloads the bulk legacy
  account-records file. Nothing between the first step
  and the last asked whether any of it was approved;
  each step required only the previous step's output.
  Per-occurrence reconciliation against exact-action
  approvals — of which the possession architecture
  produces none, for any act — reports the run
  exactly: 0 approved, 4 executed, 4 unauthorized
  occurrences, named, in chain order. The denials in
  the steps above therefore come from the governed
  path's fail-closed authorization, exact-intent
  binding, and signature verification, not from a
  harness that denies by construction, and the
  reconciliation demonstrably detects the modeled
  shape when it does occur.

Full suite at the worktree head: **1195 tests,
OK (skipped=13)** in this environment —
the recorded local baseline at the base commit
`f734c97e` is 1188 OK (skipped=13);
the delta is exactly the 7 scenario tests. (The
skipped figure is this environment's count; CI records
its own environment's skipped count with the same test
total modulo environment-specific discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — if the boundary were merely optimizing for
  internal velocity (the reported environment's actual
  condition: developer automation and sign-in
  administration are built so legitimate work is
  frictionless), the fastest route from a credential
  to a consequence is to check possession and nothing
  else. On the governed path, velocity has no
  dimension to exploit: a credential is an
  unauthenticated string at consume (step 2), genuine
  authority stops at its own intent (step 1), and
  flipping the presenter changes nothing without the
  enrolled key (step 3).
- Reverse — the consequence (an executed internal act)
  requires a consumed permit; the permit requires a
  verified approval; the approval is bound to the
  exact intent hash and signed by the enrolled
  authority. The earliest unreachable point is the act
  itself: the executor runs nothing without a consume,
  and the chain does not collapse to one control —
  possession stops at consume (step 2), scope stops at
  intent binding (step 1), self-assertion stops at
  signature verification (step 3), replay stops at
  single-use consumption (positive control), and
  absence of any artifact stops at the approval
  requirement (step 3). The reported chain's defining
  property — each step's output is the next step's
  only requirement — is exactly what this ordering
  breaks: no governed step's output is authority for
  the next.
- Invert — outcome is not legitimacy: on the reported
  path every step "worked" — the workflows ran, the
  settings changed, the sign-in succeeded, the export
  completed — and every part of that success rested on
  possession. The negative control reproduces exactly
  that shape: all four acts "succeed," and the
  reconciliation still reports all four as carrying no
  exact-action approval, so a successful execution
  under a possessed credential is classified by the
  record as unapproved, not as authorized.
- Inside-Out — the governor cannot originate the
  authority it enforces: the boundary holds no
  approval capability, the reconciliation helper is
  read-only over the harness's log and holds no
  canonical state, the possession double is test-only,
  and the orchestrator surface used for the incident
  report is read-only with its freeze asserted to
  append nothing (step 5). In particular, the kernel
  has no route by which material a presenter holds —
  a credential included — becomes authority:
  `CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`,
  and possession is not an approval transition.
- Darken — worst credible bounded case, from the
  reporting's own shape: one stolen developer
  credential becomes, in roughly a day, the run of the
  production estate — the authority system rewritten,
  persistence accounts created, production commands
  run, and the bulk records of millions of users
  downloaded before a monitoring flag, some eleven
  hours after the authority system itself was changed,
  ends it. Inside the governed path the maximum
  consequence per approval remains the one approved
  act, once; every unauthorized attempt produces audit
  records only — one per attempt on the bare-evaluate
  and consume routes, two (an `approval_rejected`
  record and a denied decision record) on the denied
  approval-envelope route — and zero executed acts.
  Outside the governed path stands the modeled worst
  case — internal paths that execute on a possessed
  credential alone — and this replay does not mitigate
  it; it is the boundary in section 5.
- Lighten — minimum benign interpretation: privileged
  credentials for developer automation and sign-in
  administration are ordinary, necessary tooling, and
  most acts they perform are legitimate work by the
  people who hold them. The governed path preserves
  what is benign: the approved configuration change
  and the approved scoped export both work (positive
  control), and each act's authorization becomes a
  governed question instead of an implication of
  whoever happens to hold the credential that morning.
- Amplify — the modeled harm is amplification by
  derivation: one possessed credential derives the
  next, and the next, until the derived authority
  exceeds anything the original credential's owner
  ever held — `AUTHORIZATION_TO_USE_CAPABILITY !=
  AUTHORIZATION_TO_DUPLICATE_CAPABILITY`. On the
  governed path, amplification multiplies attempts,
  never authority: credentials spend on nothing no
  matter how many acts they are presented for
  (step 2), approvals are per-intent and permits
  single-use (steps 1, 3), no governed step's output
  is the next step's authority (Reverse), and the
  reconciliation counts occurrences, so amplification
  is measured, not averaged away (negative control:
  4 unauthorized occurrences over the modeled chain).
- Negate — the smallest clean path: a consequential
  internal act — above all, a change to the authority
  system itself — must require an approval the
  presenter cannot supply by presenting a possessed
  artifact — signed by an enrolled authority and bound
  to the exact intent. The harvested credential, the
  stretched permits, and the attacker-signed envelope
  are each unnecessary to the approved tasks; remove
  the signature check and step 3's route returns,
  remove intent binding and step 1's returns; with
  both, the chain's shape has no governed route.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models governed internal acts at a kernel
boundary. It proves nothing about Todoist's or Doist's
actual systems, controls, or remediation, any
version-control, sign-in, or cloud product's behavior,
or any deployed environment, and it reproduces none of
the event's mechanics — the boundary's log entries are
inert labels, the possession double is a test-local
model faithful only in the properties the scenario
names (a presented credential taken at face value;
acts executed as presented; each step's output
available as the next step's artifact), and no real
credential, account detail, workflow definition, or
customer record from the real event appears anywhere
in the module. It proves nothing about non-governed
paths: an internal path that executes on a possessed
credential alone is governed by nothing here — a
control not on the execution path governs nothing.

The event narrative rests on the operator's own
incident notice, corroborated by named-outlet
reporting; the notice is the operator's account of its
own incident, and this change does not independently
verify Todoist's internal facts beyond the published
record. In particular: how the original credential was
stolen is Unknown on the face of the notice itself, so
no step models the theft — the chain begins, as the
notice does, at the credential's first identified use.
The notice's scope figures are the operator's
approximations ("approximately"), carried here as
Recorded, not as audited counts. The scenario models
the chain's four load-bearing acts (workflow
modification, access-configuration change, takeover
sign-in, bulk export) and does not model the reported
persistence accounts, production command execution,
token queries, Outlook mailbox access, or content
searches, each of which would be its own governed act
under the same rule. Every count inside the module
(the approved export's scope, the attack export's
size) is a scenario parameter, not a reported figure.

## 6. Claim classification

- Between November 22 and 23, 2026, an attacker used
  a stolen credential associated with Todoist's
  version control system to modify automated workflows
  in three repositories and obtain additional
  credentials; no application code was changed:
  **Recorded** (Todoist security notice, 2026-11-24,
  read firsthand).
- One harvested credential was an administrative
  credential for the employee sign-in system; the
  attacker used it to change an employee's
  authentication settings (November 23, 06:33–06:54
  UTC) and sign in to the cloud infrastructure as that
  employee; the bulk account records were exported and
  downloaded the same day (12:45–12:51 UTC); detection
  came at 17:01 UTC via an unexpected administrator
  account: **Recorded** (Todoist security notice
  timeline, as above).
- The scope — email addresses, salted SHA1 password
  hashes, and account creation dates for approximately
  6% of users; API/Slack tokens for approximately
  0.003%; credential-like content for approximately
  0.001%; connected-Outlook email previews for
  approximately 0.001% — and Todoist's figure of more
  than 50 million users: **Recorded** (Todoist
  security notice; the user-base figure as carried by
  TechCrunch, 2026-11-25).
- How the original credential was stolen: **Unknown**
  — Todoist states it has not established this; its
  leading theory (an employee's device may have been
  compromised) is expressly unconfirmed, and is
  carried here as the operator's unconfirmed theory,
  not as a finding.
- That the chain's acts executed on possession of
  credentials alone, with no per-act approval by an
  accountable human anywhere in the path: **Inferred**
  from the notice's own account — the notice describes
  no approval step in the path, and the modeled
  property is demonstrated executably against the
  possession double built to the notice's description
  (negative control), not observed inside Todoist's
  systems.
- That this event belongs to the governed class at
  all: **Proposed** — the 2026-11-26 incident scan
  classified it out of class (legitimate-privilege
  lateral movement); this replay was built on Austin's
  direction (2026-11-27) on the ground that the
  access-configuration change is a change to the
  authority system itself. The disagreement is
  recorded, not resolved by this change.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree
  head commit).
- The mapping from the reported chain to kernel
  artifacts (the internal-systems boundary as one
  boundary; the two configuration change sets, the
  takeover, and the two exports as distinct intents;
  the credentials modeled as consume-presented
  strings): **Inferred** — the harness's modeling
  choices, stated in the module docstring.
- Any claim that this prevents the modeled class in a
  deployed system: **Proposed** — not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346–#350, #362–#368, #374–#382, #386,
and #391–#393, and the approval-path construction of
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

Results (Verified — executed at both states):

- TRANSFERS: all 7 scenario tests pass identically at
  `f734c97e` — the positive control executing each
  approved act exactly once with exact reconciliation,
  the attacker's configuration change refused at
  consume under the genuine permit with the refusal
  burning nothing and the takeover refused behind it,
  the possessed credentials refused as permits for
  every act attempted, the no-approval and
  attacker-signed denials, the governed-sequence
  reconciliation reporting zero unauthorized, the
  incident channel's 0 incidents / 5 near-misses, and
  the negative control executing the whole
  four-act chain under no governor with reconciliation
  reporting 4 unauthorized occurrences.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed.

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.

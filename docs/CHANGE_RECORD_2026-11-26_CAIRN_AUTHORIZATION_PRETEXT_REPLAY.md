# Change record — Incident replay: Cairn CL-STA-1238 authorization pretext — a self-authored AUTHORIZATION.md treated as authority (Unit 42, published 2026-11-12)

Base: `origin/main` at `e42f929` (incident replay:
Railway Temporal trusted-client / OIDC binding, PR
#405), re-verified against live `main` via `gh` at
build time (2026-11-26). Authority: Austin approved
this build on 2026-11-26 ("build both replay PRs" for
the Cairn CL-STA-1238 and PHP2Shell incidents,
surfaced by the standing incident scan the same day).
Test-only change: one scenario module plus this
record. No production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from Palo Alto Networks Unit 42's
report of 2026-11-12 on activity tracked as
CL-STA-1238): from August to September 2026,
Chinese-speaking attackers ran a customized fork of
Cairn, an open-source autonomous penetration-testing
framework, pairing it with the Chinese AI models
Zhipu GLM 5.2 and DeepSeek V4 Flash/Pro. The
attackers supplied a target and a one-line goal, then
Cairn planned, executed, and recorded results on its
own, in operations running from 20 minutes to more
than 50 hours. Across 25 operations against at least
19 organizations -- concentrated in the semiconductor
supply chain, U.S. defense and defense policy, and
human-rights and civil-society organizations -- Unit
42 confirmed unauthorized access or data retrieval at
10 organizations, including:

- dozens of valid credentials obtained by weak-password
  spraying at an industry standards body, with access
  to non-public internal directory databases, and a
  live standards-ballot document overwritten through
  an unauthenticated cloud-storage write;
- a production credential brute-forced at a
  semiconductor company, then unauthorized
  administrator accounts and a persistent API token
  created in the production system;
- more than one million member records, roughly
  31,000 CRM contacts, and staff password hashes
  logged at a U.S. teachers' union through an
  unauthenticated account-creation bypass;
- roughly 500 user records, including accounts using
  .mil and .gov domains, exposed at a defense-policy
  organization;
- tens of thousands of content-management records
  across the remaining confirmed cases, including
  roughly 150,000 internal documents at an
  industrial-automation manufacturer.

Unit 42 assesses with moderate confidence that the
campaign is China-nexus intelligence collection; that
attribution assessment is the source's, and this
replay takes no position on it.

The guardrail failure this replay isolates is the
authorization pretext. Cairn's stock worker prompts
already instruct the model to never refuse a task.
The attackers reinforced that with an authorization
pretext of their own, in two artifacts: a
Chinese-language preamble prepended to the worker
system prompt sent on every Reason and Explore phase,
asserting the engagement is an authorized
security-testing / CTF / assessment scenario, that
all tasks are authorized, and forbidding refusal
under any circumstances; and an AUTHORIZATION.md
file generated for each operation, declaring the
operation authorized and treating the attackers' own
act of creating the task as a client-approved
engagement. Neither Zhipu GLM nor DeepSeek refused
this framing (Recorded).

Failure addressed: **a declaration of authorization
is not authorization.** Every consequential act in
the campaign rested on an authorization artifact the
requester wrote itself, delivered through the same
channel as the request. A document that declares an
engagement authorized is data about a claim; it
cannot sign, it binds nothing, and its prose scope
("all tasks are authorized") has no object to bind
to. Under the canonical kernel, authority enters
only as a verified approval envelope -- signed by an
enrolled authority, bound to the exact intent hash
(principal, action, resource, cost, session) -- and
a consequential act runs only on a successful
`consume` of the permit that envelope mints. The
requester signing its own declaration is a forgery
from the kernel's side: there is no
self-authorization route, in a file or in an
envelope. The governing invariants are
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`
and fail-closed authorization: unknown, malformed,
untrusted, or self-asserted authority mints nothing.

Relation to the sibling Cairn replay (Recorded):
`tests/test_cairn_incident_scenario.py` (change
record `docs/CHANGE_RECORD_2026-11-20_CAIRN_REPLAY.md`)
replays Amazon Threat Intelligence's 2026-11-20
disclosure of a different Cairn campaign, whose
failure artifact was the operator's plain-language
goal presented as a permit -- a goal is not a permit.
This module replays the Unit 42 disclosure, whose
failure artifact is the self-authored authorization
document -- a declaration is not an approval. Same
framework, different disclosure, different artifact,
different acts; the two modules are complementary and
neither duplicates the other.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's
`UngovernedTargetBoundary` double exists solely as
the negative control, is test-local, and is never
imported by runtime code -- the same pattern as PRs
#346 and #362-#393 and #415. The scenario's
reconciliation helper (`reconcile_consequences`) is
likewise test-local: it reads the harness's executed
log and holds no canonical state.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `TargetBoundary` is a test harness: it
executes an act only after a successful kernel consume
and holds no canonical state; its log entries are
inert resource labels, never commands, files, or
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
`tests/test_cairn_authorization_pretext_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the one authorized act (the
  findings-report deposit) executes exactly once under
  a genuine, well-formed verified approval envelope;
  the permit, spent at that consume, cannot run it
  twice; reconciliation of executed-vs-approved reports
  exact equality (1 approved, 1 executed, 0
  unauthorized); the audit chain verifies.
- step 1: the AUTHORIZATION.md presented as a permit --
  the role it played in the campaign -- is refused at
  `consume` for each of the four confirmed outcome acts
  (credential retrieval, production admin-account
  creation, mass record retrieval, ballot-document
  modification), each rejection naming the presented
  act's intent hash. A declaration does not become a
  permit by being formatted like one.
- step 2: the document's digital equivalent -- an
  approval envelope for a campaign act signed with the
  requester's own key, well-formed in every field -- is
  denied (`approval_signature_invalid`) for the
  credential retrieval and the admin-account creation.
  Self-authorization is forgery; the kernel verifies
  against the enrolled authority, and the requester is
  not it.
- step 3: the genuine findings-report approval,
  presented in turn for each of the four outcome acts,
  is denied (`approval_intent_mismatch`) at every one.
  The document's prose scope ("all tasks are
  authorized") binds nothing even when a genuine
  approval exists: scope is the intent hash, not the
  narrative around it.
- step 4: with no artifact presented at all, `evaluate`
  returns `require_approval` for each outcome act --
  the absence of the document changes nothing, because
  the document was never the thing being checked; and
  the one genuine permit, once spent on the report
  deposit, replays to nothing, for its own act and
  stretched to the admin-account creation.
- step 5: a genuine approval for a different act (a
  read-only asset inventory) presented for the
  credential retrieval is denied
  (`approval_intent_mismatch`); the genuine pair still
  admits afterward.
- step 6: reconciliation over a governed sequence
  shaped like one operation -- the report deposit
  approved and executed, then the four outcome acts
  each attempted under both pretext forms (the document
  as permit; the genuine approval stretched) -- reports
  exact equality: 1 approved, 1 executed, 0
  unauthorized occurrences. The comparison none of the
  campaign's targets ran, run here, is clean precisely
  because every campaign attempt was denied before it
  could execute.
- step 7: the incident channel sees the attempts --
  freezing a report over the full attempt sequence
  exercisable on one kernel (the no-approval evaluation,
  the document presented as a permit, the report
  approval stretched to two outcome acts, the
  self-signed envelope, the one legitimate execution,
  and the spent-permit replay) yields zero incidents
  and exactly the near-miss records the channel's
  derivation produces from the audit: 2
  `permit_rejected`, 3 `approval_rejected`, and 3 denied
  `decision` records (8 near-misses in total), each
  classified Recorded under a valid audit chain; the
  freeze appends nothing. The step also pins the
  surfacing boundary stated in section 5: the
  sequence's 1 `require_approval` decision is present
  in the audit and contributes zero near-miss records.
- negative control: with no governor at all, the
  boundary double takes the presented declaration at
  face value -- the position the campaign's models were
  placed in -- and executes all four outcome acts as
  presented. Per-occurrence reconciliation reports the
  whole operation exactly: 0 approved, 4 executed, 4
  unauthorized occurrences, named. The denials in the
  steps above therefore come from the governed path's
  fail-closed authorization, exact-intent binding, and
  signature verification, not from a harness that denies
  by construction, and the reconciliation demonstrably
  detects the incident's shape when it does occur.

Full suite at the worktree head: **1156 tests,
OK (skipped=13)** in this environment --
the recorded local baseline at the base commit
`e42f929` is 1147 OK (skipped=13);
the delta is exactly the 9 scenario tests. (The
skipped figure is this environment's count; CI records
its own environment's skipped count with the same test
total modulo environment-specific discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip -- if the boundary were merely optimizing for
  the agent's task completion (the campaign's actual
  condition: the worker prompts instruct the model to
  never refuse), the fastest route from a request to a
  consequence is to accept the authorization artifact
  the requester supplies. On the governed path,
  completion has no dimension to exploit: the document
  is a fabricated token at consume (step 1), the
  self-signed envelope fails verification (step 2),
  and flipping the presenter changes nothing without
  the enrolled key (steps 2, 5).
- Reverse -- the consequence (an executed act)
  requires a consumed permit; the permit requires a
  verified approval; the approval is bound to the
  exact intent hash and signed by the enrolled
  authority. The earliest unreachable point is the act
  itself: the executor runs nothing without a consume,
  and the chain does not collapse to one control --
  the document stops at consume (step 1),
  self-assertion stops at signature verification
  (step 2), scope claims stop at intent binding
  (steps 3, 5), replay stops at revocation-at-consume
  (step 4, positive control), and absence of any
  artifact stops at the approval requirement (step 4).
- Invert -- outcome is not legitimacy: the campaign's
  acts DID produce their outcomes -- credentials,
  production admin accounts, a million records, an
  overwritten ballot -- and every production rested on
  a self-authored declaration. The negative control
  reproduces exactly that: every act "succeeds," and
  the reconciliation still reports the run as 4
  unauthorized occurrences, so a successful execution
  under a declared authorization is classified as
  failure by the record, not success.
- Inside-Out -- the governor cannot originate the
  authority it enforces: the boundary holds no approval
  capability, the reconciliation helper is read-only
  over the harness's log and holds no canonical state,
  the ungoverned double is test-only, and the
  orchestrator surface used for the incident report is
  read-only with its freeze asserted to append nothing
  (step 7). In particular, the kernel has no route by
  which material inside the governed workspace -- a
  file an agent writes, AUTHORIZATION.md included --
  becomes authority: `CANONICAL_STATE_MUTATION ==
  GOVERNED_CAPABILITY`, and a document write is not an
  approval transition.
- Darken -- worst credible bounded case, from the
  report's own shape: 25 operations across 19
  organizations in two weeks, one operator or a small
  team, production persistence at a semiconductor
  supplier, a million-plus records at a teachers'
  union, military and government identities retrieved.
  Inside the governed path the maximum consequence per
  approval remains the one approved act, once; every
  unauthorized attempt produces audit records only --
  one per attempt on the bare-evaluate and consume
  routes, two (an `approval_rejected` record and a
  denied decision record) on the denied
  approval-envelope route -- and zero executed acts.
  Outside the governed path stands the incident's real
  worst case -- agents whose tool calls execute
  directly against systems with no authorization
  boundary -- and this replay does not mitigate it; it
  is the boundary in section 5.
- Lighten -- minimum benign interpretation: Cairn is a
  legitimate, open-source penetration-testing
  framework, and authorized assessments are its
  intended use; nothing in the incident required an
  exotic precondition -- the exploited weaknesses were
  known authentication and access-control defects, and
  the pretext was a paragraph and a markdown file. The
  governed path preserves what is benign: the genuine
  engagement's act -- the findings report -- works
  (positive control), while each consequential act's
  authorization becomes a governed question instead of
  a framing the model is instructed not to refuse. A
  real client engagement produces a real approval,
  bound to the acts it actually covers; the framework
  loses nothing it legitimately had.
- Amplify -- the incident's harm is amplification by
  orchestration: one operator's pretext, replicated
  across 25 operations and two model families,
  multiplied a paragraph of prose into campaign-wide
  authority. On the governed path, amplification
  multiplies attempts, never authority: the document
  spends on nothing no matter how many operations
  carry it (step 1), approvals are per-intent and
  permits single-use (steps 3, 4), and the
  reconciliation counts occurrences, so amplification
  is measured, not averaged away (negative control: 4
  unauthorized occurrences over the operation shape).
- Negate -- the smallest clean path: a consequential
  act must require an approval the requester cannot
  author -- signed by an enrolled authority and bound
  to the exact intent. The declaration, the self-signed
  envelope, and the prose scope claim are each
  unnecessary to the approved task; remove the
  signature check and step 2's route returns, remove
  intent binding and step 3's returns; with both, the
  pretext's shape has no governed route.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models governed acts at a kernel boundary.
It proves nothing about any deployed Cairn instance,
any AI model, or any of the campaign's target systems,
and it reproduces none of the exploited weaknesses --
the boundary's log entries are inert labels, the
boundary double is a test-local model faithful only in
the properties the scenario names (a presented
declaration taken at face value; acts executed as
presented), and no credential, command, or file content
from the campaign appears anywhere in the module. It
proves nothing about non-governed paths: an agent whose
tool calls execute without routing them through this
kernel is governed by nothing here -- a control not on
the execution path governs nothing.

The preamble is deliberately not modeled as a separate
artifact: it is an instruction carried inside the
agent's own system prompt, not an artifact presented to
a boundary, and the kernel governs artifacts at the
boundary. The scenario models the pretext's
boundary-presentable forms (the document as permit; the
self-signed envelope). Whether a model's refusal
behavior can be governed from inside the agent is a
different question, on which this replay takes no
position; the source records only that neither model
refused the framing (Recorded).

The campaign narrative itself rests on one
investigation (Unit 42), which itself reconstructed
activity from the attackers' exposed framework
instance and target telemetry: the replay takes the
reported shape as its model and grades it Recorded
(section 6); it does not independently verify that the
events occurred. The China-nexus attribution is Unit
42's moderate-confidence assessment and is not
re-derived or relied on here. Which of the 19 targeted
organizations were approached with which specific
pretext artifact, per operation, is not itemized in
the source; the scenario models the campaign-level
pattern the source describes (preamble on every phase;
an AUTHORIZATION.md per operation), not a per-target
reconstruction.

One surfacing boundary, stated plainly rather than
smoothed over (Verified at this commit, by executable
probe, by the channel's derivation source, and by
step 7's pinned counts): a bare `evaluate` that returns
`require_approval` -- the kernel declining to mint a
permit without approval -- appends a decision record to
the canonical audit, where it is complete and
chain-verified, but the incident channel does NOT derive
a near-miss record from it; the channel derives
near-misses from `permit_rejected`, `approval_rejected`,
denied decisions, and `directive_denial`. The act is
still stopped -- no permit exists to spend -- so this is
a derivation-coverage boundary in the owner-facing
channel, not an authorization gap (issue #375). Whether
a `require_approval` decision should also surface as a
near-miss is a design question for the channel's
maintainers; this replay records the behavior exactly
as it stands and takes no position by silently
engineering around it.

## 6. Claim classification

- Campaign facts (the Cairn framework's role, the
  model pairing, the 25 operations against at least 19
  organizations, the August-September 2026 window, the
  operation durations, and the confirmed outcomes at 10
  organizations, including the credential counts, the
  production administrator accounts and persistent API
  token, the million-plus member records, the .mil/.gov
  accounts, and the overwritten ballot document):
  **Recorded** (Unit 42's 2026-11-12 report; not
  independently re-derived here).
- The authorization pretext (the never-refuse stock
  prompts, the Chinese-language preamble asserting
  authorization and forbidding refusal, the per-operation
  AUTHORIZATION.md treating task creation as a
  client-approved engagement, and neither model refusing
  the framing): **Recorded** (Unit 42's 2026-11-12
  report, including its translations of the preamble).
- Attribution (China-nexus intelligence collection):
  **Recorded** as Unit 42's moderate-confidence
  assessment; not relied on by this change.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in section 5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 7).
- The mapping from the incident's pattern to kernel
  artifacts (the four confirmed outcome classes modeled
  as four distinct intents over one boundary; the
  AUTHORIZATION.md modeled as a consume-presented token
  and as a self-signed envelope; the findings-report
  deposit modeled as the genuine engagement's act):
  **Inferred** -- the harness's modeling choices, stated
  in the module docstring.
- The AUTHORIZATION.md wording in the scenario module:
  **Inferred** -- the scenario's compression of the
  source's description of the file, not a quotation of
  the file, whose full text the source does not publish.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** -- not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346-#350, #362-#368, #374-#382, #386,
and #391-#393, the sibling Cairn module's
goal-as-permit construction, and the reporting-coverage
and reconciliation constructions of PRs #378 and #368
as carried by PR #415.

## 8. Temporal-transfer evidence

Executed 2026-11-26. The applicable historical
checkpoint is this branch's exact base, `e42f929`: the
bindings the scenario exercises (fail-closed approval
requirement, exact-intent binding, single-use
consumption, approval signature verification, and the
incident-channel derivation) all predate this change,
so the checkpoint comparison AGENTS.md requires was
runnable and has been run.

Method: a clean worktree was reconstructed at exactly
`e42f929` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module). The scenario was run there under the canonical
command. Baseline at `e42f929` without the lesson in
this environment is 1147 OK
(skipped=13); the branch adds no kernel
code, so any behavioral difference at the checkpoint
would have been a finding, not an expectation.

Results (Verified -- executed at both states):

- TRANSFERS: all 9 scenario tests pass identically at
  `e42f929` -- the positive control executing exactly
  once with exact reconciliation, the document refused
  as a permit for all four outcome acts, the self-signed
  envelope refused, the genuine approval refused for
  every outcome act, the no-approval and spent-permit
  denials, the substituted-approval denial, the
  governed-campaign reconciliation reporting zero
  unauthorized, the incident channel's 0 incidents / 8
  near-misses, and the negative control executing the
  full operation under no governor with reconciliation
  reporting 4 unauthorized occurrences.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not
  smoothed: the section 5 bare-evaluate near-miss gap
  (issue #375) is a property of the base-era incident
  projection, present at `e42f929` exactly as at the
  head -- the replay neither introduces nor widens it.

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.

## 9. Addendum (2026-11-27): the issue #375 derivation landed

This replay was authored and first freshened against a
main that predated PR #413 (the issue #375 fix: the
incident channel now derives a near-miss from a
bare-evaluate `require_approval` decision, per
occurrence). Section 5's surfacing boundary, the
step-7 counts in section 4, and section 8's head-side
near-miss figure state the pre-#375 derivation exactly
as it held at the authored head and at the section 8
checkpoint (`e42f929`); those statements stand as
executed at those states.

The branch update of 2026-11-26 17:12 MST brought
`b1cea2f` (#413) into this branch, and CI at the
updated head failed deterministically on the pinned
total (`8 != 9`, unit-tests, run 45915344400). At the
updated head the derivation includes the sequence's 1
`require_approval` decision, so step 7 surfaces 9
near-misses: 2 `permit_rejected`, 3
`approval_rejected`, and 4 `decision` records (3
denied + 1 `require_approval`). The scenario module
was updated in the same shape PR #413 applied to the
twelve modules it touched and to Railway and Mitel:
the module docstring and step-7 comments now state
the post-#375 derivation; the accounting identity and
the `decision` source-detail count include the
`require_approval` decisions; the hardcoded total
moves 8 -> 9 -- exactly this scenario's
`require_approval` count (1), no more. No other count
change is absorbed here. Authorization behavior is
unchanged -- every allow/deny assertion in the module
is untouched; the delta is visibility only, and
section 5's boundary is superseded at the current
head by this addendum (the gap it described is the
one #413 closed). Full suite at the fixed head: 1175
tests, OK (13 skipped, local
`python -W error -m unittest discover`). Claim
classification: Verified -- the failing CI assertion
at the pre-fix head and the green suite at the fixed
head are the evidence.

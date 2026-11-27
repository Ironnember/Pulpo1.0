# Change record — Incident replay: SAP "Project Granite" — stolen employee tokens used on the trusted code path (reported 2026-11-26)

Base: `origin/main` at `10b089e` (incident replay:
Cairn CL-STA-1238 authorization pretext, PR #416),
re-verified against live `main` via `gh` at build
time (2026-11-27). Authority: Austin approved this
build on 2026-11-27 ("build both replay PRs" for the
SAP Project Granite and Morris guard-bypass
incidents, surfaced by the standing incident scan the
same day), and gave his explicit proceed for this
build's clone the same morning. Test-only change: one
scenario module plus this record. No production code
is touched.

## 1. Invariant or failure addressed

Incident (graded from the public record): SAP
confirmed (Verified, SAP's statements to
BleepingComputer and dpa) that it identified
suspicious activity in its GitHub development
environment and promptly implemented the necessary
measures to protect its customers and preserve the
security of its services, and that, based on its
investigation to date, it has found no evidence of
unauthorized access to customer business data. Der
Spiegel reported (Recorded, insider sources) that
attackers stole authentication tokens belonging to
SAP employees and used them to copy and alter SAP
source code on GitHub, and that SAP tracks the
incident internally as an "active security incident"
under the code name "Project Granite." Handelsblatt
reported (Recorded, insider sources; SAP has not
confirmed the specifics) the response: GitHub access
restricted, automated build and delivery pipelines
paused, and code-signing keys rotated. SAP has not
confirmed the token theft, the code alteration, the
affected repositories, or any AI involvement, and
whether altered code reached any build or customer
shipment is Unknown on the public record.

Failure addressed: **a bearer credential is not
authority for the act.** The stolen token
authenticated its holder as the employee, for
everything the employee could do, on the trusted code
path: the credential was the only artifact the path
checked, and possessing it was treated as authority
for each act it was presented for -- copying source,
altering source, moving code toward build. At no
point did the path ask the separate question: was
THIS act authorized? Under the canonical kernel, the
token is not a permit at all -- presented at
`consume` it is an unauthenticated string and is
refused. Authority for an act enters only as a
verified approval envelope -- signed by an enrolled
authority, bound to the exact intent hash (principal,
action, resource, cost, session) -- and mints a
single-use permit for exactly that intent: a permit
minted for the engineer's ordinary work spends on
that work and nothing else. And when the incident
response revokes the standing authority the work ran
under -- the governed counterpart of restricting
access, pausing the pipelines, and rotating the keys
-- authority already issued but not yet consumed dies
at consume time, not merely at the next issuance.
The governing invariants are
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`
and fail-closed authorization: unknown, malformed,
untrusted, or merely possessed authority mints
nothing and spends nothing.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's
`UngovernedCodePathBoundary` double exists solely as
the negative control, is test-local, and is never
imported by runtime code -- the same pattern as PRs
#346 and #362-#393, #415, and #416. The scenario's
reconciliation helper (`reconcile_consequences`) is
likewise test-local: it reads the harness's executed
log and holds no canonical state.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`,
directive activation/revocation, governed directive
projection, audit read, and incident-channel
derivation paths, and adds no writer, route, ledger,
executor, or state backend. The scenario's
`CodePathBoundary` is a test harness: it executes an
act only after a successful kernel consume and holds
no canonical state; its log entries are inert
resource labels, never commands, files, or
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
the scenario pins. The directive activation and
revocation in Setup B are operator transitions in
their own right, each appending its own record; they
are the incident response modeled, not attempt
growth.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_sap_granite_incident_scenario.py`
(8 tests, all passing at the worktree head):

- positive control: the one authorized act (the
  engineer's ordinary source read) executes exactly
  once under a genuine, well-formed verified approval
  envelope; the permit, spent at that consume, cannot
  run it twice; reconciliation of executed-vs-approved
  reports exact equality (1 approved, 1 executed, 0
  unauthorized); the audit chain verifies.
- step 1: the stolen token presented as a permit --
  the role it played in the incident -- is refused at
  `consume` for the ordinary read and for both
  consequential acts (source alteration,
  promote-to-build), each rejection naming the
  presented act's intent hash. Possession
  authenticates the holder, and authorizes nothing.
- step 2: genuine authority stretched -- a real
  permit minted through a verified approval for the
  ordinary read, presented at consume for the
  alteration and the promotion -- is refused for both
  at the kernel's intent binding, and the refusals
  burn nothing: the genuine permit still spends on
  its own act, exactly once. Authority for daily work
  is not authority for the acts the theft was for.
- step 3: with no artifact presented at all,
  `evaluate` returns `require_approval` for each
  consequential act -- holding the employee's identity
  confers no route to a permit; and an approval
  envelope for the alteration signed with a key the
  token holder controls is denied
  (`approval_signature_invalid`). The kernel verifies
  against the enrolled authority, and the credential's
  holder is not it.
- step 4: reconciliation over a governed sequence
  shaped like the incident -- the ordinary read
  approved and executed, then the alteration and the
  promotion each attempted under the theft's two forms
  (the token as permit; the genuine read permit
  stretched) -- reports exact equality: 1 approved, 1
  executed, 0 unauthorized occurrences. The comparison
  the incident's path never ran, run here, is clean
  precisely because every consequential attempt was
  denied before it could execute.
- step 5: the incident channel sees the attempts --
  freezing a report over the full attempt sequence
  exercisable on one kernel (the no-approval
  evaluation, the token presented as a permit for both
  consequential acts, the genuine read approval
  stretched to the alteration, the one legitimate
  execution, and the spent-permit replay) yields zero
  incidents and exactly the near-miss records the
  channel's derivation produces from the audit: 3
  `permit_rejected`, 1 `approval_rejected`, 1 denied
  `decision`, and 1 `require_approval` `decision`
  (6 near-misses in total), each classified Recorded
  under a valid audit chain; the freeze appends
  nothing. The `require_approval` decision contributes
  one near-miss per occurrence under the issue #375
  derivation (PR #413) -- this module was authored
  after that fix landed, so its counts are born
  correct against it rather than addended onto it.
- revocation (Setup B): the dev run operates under an
  active directive scoped to the dev environment. A
  read permit issued under it is consumed -- work done
  before the response, and it stands. A second read
  permit is issued and left unconsumed; the directive
  is then revoked (the governed counterpart of SAP's
  reported response), and the unconsumed permit fails
  at `consume` with the directive recorded as revoked
  (`directive_status == "directive_revoked"`).
  Revocation bites at consume time, which is the only
  time that protects the pipeline.
- negative control: with no governor at all, the
  boundary double takes the presented bearer
  credential at face value -- the position the
  incident's code path was in -- and executes all
  three acts as presented: the source copied, the
  source altered, the code promoted. Per-occurrence
  reconciliation reports the whole run exactly: 0
  approved, 3 executed, 3 unauthorized occurrences,
  named. The denials in the steps above therefore come
  from the governed path's fail-closed authorization,
  exact-intent binding, and signature verification,
  not from a harness that denies by construction, and
  the reconciliation demonstrably detects the
  incident's shape when it does occur.

Full suite at the worktree head: **1183 tests,
OK (skipped=13)** in this environment --
the recorded local baseline at the base commit
`10b089e` is 1175 OK (skipped=13);
the delta is exactly the 8 scenario tests. (The
skipped figure is this environment's count; CI records
its own environment's skipped count with the same test
total modulo environment-specific discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip -- if the boundary were merely optimizing for
  the developer's throughput (the incident's actual
  condition: the token was accepted because accepting
  it is what the path is for), the fastest route from
  a credential to a consequence is to check possession
  and nothing else. On the governed path, throughput
  has no dimension to exploit: the token is an
  unauthenticated string at consume (step 1), genuine
  authority stops at its own intent (step 2), and
  flipping the presenter changes nothing without the
  enrolled key (step 3).
- Reverse -- the consequence (an executed act)
  requires a consumed permit; the permit requires a
  verified approval; the approval is bound to the
  exact intent hash and signed by the enrolled
  authority. The earliest unreachable point is the act
  itself: the executor runs nothing without a consume,
  and the chain does not collapse to one control --
  possession stops at consume (step 1), scope stops at
  intent binding (step 2), self-assertion stops at
  signature verification (step 3), replay stops at
  revocation-at-consume (positive control, Setup B),
  and absence of any artifact stops at the approval
  requirement (step 3).
- Invert -- outcome is not legitimacy: on the
  incident's path the acts DID produce their outcomes
  -- source copied, source altered -- and every
  production rested on a possessed credential. The
  negative control reproduces exactly that: every act
  "succeeds," and the reconciliation still reports the
  run as 3 unauthorized occurrences, so a successful
  execution under a possessed credential is classified
  as failure by the record, not success.
- Inside-Out -- the governor cannot originate the
  authority it enforces: the boundary holds no approval
  capability, the reconciliation helper is read-only
  over the harness's log and holds no canonical state,
  the ungoverned double is test-only, and the
  orchestrator surface used for the incident report is
  read-only with its freeze asserted to append nothing
  (step 5). In particular, the kernel has no route by
  which material a credential holder presents -- a
  token string included -- becomes authority:
  `CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`,
  and possession is not an approval transition.
- Darken -- worst credible bounded case, from the
  reporting's own shape: an enterprise vendor's source
  copied and altered under stolen employee tokens,
  with the question of altered code reaching customer
  builds open on the public record. Inside the
  governed path the maximum consequence per approval
  remains the one approved act, once; every
  unauthorized attempt produces audit records only --
  one per attempt on the bare-evaluate and consume
  routes, two (an `approval_rejected` record and a
  denied decision record) on the denied
  approval-envelope route -- and zero executed acts;
  and revocation kills unconsumed authority at consume
  even mid-run (Setup B). Outside the governed path
  stands the incident's real worst case -- code paths
  that execute on a presented credential alone -- and
  this replay does not mitigate it; it is the boundary
  in section 5.
- Lighten -- minimum benign interpretation: employee
  tokens on a development platform are ordinary
  tooling, and the work they carry is legitimate every
  day; nothing in the incident required an exotic
  precondition -- a credential was taken and the path
  trusted it. The governed path preserves what is
  benign: the engineer's ordinary read works (positive
  control), work consumed before the response stands
  (Setup B), and each consequential act's authorization
  becomes a governed question instead of an implication
  of employment.
- Amplify -- the incident's harm is amplification by
  standing access: one stolen token, valid for
  everything its owner could do, multiplied a single
  theft into copy, alteration, and pipeline reach. On
  the governed path, amplification multiplies attempts,
  never authority: the token spends on nothing no
  matter how many acts it is presented for (step 1),
  approvals are per-intent and permits single-use
  (steps 2, 3), and the reconciliation counts
  occurrences, so amplification is measured, not
  averaged away (negative control: 3 unauthorized
  occurrences over the incident shape).
- Negate -- the smallest clean path: a consequential
  act must require an approval the credential holder
  cannot supply by possession -- signed by an enrolled
  authority and bound to the exact intent. The token,
  the stretched permit, and the holder-signed envelope
  are each unnecessary to the approved task; remove the
  signature check and step 3's route returns, remove
  intent binding and step 2's returns; with both, the
  theft's shape has no governed route.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models governed acts at a kernel boundary.
It proves nothing about SAP's actual systems, GitHub's
controls, or any deployed environment, and it
reproduces none of the incident's mechanics -- the
boundary's log entries are inert labels, the boundary
double is a test-local model faithful only in the
properties the scenario names (a presented credential
taken at face value; acts executed as presented), and
no token, credential, command, or source content from
the incident appears anywhere in the module. It proves
nothing about non-governed paths: a code path that
executes on a presented credential alone is governed by
nothing here -- a control not on the execution path
governs nothing.

The incident narrative itself rests on reporting SAP
has only partly confirmed. The replay takes the
reported shape as its model and grades each element
(section 6); it does not independently verify that the
token theft or the code alteration occurred. In
particular, the two Unknowns are load-bearing
boundaries, not details: whether AI agents assisted
the attackers is not modeled in any step (no step
asserts or assumes an agent's involvement -- the
boundary governs artifacts, whoever or whatever
presents them), and whether altered code reached any
build or customer shipment is not modeled or claimed
(the promotion intent models the act class -- moving
code toward build -- not any shipment outcome). Which
repositories were affected and which employees' tokens
were taken are not public; the scenario models one
engineer, one module, and one pipeline as the
campaign-level pattern the reporting describes, not a
per-target reconstruction.

## 6. Claim classification

- SAP confirmed a security incident in its GitHub
  development environment, took protective measures,
  and has found no evidence of unauthorized access to
  customer business data: **Verified** (SAP's own
  statements to BleepingComputer and dpa, read
  firsthand).
- Token theft (attackers stole SAP employees'
  authentication tokens) and source-code copying and
  alteration via those tokens; the internal code name
  "Project Granite": **Recorded** (Der Spiegel,
  insider sources; carried by dpa summaries).
- The specific countermeasures -- GitHub access
  restricted, automated build and delivery pipelines
  paused, code-signing keys rotated: **Recorded**
  (Handelsblatt, insider sources; SAP has not
  confirmed the specifics).
- AI-agent involvement in the incident; whether
  altered code reached any build or customer shipment:
  **Unknown** -- not modeled as fact anywhere in this
  change.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree
  head commit).
- The mapping from the incident's pattern to kernel
  artifacts (the dev environment as one boundary; the
  ordinary read, the alteration, and the promotion as
  three distinct intents; the stolen token modeled as
  a consume-presented string and as the genuine
  authority it could reach; SAP's countermeasures
  modeled as directive revocation): **Inferred** --
  the harness's modeling choices, stated in the module
  docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** -- not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346-#350, #362-#368, #374-#382, #386,
and #391-#393; the approval-path construction of PR
#416 (the sibling Cairn pretext replay) and the
directive-revocation construction of the NGINX2Root
scenario (Setup B) as carried by the canonical suite.

## 8. Temporal-transfer evidence

Executed 2026-11-27. The applicable historical
checkpoint is this branch's exact base, `10b089e`: the
bindings the scenario exercises (fail-closed approval
requirement, exact-intent binding, single-use
consumption, approval signature verification,
directive revocation at consume, and the
incident-channel derivation including the issue #375
near-miss rule) all predate this change, so the
checkpoint comparison AGENTS.md requires was runnable
and has been run.

Method: a clean worktree was reconstructed at exactly
`10b089e` (no tree rewriting; `git status` verified
the only delta from the checkpoint was the copied
scenario module). The scenario was run there under
the canonical command. Baseline at `10b089e` without
the lesson in this environment is 1175 OK
(skipped=13); the branch adds no kernel
code, so any behavioral difference at the checkpoint
would have been a finding, not an expectation.

Results (Verified -- executed at both states):

- TRANSFERS: all 8 scenario tests pass identically at
  `10b089e` -- the positive control executing exactly
  once with exact reconciliation, the stolen token
  refused as a permit for all three acts, the genuine
  ordinary permit refused for both consequential acts
  and still spending on its own act, the no-approval
  and holder-signed denials, the governed-sequence
  reconciliation reporting zero unauthorized, the
  incident channel's 0 incidents / 6 near-misses, the
  revoked directive invalidating the issued unconsumed
  permit while the pre-revocation consume stands, and
  the negative control executing the full run under no
  governor with reconciliation reporting 3 unauthorized
  occurrences.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed.

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.

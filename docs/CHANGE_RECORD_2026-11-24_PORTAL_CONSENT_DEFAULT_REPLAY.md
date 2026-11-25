# Change record — Incident replay: portal consent default — recorded entry permission without an affirmative consent act

Base: `origin/main` at `9aca02e` (incident replay:
WP connect WordPress plugins supply-chain backdoor,
PR #388).
Authority: the standing incident-replay program; the
operator directed this build after living the class
and approving the scenario design, including the
anonymity constraint recorded below.
Test-only change: one scenario module plus this
record. No production code is touched.

Anonymity constraint (binding on this change): the
underlying instance is a live private dispute. This
record and the scenario module model the generic
class only — no property name, no management
company, no portal vendor, no unit, no person, no
work-order number, and no date that identifies the
instance appears anywhere in this change. The class
is everywhere-true (consent defaults in resident and
service portals generally); the instance stays out
of the repository.

## 1. Invariant or failure addressed

The class (Recorded: a real instance of this class
is known to the authors; identifying details are
withheld by design, per the constraint above): a
resident-services portal recorded
`permission_to_enter = Yes` for a dwelling unit,
sourced from a user-interface default in the
service-request filing flow. The flow offered the
resident no way to decline; the same system records
`Permission to Enter: No` on other orders, so the
field can hold "No" — it simply was not offered in
this flow. The resident performed no affirmative
consent act: no signature, no confirmation, no
appointment. A maintenance actor could then attempt
physical entry into the unit relying on that record
as its authority.

Failure addressed: **a stored field was treated as
an authorization.** ``RECORDED_STATE !=
AUTHORIZATION``. Class: manufactured consent. The
record binds no intent (it does not say which actor,
for what purpose, in what window), names no
accountable approver (the resident never acted), and
has no provenance (its source is a default, not a
decision). State is evidence; state is not
provenance; provenance is not authority. The
governing invariants are the fail-closed rule of
AGENTS.md (unknown, malformed, untrusted, expired,
replayed, or unavailable authority fails closed
through the canonical kernel) and exact-intent
binding itself: under the kernel, a consequential
act requires a permit issued only after an approval
whose signature verifies against the value computed
from the payload under the enrolled authority's key,
bound to the exact intent — principal, action,
resource, cost, session — and spent exactly once at
consume, where the token is itself authenticated and
its state row re-checked. A stored default is none
of those things on any route: not a token the kernel
issued (consume refuses it), not a signature the
authority made (evaluation refuses it), not the
portal's to give (the portal system's own key is not
the resident's authority), and not a scope (a genuine
approval for one appointment refuses to stretch to
another entry, or past its window).

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately
vulnerable double (`_RecordTrustingVerifier`) exists
solely as the negative control, is test-local, and
is never imported by runtime code — the same pattern
as PRs #346 and #362–#400.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`,
audit read, and incident-channel derivation paths,
and adds no writer, route, ledger, executor, or
state backend. The scenario's `UnitEntryExecutor`
is a test harness: it records a consequence only
after a successful kernel consume and holds no
canonical state. The incident-channel freeze is
asserted read-only in the scenario itself (audit
length unchanged across the freeze). The step-7
reconciliation is test-level, against the public
`kernel.audit` read path (see §4 and §5): it
introduces no reconciler and no state mutation.
Audit growth is classified in the module docstring
per AGENTS.md (`NO_PERMIT != NO_GOVERNED_EFFECT`):
each denied attempt appends audit records — a
governed effect (evidence production), append-only,
with `authority_effect=none` and no capability
accumulation — assessed separately from governed
external consequences throughout. The count is per
route, not uniformly one: a bare `evaluate`
returning `require_approval` appends one decision
record; a denied `evaluate` appends one decision
record; a `consume` rejection appends one
`permit_rejected` record; a denied approval-envelope
evaluation appends two records — an
`approval_rejected` record and a denied decision
record. Growth stays bounded per attempt (at most
two records), which is the invariant the scenario
pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_portal_consent_default_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the one legitimate act (entry
  for the appointment the resident affirmatively
  approved) executes exactly once under a genuine,
  well-formed verified approval envelope; replay of
  the spent permit is denied; the audit chain
  verifies. The governed path permits the legitimate
  flow end to end — the scenario is not
  deny-everything.
- step 1: with no artifact at all, `evaluate`
  returns `require_approval` with no permit minted,
  and nothing executes — presence at the entry
  boundary is not an approval. An act the policy
  does not contain (`duplicate_key`, a verb the
  boundary has never been given for anyone) is
  denied outright (`action_not_allowed`).
- step 2: the portal record presented as a permit
  at the entry boundary is refused for both the
  unscheduled entry and the legitimate appointment
  (`permit_rejected`, reason
  `permit_signature_invalid`, bound to the exact
  intent hash each time). The record was never
  issued: no state row stands behind it and no
  genuine token signature does either, so a stored
  field is not an issuance.
- step 3: the portal record offered as an approval
  signature, a garbage string offered the same way,
  and an envelope signed with the portal system's
  own key are each denied
  (`approval_signature_invalid`); an empty signature
  is denied earlier and separately
  (`approval_signature_missing`). The governed path
  does not distinguish a correctly-formatted
  non-authority from a formless one, and the portal
  cannot mint the resident's consent with its own
  key — absence of consent fails closed here instead
  of defaulting to "Yes".
- step 4: the genuine grant does not stretch. The
  genuine envelope for the approved appointment
  presented for an unscheduled entry is denied
  (`approval_session_mismatch`); the genuine issued
  permit presented against the unscheduled entry at
  consume is refused (`permit_intent_mismatch`); the
  same envelope evaluated after its window has
  passed is denied (`approval_expired`). The denials
  do not poison the path — the same permit then
  performs its own appointment exactly once.
- step 5 (migration): the portal's data is copied
  into a fresh system of record (same policy, same
  enrolled resident authority, same deployment
  secret — a faithful migration). The standing
  record carried across is refused as a permit
  (`permit_signature_invalid`) and denied as an
  approval signature (`approval_signature_invalid`)
  exactly as in the old system. Even the genuine
  permit issued pre-migration does not spend in the
  new system: its token is well-formed and its
  signature genuine, but no issuance row stands
  behind it in the new system of record and consume
  re-checks the row; the refusal is recorded against
  the intent with no signature-failure reason — a
  state absence, not a forgery (Verified by
  executable probe at the base commit; the payload
  shape is pinned by the test). The migrated
  system's own genuine flow then works end to end,
  and the old permit still spends in the old system
  where its row lives: state carried over is not
  authority carried over, in either direction.
- step 6: the incident channel sees the attempts —
  freezing a report over the full attempt sequence
  in the class's own order (the no-artifact probe,
  the unlisted-act probe, the record spent as a
  permit, the record offered as an approval, the
  genuine envelope stretched to an unscheduled
  entry, the genuine permit spent against the
  unscheduled entry, the one legitimate execution,
  and the spent-permit replay) yields zero incidents
  and exactly the near-miss records the channel's
  derivation produces from the audit: 3
  `permit_rejected`, 2 `approval_rejected`, and 3
  denied `decision` records (8 near-misses in
  total), each classified Recorded under a valid
  audit chain; the freeze appends nothing. The step
  also pins the surfacing boundary stated in §5: the
  sequence's 1 `require_approval` decision is
  present in the audit and contributes zero
  near-miss records. The counts are from the
  executed run at this head, not estimates. The
  provenance defect is named in the record the
  channel derives: every near-miss in the sequence
  traces to an authorization claimed by state and
  absent in provenance.
- step 7 (reconciliation, class-specific): after
  the attempt sequence, the consequence ledger
  contains exactly the one legitimate effect (one
  `permit_consumed` record, for the appointment
  intent hash only; the unscheduled intent hash is
  present in the audited attempts and absent from
  the audited consequences). A test-level
  reconciliation of a claimed state against the
  kernel audit — verifying the audit chain first,
  then comparing consumed consequences and disclosed
  attempts, as in the gainsight, filename-deception,
  Mythos and hexpm scenarios — reconciles exactly
  for the honest claim (no undisclosed attempts, no
  unbacked or missing consequences, no phantom
  attempts). The portal's own claim — the standing
  "Yes" read as the portal reads it (permission to
  enter, unbound to the one appointment the resident
  actually approved, so the unscheduled entry stands
  authorized too) — fails by name
  (`unbacked_consequences` = the unscheduled intent
  hash): a standing permission with no matching
  authorization in the ledger, surfaced rather than
  silently accepted. A claim omitting the attempts
  fails by name (`undisclosed_attempts` = the full
  audited attempt set). What this proves, precisely:
  on the governed path, every standing permission
  can be matched to the act of consent that stands
  behind it, or flagged. It proves it by the
  test-level construction described here, not by a
  shipped reconciler: the shipped `def reconcile`
  APIs (`pulpo.effect_reconcile.reconcile_effects`,
  `pulpo.custody_reconcile`, the commerce budget
  reconciler) reconcile filesystem effects,
  custody-domain outcomes, and payment evidence —
  none of them takes a claimed consequence ledger
  against a kernel audit — so this step follows the
  prior scenarios' test-level pattern and claims
  exactly its semantics, no more.
- negative control: with the verifier swapped for
  the class's own shape — a verifier whose `verify`
  accepts the portal record itself as a valid
  signature — the record VERIFIES as an approval
  signature, a permit mints, and the unscheduled
  entry EXECUTES. Under the same double, a garbage
  string and the resident authority's real HMAC
  signature are both denied: only the record itself
  verifies, because the stored field is the whole
  check — the class's precision, reproduced at the
  exact layer it happens. The denials in the steps
  above therefore come from the governed
  verification's shape (a computed expected signature
  under the enrolled key, bound to the exact intent),
  not from a harness that denies by construction.

Full suite at the worktree head: **1115 tests, OK
(skipped=25)** in this environment — the recorded
local baseline at the base commit `9aca02e` is 1106
OK (skipped=25), verified by direct execution at the
pristine checkpoint (see §8); the delta is exactly
the 9 scenario tests. (The skipped=25 figure is this
environment's count; CI records its own
environment's skipped count with the same test total
modulo environment-specific discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — the class is itself a flip of the consent
  direction: the helpful component (the filing flow,
  built to make reporting a problem easy) is the
  consent path, and its convenience is the defect —
  it recorded agreement faithfully, straight into
  the system of record, without the resident ever
  agreeing. No control on the governed path depends
  on the interface's cooperation: no artifact (step
  1), the record (steps 2, 3), a garbage string
  (step 3), the portal's own key (step 3), and a
  copied record in a new system (step 5) are the
  same denial, and flipping the presenter (resident
  vs. maintenance actor vs. the portal itself)
  changes nothing without the enrolled key.
- Reverse — the consequence (a physical entry)
  requires a consumed permit; the permit requires a
  verified approval; the approval requires a
  signature computed from the payload under the
  enrolled authority's key by the accountable
  approver — the resident — bound to the exact
  intent. The earliest point at which the
  consequence becomes unreachable is the record
  itself, and the chain does not collapse to one
  control: the record fails at token authentication
  at consume (step 2) and at signature verification
  at evaluate (step 3), the portal's self-attestation
  fails at verification (step 3), the genuine grant
  fails to stretch at session binding, intent
  binding, and expiry (step 4), the carried-over
  artifacts fail at the state-row re-check in the
  new system (step 5), and the spent permit cannot
  be replayed (positive control, step 6).
- Invert — outcome is not legitimacy: inside the
  class, the portal's "success" (a complete record,
  a dispatched work order, a door opened) is an
  outcome-success at every layer and a legitimacy
  failure throughout — nothing in the chain was
  authorized by the person whose consent it claims.
  The governed record supports credit only for
  consumed acts under verified approvals, so a
  record-trusting entry would stand in the record
  as a consequence with no approval behind it,
  visible as such; the negative control produces
  exactly that shape, under the double rather than
  the kernel.
- Inside-Out — the governor cannot originate the
  authority it enforces: the approval verifier holds
  only verification; a stored field cannot produce
  an approval envelope or ceremony evidence at all;
  the portal system's own key is not enrolled as the
  resident's authority and its self-signed envelope
  is denied (step 3c); the test double is test-only;
  the orchestrator surface used for the incident
  report is read-only and its freeze is asserted to
  append nothing (step 6); the step-7 reconciliation
  reads the audit and asserts — it writes nothing.
- Darken — worst credible bounded case (a threat
  case, not a claim): the technique costs one
  service request and no credentials at all, and it
  reaches physical entry into a home. The record is
  standing, not single-use: it purports to authorize
  entry for as long as it is displayed, by any actor
  the holder dispatches, and it survives a change of
  management systems by being copied. Had the entry
  boundary been the only control, the blast radius
  is every unit whose portal carries the same
  default. Inside the governed path the maximum
  consequence per approval remains the one
  authorized appointment; every unauthorized attempt
  produces audit records only — one per attempt on
  the bare-evaluate and consume routes, two (an
  `approval_rejected` record and a denied decision
  record) on the denied approval-envelope route —
  and zero consequences. Outside the governed path
  stands the class's real worst case — doors that
  open on stored defaults, anywhere they still
  exist — and this replay does not mitigate it; it
  is the boundary in §5.
- Lighten — minimum benign interpretation: a
  defaulted "Yes" is plausibly a design shortcut,
  not a scheme — the flow's authors optimized for
  dispatch speed, the field's "No" exists elsewhere
  in the same system, and no entry may ever have
  been attempted on the strength of the record in
  the known instance (whether any entry occurred is
  not established — Unknown). The replay grades the
  mechanism — recorded state treated as
  authorization — not any actor's intent, and claims
  no harm the record does not show.
- Amplify — the attempt is free to replicate: many
  portals, many units, many defaults, each standing
  indefinitely. Approvals are per-intent and permits
  single-use, so replication multiplies claims,
  never authority; denial volume produces audit
  growth only, bounded per attempt, and step 7's
  reconciliation still accounts for every
  consequence exactly — and flags every standing
  claim that no consent backs, at whatever scale the
  claims are made.
- Negate — the smallest clean path: a consequential
  entry needs no record-trusting route at all.
  Record the request; authorize separately. A
  verified approval bound to the exact intent —
  this actor, this unit, this appointment — checked
  against a value computed under the resident's
  enrolled key, achieves the legitimate purpose
  (maintenance enters exactly when the resident
  agreed it may) with no stored field whose mere
  presence performs consent. Remove
  default-as-consent and the class does not happen.

Stop/continue decision: CONTINUE in the governed
kernel path only.

## 5. Boundary the evidence does not prove

The scenario models artifacts presented at a
governed entry boundary. It proves nothing about any
real portal, property-management system, intercom or
lock hardware, or the known instance of the class,
and it reproduces no part of any real entry — the
portal-record string is an inert stand-in that opens
nothing, and the verifier double is a test-local
model faithful only in the property the scenario
names (verification that accepts the record itself).
Pulpo's claim here is only about the gate it sits on:
had the actor reached an entry boundary routing its
consequential acts through this kernel, the record,
the garbage string, the portal's self-attestation,
and the stretched or carried-over grants would each
have failed closed, for the reasons the steps record.
The replay does not speak to the parts of the class
outside the gate: the interface design that produced
the default, the dispatch decision that relied on
it, or any entry that may have occurred in the real
instance. And it proves nothing about non-governed
paths: a door that opens on a stored default is
governed by nothing here — a control not on the
execution path governs nothing.

One surfacing boundary, stated plainly rather than
smoothed over (Verified at this commit, by
executable probe, by the channel's derivation
source, and by step 6's pinned counts): a bare
`evaluate` that returns `require_approval` — the
kernel declining to mint a permit without approval —
appends a decision record to the canonical audit,
where it is complete and chain-verified, but the
incident channel does NOT derive a near-miss record
from it; the channel derives near-misses from
`permit_rejected`, `approval_rejected`, denied
decisions, and `directive_denial`. The act is still
stopped — no permit exists to spend — so this is a
derivation-coverage boundary in the owner-facing
channel, not an authorization gap (issue #375).
Whether a `require_approval` decision should also
surface as a near-miss is a design question for the
channel's maintainers; this replay records the
behavior exactly as it stands and takes no position
by silently engineering around it.

## 6. Claim classification

- The failure class (a resident-services portal
  recording `permission_to_enter = Yes` from a
  user-interface default, with no decline path in
  the filing flow while the same system records "No"
  on other orders, and no affirmative consent act by
  the resident): **Recorded** (a real instance known
  to the authors; identifying details withheld by
  design — this change models the class, not the
  instance).
- Whether any entry was attempted or effected on
  the strength of the record in the known instance:
  **Unknown** (not established; the replay takes no
  position on it).
- The intent of the flow's designers (design
  shortcut vs. deliberate practice): **Unknown** —
  the replay grades the mechanism, not the intent.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree
  head commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 6).
- The step-5 migration refusal shapes (the
  carried-over record's `permit_signature_invalid`;
  the carried-over genuine permit's refusal recorded
  with no signature-failure reason, a state-row
  absence): **Verified** (executable probe at the
  base commit, pinned by step 5's assertions).
- The step-7 reconciliation semantics (test-level,
  against the public audit read path; the shipped
  reconcilers' actual scopes as described in §4):
  **Verified** (the construction and its results are
  executable at this head; the shipped APIs' scopes
  are read from their source at the base commit).
- The mapping from the class's pattern to kernel
  artifacts (physical entry modeled as the
  consequential act; the portal record modeled in
  its four positions — presented permit, presented
  approval signature, portal-key self-attestation,
  accepted record under the double; the resident's
  appointment approval modeled as the one authorized
  act): **Inferred** — the harness's modeling
  choices, stated in the module docstring.
- Any claim that this prevents the class in a
  deployed system: **Proposed** — not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no
legacy control path was copied. Structure, helpers,
and assertion style mirror the canonical scenario
modules merged in PRs #346 and #362–#388 and built
in PRs #396–#400, including their per-module
helper-duplication pattern, the test-level
reconciliation construction of the gainsight /
filename-deception / Mythos / hexpm scenarios, and
the negative-control double construction of PR #396.

## 8. Temporal-transfer evidence

Executed 2026-11-24. The applicable historical
checkpoint is this branch's exact base, `9aca02e`:
the bindings and verification checks the scenario
exercises (exact-intent binding, session binding,
approval expiry, single-use consumption, token
authentication at consume, the consume state-row
re-check, approval verification with an exact-`True`
verdict, the approval-envelope structural checks)
all predate this change, so the checkpoint
comparison AGENTS.md requires was runnable and has
been run.

Method: a clean worktree was reconstructed at
exactly `9aca02e` (no tree rewriting; `git status`
verified the only delta from the checkpoint was the
copied scenario module). The scenario was run there
under the canonical command, then the full suite.
Baseline at `9aca02e` without the lesson in this
environment is 1106 OK (skipped=25), verified by
direct execution at the pristine checkpoint; the
branch adds no kernel code, so any behavioral
difference at the checkpoint would have been a
finding, not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 9 scenario tests pass identically
  at `9aca02e` — the positive control executing
  exactly once, the no-artifact and unlisted-act
  denials, the record's consume refusals, the
  record / garbage / portal-key / missing-signature
  denials, the genuine grant's refusal to stretch
  across session, intent, and expiry, the migration
  carryover refusals in both shapes alongside the
  migrated system's own working genuine flow, the
  incident channel's 0 incidents / 8 near-misses,
  the step-7 reconciliation reconciling the honest
  claim and failing the portal's claim and the quiet
  claim by name, and the negative control executing
  under the record-trusting double. Full suite at
  checkpoint-plus-lesson: 1115 OK (skipped=25),
  identical to the worktree head; the delta over the
  1106 baseline is exactly the 9 scenario tests.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the
  checkpoint or at the head, and consequential
  authority is unchanged by the replay itself
  (`authority_effect=none` at both states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not
  smoothed: the §5 bare-evaluate near-miss gap
  (issue #375) is a property of the base-era incident
  projection, present at `9aca02e` exactly as at the
  head — the replay neither introduces nor widens
  it.

The evidence is therefore valid at the checkpoint
and at the worktree head; reuse of the lesson at a
later commit still requires re-evaluation there.

# Change record — Incident replay: Radware Cloud WAF management API exposure (unauthorized access 2026-11-19; disclosed 2026-11-24)

Base: `origin/main` at `9aca02e` (incident replay:
WP connect WordPress plugins supply-chain backdoor,
PR #388).
Authority: the standing incident scan surfaced the
incident in its 2026-11-24 run; Austin approved this
build on 2026-11-24 ("build both"). Test-only change:
one scenario module plus this record. No production
code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from BleepingComputer's
2026-11-24 reporting of Radware's root cause
analysis, which reached BleepingComputer from an
anonymous source; Radware had issued no public
statement and no SEC filing as of that reporting):
"On 19 November 2026, an unauthorized party accessed
an internal-only Cloud WAF management API that was
reachable from the Public Internet without requiring
authentication." The confirmed information
potentially accessed includes customer contact
details and, for a subset of customers, the
credentials configured for log export into their
self-managed storage (AWS S3, Azure Blob Storage, or
SFTP). Per the root cause analysis as reported,
Radware blocked the originating IP address and
access to the internal management API and revoked
and replaced all internal account credentials after
detecting the breach, ten hours after the initial
unauthorized API access. Radware said the breach
did not expose WAF traffic inspection, certificates,
end-users' data, customer application traffic, or
cloud DDoS services and data, and that it had found
no evidence of changes to customer security policies
or of access to customer application traffic.
Affected AppSec (WAF, BOT) customers were advised to
rotate Cloud WAF log-export credentials (Azure Blob
Storage keys or SAS tokens, AWS S3 access keys, or
SFTP credentials) as soon as possible and to review
access logs on their cloud storage accounts for
unexpected access since at least November 19;
Radware had already received reports from customers
about AWS alerts for an unfamiliar IP address
attempting to access their log-export buckets. The
company was still investigating whether any exposed
API keys or other customer information were used
without authorization.

Failure addressed: **a network position is not a
permit.** There was no authorization step to bypass:
the management API's access control was its presumed
network position. The API was "internal-only" by
intention and reachable from the public internet in
fact, and a request that arrived was executed
because of where the API was supposed to sit --
there was no authentication to defeat and no per-act
authorization to check. The governing invariants
are the fail-closed rule of AGENTS.md (unknown,
malformed, untrusted, expired, replayed, or
unavailable authority fails closed through the
canonical kernel) and the exact-intent binding
itself: under the kernel, the consequential act
requires a permit bound to the exact intent hash --
principal, action, resource, cost, session -- issued
only after a verified approval. Reachability
evidence (the request arrived; it arrived over the
internal path) is context bound into the intent as
session identity; it is never the authorization for
the act.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds
a test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately
unguarded doubles (`_IntentBlindState`,
`_UnguardedConsumeKernel`) exist solely as the
negative control, are test-local, and are never
imported by runtime code -- the same pattern as
PRs #346 and #362-#388.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`,
audit read, and incident-channel derivation paths,
and adds no writer, route, ledger, executor, or
state backend. The scenario's `ManagementApiExecutor`
is a test harness: it records a consequence only
after a successful kernel consume and holds no
canonical state. The incident-channel freeze is
asserted read-only in the scenario itself (audit
length unchanged across the freeze). Audit growth
is classified in the module docstring per AGENTS.md
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
`tests/test_radware_incident_scenario.py`
(8 tests, all passing at the worktree head):

- positive control: the one authorized act (an
  operator's credential export from the management
  plane) executes exactly once under a genuine,
  well-formed verified approval envelope; replay of
  the spent permit is denied; the audit chain
  verifies.
- step 1: with no permit at all, `evaluate` returns
  `require_approval` with no permit minted; the
  attempt is still presented for dispatch and the
  kernel itself refuses it at consume -- the
  executor presents the never-issued
  `NO_PERMIT_TOKEN` for the absent permit, and the
  refusal is recorded as a `permit_rejected`
  (`permit_signature_invalid`) bound to the
  export's intent hash; and the presumed-internal
  channel itself, presented as the permit, is
  rejected at consume the same way, as a fabricated
  token. Arrival over the trusted path is not an
  approval -- the incident's route (a), closed.
  (The no-permit routing is the post-review fix in
  section 9.)
- step 2: a genuine permit to read the configuration
  of the same resource spends on the credential
  export not at all (exact-intent binding, action
  half of the incident's route (b)); the denial is
  scope, not lockout -- the permit still spends on
  the read it names.
- step 3: a genuine permit to export a different
  resource on the same plane (the customer contact
  details -- the incident's other confirmed
  disclosure) spends on the credential export not
  at all (resource half of route (b)); the permit
  still spends on the resource it names.
- step 4: an exact permit for the export authorizes
  exactly one export (route (c), the only executing
  path); the spent permit re-presented for the same
  export and re-aimed at the configuration read is
  rejected both times.
- step 5: an approval envelope for the export
  signed with an unauthorized key is denied
  (`approval_signature_invalid`), and the genuine
  envelope for the configuration read presented for
  the export intent is denied
  (`approval_intent_mismatch`); the genuine pair
  still admits afterward.
- step 6: the incident channel sees the attempts --
  freezing a report over the full attempt sequence
  of steps 1-5 (the no-permit evaluation and its
  consume presentation, the channel token, the
  different-action permit, the
  different-resource permit, both approval-envelope
  attempts, the one legitimate export, and the
  spent-permit replays) yields zero incidents and
  exactly the near-miss records the channel's
  derivation produces from the audit: 6
  `permit_rejected`, 2 `approval_rejected`, and 2
  denied `decision` records (10 near-misses in
  total), each classified Recorded under a valid
  audit chain; the freeze appends nothing. The step
  also pins the surfacing boundary stated in
  section 5: the sequence's 1 `require_approval`
  decision is present in the audit and contributes
  zero near-miss records. The counts are from the
  executed run at this head, not estimates.
- negative control: with consume unguarded at both
  layers -- a kernel double whose consume skips
  token authentication and the token-to-intent
  binding, over a state double whose consume
  ignores the store's binding -- the credential
  export EXECUTES under a permit issued for a
  configuration read. That is the incident's own
  shape: a plane that performs what arrives because
  it arrived over the trusted path. The double in
  fact checks more than the incident's API did --
  it requires some issued, unspent permit, where
  the real API required no authentication at all --
  and the export still executes. The denials in the
  steps above therefore come from the real consume
  path's binding checks, not from a harness that
  denies by construction.

Full suite at the worktree head: **1114 tests, OK
(skipped=25)** in this environment -- the recorded
local baseline at the base commit `9aca02e` is 1106
OK (skipped=25); the delta is exactly the 8 scenario
tests. (The skipped=25 figure is this environment's
count; CI records its own environment's skipped
count with the same test total modulo
environment-specific discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip -- the incident is itself a flip: the
  protective property (internal-only reachability)
  inverted into the exposure, and the absence of a
  check became the check passing. On the governed
  path, flipping the presenter (operator vs.
  unauthenticated peer) changes nothing without the
  enrolled key, and flipping the route (no permit,
  channel token, wrong-action permit, wrong-resource
  permit) produces the same denial at distinct
  checks (steps 1-3).
- Reverse -- the consequence requires a consumed
  permit; the permit requires a verified approval;
  the approval binds the exact intent hash. The
  earliest unreachable point is the approval itself,
  and the chain does not collapse to one control:
  the channel token (step 1), the action mismatch
  (step 2), the resource mismatch (step 3), the
  forged key (step 5a), and the mismatched intent
  (step 5b) are each stopped at a distinct check,
  and the spent permit cannot be replayed (steps 4
  and 6).
- Invert -- outcome is not legitimacy: the
  incident's reads were "successful" API responses
  and wholly illegitimate; the governed record
  supports credit only for consumed acts under
  verified approvals, so any claim that a
  channel-delivered read was authorized is
  unsupportable against the audit and visible as
  such in the incident channel (step 6).
- Inside-Out -- the governor cannot originate the
  authority it enforces: the approval verifier
  holds only verification; the channel, the API
  service, and the session identity can each produce
  requests but none can produce an approval envelope
  or ceremony evidence; the test verifiers and
  doubles are test-only; the orchestrator surface
  used for the incident report is read-only and its
  freeze is asserted to append nothing (step 6).
- Darken -- worst credible bounded case: the
  exposure window ran at least ten hours before
  detection (per the root cause analysis as
  reported), the read side of a management plane is
  the whole plane's credential store, and the
  disclosed keys are live in customers' own cloud
  accounts until each customer rotates them -- some
  customers had already seen an unfamiliar IP
  probing their log-export buckets. Inside the
  governed path the maximum consequence per approval
  remains the one authorized act; every unauthorized
  attempt produces audit records only -- one per
  attempt on the bare-evaluate and consume routes,
  two (an `approval_rejected` record and a denied
  decision record) on the denied approval-envelope
  route -- and zero consequences. Outside the
  governed path stands the incident's real worst
  case -- a management plane with no authorization
  layer at all -- and this replay does not mitigate
  it; it is the boundary in section 5.
- Lighten -- minimum benign interpretation:
  internal-only management APIs are a normal,
  intentional architecture -- segmentation is a real
  control, and nothing in this record claims Radware
  acted in bad faith; a routing or exposure error
  made one layer carry a weight it cannot carry
  alone. The governed path preserves the distinction
  exactly: reachability stays in the record as
  session context, and the positive control shows
  the real route for a real approval.
- Amplify -- an unauthenticated management API is
  scriptable at internet scale for the whole
  exposure window: every customer, every configured
  credential, enumerable by a single scanner.
  Approvals are per-intent and permits single-use,
  so replication multiplies attempts, never
  authority. Denial volume produces audit growth
  only, bounded per attempt.
- Negate -- the smallest clean path: the dispatch
  boundary must require a permit bound to the exact
  act, issued from a verified approval, before it
  performs anything. Network position, channel
  trust, and session establishment are none of them
  necessary as authorization -- remove the reliance
  on any one as the access control and the incident
  does not happen.

Stop/continue decision: CONTINUE in the governed
kernel path only.

## 5. Boundary the evidence does not prove

The scenario models requests presented for
authorization at a governed kernel boundary. It
proves nothing about Radware's deployed systems,
its actual API, or any management plane that does
not route its dispatch through this kernel, and it
reproduces no part of the exposed API and none of
the incident's access: no network behavior is
modeled, and no credential value exists anywhere in
the scenario -- the export is identified by the
resource whose material it would read out.

Two further limits, stated plainly. First,
reachability: the replay governs the act at the
dispatch boundary; it does not model or repair how
the API came to be reachable from the public
internet. A governed API that is unintentionally
reachable still denies unauthenticated acts, and an
ungoverned API that is unreachable is merely lucky;
this evidence speaks only to the authorization half
of that pair, and segmentation remains a separate,
necessary control. Second, irreversibility: once
credential material has left the plane, no permit
system recalls it -- the downstream use of the
exposed keys against customers' own AWS, Azure, and
SFTP storage is outside this boundary, and the
incident's actual remedy (rotation, advised by
Radware) is incident response, not authorization.
The replay governs the export before it happens,
not the exposure afterward. It also does not speak
to the contact-details disclosure beyond modeling
it as the different-resource act in step 3, nor to
whether any exposed material was in fact used --
which Radware was still investigating as of the
disclosure.

One surfacing boundary, stated plainly rather than
smoothed over (Verified at this commit, by
executable probe, by the channel's derivation
source, and by step 6's pinned counts): a bare
`evaluate` that returns `require_approval` -- the
kernel declining to mint a permit without approval
-- appends a decision record to the canonical
audit, where it is complete and chain-verified, but
the incident channel does NOT derive a near-miss
record from it; the channel derives near-misses
from `permit_rejected`, `approval_rejected`, denied
decisions, and `directive_denial`. The act is still
stopped -- no permit exists to spend -- so this is
a derivation-coverage boundary in the owner-facing
channel, not an authorization gap (issue #375).
Whether a `require_approval` decision should also
surface as a near-miss is a design question for the
channel's maintainers; this replay records the
behavior exactly as it stands and takes no position
by silently engineering around it.

## 6. Claim classification

- Incident narrative: **Recorded** (BleepingComputer's
  2026-11-24 reporting of Radware's root cause
  analysis: the 2026-11-19 unauthorized access date,
  the internal-only API reachable from the public
  internet without authentication, the categories of
  information potentially accessed, the ten-hour
  detection figure, the credential revocation, the
  rotation advice, and the customer-reported AWS
  alerts. The root cause analysis reached
  BleepingComputer from an anonymous source and
  Radware had issued no public statement or SEC
  filing as of the reporting; no figure in the
  narrative is independently re-derived here).
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree
  head commit).
- The incident-channel surfacing boundary in
  section 5: **Verified** (executable probe plus
  the channel's derivation source at the base
  commit, pinned by step 6).
- The mapping from the incident's pattern to kernel
  artifacts (the credential export modeled as the
  consequential act; the configuration read and the
  contact-details export modeled as the
  different-action and different-resource acts; the
  presumed-internal channel modeled as session
  context and, in step 1, as a presented token):
  **Inferred** -- the harness's modeling choices,
  stated in the module docstring.
- Any claim that this prevents the incident class
  in a deployed system: **Proposed** -- not made by
  this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no
legacy control path was copied. Structure, helpers,
and assertion style mirror the canonical scenario
modules merged in PRs #346-#350, #362-#368,
#374-#382, and #386-#388, including their
per-module helper-duplication pattern, the
reporting-coverage construction of PR #378's step 6
as amended, and the negative-control double
construction of PRs #386 and #391.

## 8. Temporal-transfer evidence

Executed 2026-11-24. The applicable historical
checkpoint is this branch's exact base, `9aca02e`:
the bindings and verification checks the scenario
exercises (exact-intent binding across action and
resource, single-use consumption, approval
verification, the approval-envelope structural
checks) all predate this change, so the checkpoint
comparison AGENTS.md requires was runnable and has
been run.

Method: a clean worktree was reconstructed at
exactly `9aca02e` (no tree rewriting; `git status`
verified the only delta from the checkpoint was the
copied scenario module). The scenario was run there
under the canonical command, then the full suite.
Baseline at `9aca02e` without the lesson in this
environment is 1106 OK (skipped=25); the branch
adds no kernel code, so any behavioral difference
at the checkpoint would have been a finding, not an
expectation.

Results (Verified -- executed at both states):

- TRANSFERS: all 8 scenario tests pass identically
  at `9aca02e` -- the positive control executing
  exactly once, the no-permit and channel-token
  denials, the different-action and
  different-resource permit denials, the
  exact-permit single execution and spent-permit
  replays, the forged/mismatched approval denials,
  the incident channel's 0 incidents / 10
  near-misses, and the negative control executing
  under the unguarded-consume doubles. Full suite
  at checkpoint-plus-lesson: 1114 OK (skipped=25),
  identical to the worktree head; the delta over
  the 1106 baseline is exactly the 8 scenario
  tests.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the
  checkpoint or at the head, and consequential
  authority is unchanged by the replay itself
  (`authority_effect=none` at both states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not
  smoothed: the section 5 bare-evaluate near-miss
  gap (issue #375) is a property of the base-era
  incident projection, present at `9aca02e` exactly
  as at the head -- the replay neither introduces
  nor widens it.

The evidence is therefore valid at the checkpoint
and at the worktree head; reuse of the lesson at a
later commit still requires re-evaluation there.

## 9. Post-review fix (Codex P2 on PR #394)

After the original head `fc2055c` was reported,
Codex review (2026-11-24) raised a P2 on
`tests/test_radware_incident_scenario.py`: "Route
absent permits through the kernel." In step 1 the
unauthenticated-input case produced `permit=None`
from `evaluate`, and the scenario's executor
returned `False` on `permit is None` before
`GovernanceKernel.consume` ran -- so the claimed
fail-closed result for the central case was
enforced by the test harness rather than verified
through the canonical kernel. The negative control
could not catch it, because it supplies a genuine
issued read permit: the scenario could keep passing
without demonstrating kernel rejection of
unavailable authority.

Fix (approved by Austin 2026-11-24; the same
construction as the Chevrolet scenario's
`NO_PERMIT_TOKEN` and the WPpConnect scenario's
sentinel presentation, the latter itself a Codex
P2 fix on its PR):

- The executor no longer returns early on
  `permit=None`. Every attempt is presented to
  `GovernanceKernel.consume`; for an absent permit
  the executor presents `NO_PERMIT_TOKEN` (the
  empty string -- issued permits are
  `<intent-hash>:<nonce>:<signature>` and are never
  empty), a never-issued sentinel with no state row
  behind it. The kernel refuses it at consume and
  writes the `permit_rejected` record itself
  (reason `permit_signature_invalid`).
- Step 1 now asserts both kernel refusals -- the
  never-issued token and the channel token -- each
  bound to the export's intent hash with reason
  `permit_signature_invalid`.
- Step 6's frozen sequence now includes the
  no-permit dispatch presentation, as step 1
  exercises it. The near-miss accounting therefore
  changes: 6 `permit_rejected` (was 5), 2
  `approval_rejected`, 2 denied decisions -- 10
  near-misses (was 9), 0 incidents. The bare
  `require_approval` decision still contributes
  zero near-miss records; the section 5 surfacing
  boundary (issue #375) is unchanged -- what
  changed is that the dispatch attempt now reaches
  consume, whose rejection the channel does derive.
- No other case was weakened; the negative control
  is unchanged. No production code is touched;
  `authority_effect=none`.

Evidence (Verified -- executed 2026-11-24):
scenario 8/8 at the post-fix head; full suite 1114
OK (skipped=25) at the post-fix head. Temporal
replay re-run with the fixed module at the clean
base checkpoint `9aca02e` (worktree reconstructed
by exact SHA; the only delta was the copied
scenario module): scenario 8/8 and
checkpoint-plus-lesson full suite 1114 OK
(skipped=25) -- identical to the post-fix head, no
negative transfer. Sections 4 and 8 above state
the post-fix counts.

## 10. Second pass (2026-11-25): PR-body reconciliation and re-verification

The Codex P2 thread remained unresolved after the
section 9 fix (the reviewer resolves after
re-review; the fix author does not self-resolve).
A second pass over the live PR on 2026-11-25 found
the section 9 code fix in place at head `eb78304`
and re-verified it by execution in a fresh
worktree: scenario 8/8; full suite 1114 OK
(skipped=25) -- identical to the section 9
numbers.

One artifact still asserted the pre-fix evidence:
the PR body. It stated the incident-channel result
as "0 incidents, 9 near-misses (5
`permit_rejected`, ...)" -- the counts from before
the fix -- and its no-permit bullet did not state
that the dispatch attempt is presented to the
kernel with the never-issued sentinel and refused
by the kernel at consume. The scenario code and
this record (sections 4, 8, 9) already stated the
post-fix counts; the body did not.

This pass corrects the PR body explicitly (the
correction is noted in the body itself, not made
silently): the channel counts now read 10
near-misses (6 `permit_rejected`, 2
`approval_rejected`, 2 denied decisions), and the
no-permit bullet states the kernel routing. No
test or production code changes in this pass; no
claim is weakened -- the body's claims are brought
up to the evidence the code already produces.
`authority_effect=none`.

# Change record — Incident replay: Xen Orchestra VSA-2026-062 empty-object cookie admin sign-in (disclosed 2026-11-10; CVE-2026-133469 published 2026-11-23)

Base: `origin/main` at `9aca02e` (incident replay:
WP connect WordPress plugins supply-chain backdoor,
PR #388).
Authority: the standing incident scan surfaced the
incident in its 2026-11-24 evening run (a catch-up
find; Vates disclosed 2026-11-10); Austin approved
building all five replays on 2026-11-24. Test-only
change: one scenario module plus this record. No
production code is touched.

## 1. Invariant or failure addressed

Incident (Verified, from Vates advisory VSA-2026-062
and CVE-2026-133469, CVSS 9.8; reported at
https://thehackernews.com/2026/11/hackers-exploit-critical-xen-orchestra.html):
a REST cookie-parsing flaw in Xen Orchestra let an
unauthenticated attacker send
`authenticationToken=j:{}` — the value decoded to an
EMPTY OBJECT, which was passed to the token provider
as an unfiltered lookup that returned the FIRST STORED
TOKEN — and sign in as admin with no password. Vates
confirmed active exploitation (an attacker IP and a
Tor domain observed; a pivot VM; persistence files)
and that the same actor chained VSA-2026-063 (a
VM-import authorization flaw) to compromise XCP-ng
hosts as root. A successful bypass leaves NO log
entry. No victim is named and the scale of exploitation
is undisclosed.

Failure addressed: **a malformed credential that
decodes to nothing is not an authenticated identity.**
`A_MALFORMED_CREDENTIAL_THAT_DECODES !=
AN_AUTHENTICATED_IDENTITY`. An empty object — the
absence of a credential — was resolved by an
unfiltered lookup into the first real credential in
the store, so absence became the strongest credential
available: it worked for everything the first token's
owner could do, and it left no log entry because, to
the system, a legitimate admin had signed in. The
governing invariants are the fail-closed rule of
AGENTS.md (unknown, malformed, untrusted, expired,
replayed, or unavailable authority fails closed
through the canonical kernel) and exact-intent binding
itself: under the kernel, a consequential act requires
a permit issued only after an approval whose signature
verifies against the value computed from the payload
under the enrolled authority's key, bound to the exact
intent — principal, action, resource, cost, session —
and spent exactly once at consume, where the token is
itself authenticated and its state row re-checked. A
decoded empty object is none of those things on any
route: not a token the kernel issued (consume refuses
it), not a signature the authority made (evaluation
refuses it), and not a scope (a genuine approval for
one act refuses to stretch to another). And because
the real bypass left no logs, the replay's third
mechanism is reconciliation as the detection layer:
every attempt on the governed path appends audit
records, the chain verifies, and reconciliation proves
the consequence set is exactly the authorized set.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately vulnerable
double (`_UnfilteredLookupVerifier`) exists solely as
the negative control, is test-local, and is never
imported by runtime code — the same pattern as PRs
#346 and #362–#388.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, test-level reconciliation against the public
audit read path, and incident-channel derivation
paths, and adds no writer, route, ledger, executor, or
state backend. The scenario's `ConsoleExecutor` is a
test harness: it records a consequence only after a
successful kernel consume and holds no canonical
state. The reconciliation helper
(`reconcile_against_audit`) is likewise test-level,
implemented against the public `kernel.audit` read
path as in the gainsight and filename-deception
scenarios: the shipped reconcilers reconcile
filesystem effects and custody-domain outcomes, not a
claimed history against the kernel audit trail; this
helper adds no canonical writer. The incident-channel
freeze is asserted read-only in the scenario itself
(audit length unchanged across the freeze). Audit
growth is classified in the module docstring per
AGENTS.md (`NO_PERMIT != NO_GOVERNED_EFFECT`): each
denied attempt appends audit records — a governed
effect (evidence production), append-only, with
`authority_effect=none` and no capability
accumulation — assessed separately from governed
external consequences throughout. The count is per
route, not uniformly one: a bare `evaluate` returning
`require_approval` appends one decision record; a
denied `evaluate` appends one decision record; a
`consume` rejection appends one `permit_rejected`
record; a denied approval-envelope evaluation appends
two records — an `approval_rejected` record and a
denied decision record. Growth stays bounded per
attempt (at most two records), which is the invariant
the scenario pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_xen_orchestra_incident_scenario.py`
(7 tests, all passing at the worktree head):

- positive control: the one authorized act (an
  authorized administrator's bounded read of VM
  inventory) executes exactly once under a genuine,
  well-formed verified approval envelope; replay of
  the spent permit is denied; the audit chain
  verifies.
- step 1: with no credential at all, `evaluate` of the
  host act returns `require_approval` with no permit
  minted, and nothing executes — reachability of the
  console is not an approval. An act the console's
  policy does not contain (`purge_host`) is denied
  outright (`action_not_allowed`).
- step 2 (the incident's core): the empty-object token
  — the inert stand-in string `j:{}` — presented as a
  permit at consume is refused for both the host act
  and the legitimate inventory read
  (`permit_rejected`, reason `permit_signature_invalid`,
  bound to the exact intent hash each time). It was
  never issued: no state row stands behind it and no
  genuine token signature does either. Absence of a
  credential is not a weaker credential; it is refused
  at the same boundary.
- step 3: the empty-object token offered as an
  approval signature and an envelope signed with an
  unauthorized key are each denied
  (`approval_signature_invalid`); a literally empty
  signature is denied earlier and separately
  (`approval_signature_missing`).
- step 4: the genuine envelope for the inventory read
  presented for the host act is denied
  (`approval_intent_mismatch`), and the genuine issued
  permit presented against the host act at consume is
  refused (`permit_intent_mismatch`) — the "first
  stored token works for everything" move, refused by
  intent binding on both boundaries; the denials do
  not poison the path — the same permit then performs
  its own act exactly once.
- step 5 (reconciliation as witness): after the full
  sequence (the no-credential probe, the wrong-verb
  probe, the empty-object token spent as a permit, the
  empty-object token and an empty signature offered as
  approvals, the genuine envelope stretched to the
  host act, the genuine permit spent against the host
  act, the one legitimate execution, and the
  spent-permit replay), reconciliation of the claimed
  history against the audit shows the consequence set
  is exactly the authorized set: exactly one
  `permit_consumed` record (the inventory read), and
  the attempt set is exactly the three intent hashes
  the sequence touched. A claim reporting only the
  legitimate effect and silence about the attempts
  does NOT reconcile — reconciliation names the
  silence precisely (`undisclosed_attempts` = the full
  attempt set); a claim promoting the host act to a
  consequence is unbacked; a claim disclosing the
  attempts alongside exactly the one genuine
  consequence reconciles exactly. The executor's
  ledger and the audit agree (one effect, one consumed
  consequence): there is no unlogged consequence — the
  incident's "no log entry" outcome is impossible on
  this path because the effect exists only through the
  consume that writes the record. The incident channel
  over the same sequence yields zero incidents and
  exactly the near-miss records the channel's
  derivation produces from the audit: 3
  `permit_rejected`, 3 `approval_rejected`, and 4
  denied `decision` records (10 near-misses in total),
  each classified Recorded under a valid audit chain;
  the freeze appends nothing. The step also pins the
  surfacing boundary stated in §5: the sequence's 1
  `require_approval` decision is present in the audit
  and contributes zero near-miss records. The counts
  are from the executed run at this head, not
  estimates.
- negative control: with the verifier swapped for the
  incident's own shape — an unfiltered-lookup verifier
  whose store holds the GENUINE permit issued for the
  inventory read (the first stored token) — an
  envelope for the HOST act whose "signature" is the
  empty object itself, `j:{}` (the incident's exact
  input; the attacker never possesses the stored
  token's value), VERIFIES: the double's modeled
  provider lookup resolves the empty object to the
  first stored token (asserted directly in the test),
  a permit mints, and the host act EXECUTES. Under
  the same double, a random string is denied
  (`approval_signature_invalid` — it resolves through
  the lookup to itself and matches no stored token)
  and an empty string is denied
  (`approval_signature_missing`): the lookup is the
  whole check. Contrast: the identical attack
  envelope against the governed kernel is denied
  (`approval_signature_invalid`) — the stored permit
  is not a signature over this envelope's payload.
  The denials in the steps above therefore come from
  the governed verification's shape (a computed
  expected signature under the enrolled key, bound to
  the exact intent), not from a harness that denies
  by construction. (At the original head the control
  presented the stored token's value directly and the
  lookup step was not modeled; the §10 fix pass
  corrects that.)

Full suite at the worktree head: **1113 tests, OK
(skipped=25)** in this environment — the recorded local
baseline at the base commit `9aca02e` is 1106 OK
(skipped=25); the delta is exactly the 7 scenario
tests. (The skipped=25 figure is this environment's
count; CI records its own environment's skipped count
with the same test total modulo environment-specific
discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — the incident is itself a flip of the
  credential direction: the weakest possible input (a
  value that decodes to an empty object, the absence
  of a credential) became the strongest credential in
  the system, because the lookup inverted "no match"
  into "first match." No control on the governed path
  has a lookup to flip: the empty-object token fails
  at consume (step 2) and at approval verification
  (step 3), an empty signature fails earlier still
  (step 3), and flipping the presenter changes nothing
  without the enrolled key.
- Reverse — the consequence (a host-level
  administrative act) requires a consumed permit; the
  permit requires a verified approval; the approval
  requires a signature computed from the payload under
  the enrolled key by an accountable approver, bound
  to the exact intent. The earliest point at which the
  consequence becomes unreachable is the credential
  itself, and the chain does not collapse to one
  control: the empty-object token fails at token
  authentication at consume (step 2) and at signature
  verification at evaluate (step 3), the forged
  artifact fails at verification (step 3), the genuine
  article fails to stretch at intent binding on both
  boundaries (step 4), and the spent permit cannot be
  replayed (positive control, step 5).
- Invert — outcome is not legitimacy: inside the
  incident, the attacker's "success" (an admin session)
  was an outcome-success and a legitimacy failure
  throughout — nobody had authenticated or authorized
  anything, and the system's own record could not show
  the difference, because the bypass left no log entry.
  The governed record supports credit only for consumed
  acts under verified approvals, and step 5's
  reconciliation makes the distinction checkable after
  the fact: a consequence with no approval behind it
  would stand in the record as unbacked, and an attempt
  omitted from a claimed history stands as undisclosed.
  The negative control produces exactly the incident's
  shape — a consequence whose only backing is a lookup
  — under the double rather than the kernel.
- Inside-Out — the governor cannot originate the
  authority it enforces: the approval verifier holds
  only verification; a decoded empty object cannot
  produce an approval envelope or ceremony evidence at
  all; the test double is test-only; the orchestrator
  surface used for the incident report is read-only
  and its freeze is asserted to append nothing
  (step 5); reconciliation reads the audit and writes
  nothing.
- Darken — worst credible bounded case (a threat case,
  not a claim): the bypass is unauthenticated, remote,
  and rated CVSS 9.8; Vates confirmed active
  exploitation, and the same actor chained a second
  flaw to root compromise of the underlying hosts, with
  persistence. Had the console's dispatch boundary
  been the only flaw and its verification
  lookup-shaped, one cookie reads as full admin with
  no log entry to detect it by. Inside the governed
  path the maximum consequence per approval remains
  the one authorized act; every unauthorized attempt
  produces audit records only — one per attempt on the
  bare-evaluate and consume routes, two (an
  `approval_rejected` record and a denied decision
  record) on the denied approval-envelope route — and
  zero consequences, and step 5 proves the record is
  complete enough to reconcile exactly. Outside the
  governed path stands the incident's real worst case
  — consoles whose token provider answers an empty
  object with the first stored token — and this replay
  does not mitigate it; it is the boundary in §5.
- Lighten — minimum benign interpretation: no victim
  is named, the scale of exploitation is undisclosed,
  and the confirmed exploitation Vates describes is
  one actor's observed activity (an IP, a Tor domain,
  a pivot VM, persistence files), not a measured
  population of compromised deployments. The replay
  grades the mechanism — an unfiltered lookup treating
  a decoded absence as a credential — not the actor,
  and claims no harm beyond what the advisory records.
- Amplify — the bypass costs one cookie header and is
  free to replicate against every exposed console, in
  parallel, and each success is silent. Approvals are
  per-intent and permits single-use, so replication
  multiplies attempts, never authority; denial volume
  produces audit growth only, bounded per attempt —
  and, unlike the incident, the attempts themselves
  are the detection signal, witnessed and reconcilable
  (step 5).
- Negate — the smallest clean path: a token provider
  needs no unfiltered lookup at all. An exact-match
  verification — a signature computed under the
  enrolled key, bound to the exact intent, checked
  against the presented value and nothing else —
  achieves the legitimate purpose (administrators sign
  in and act within their approvals) with no code path
  in which an empty or malformed value can resolve to
  someone else's credential. Remove the unfiltered
  lookup and the incident class does not happen.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models credentials and approval artifacts
presented at a governed console dispatch boundary. It
proves nothing about Xen Orchestra, its cookie
parsing, its token provider, or any deployed XCP-ng
host, and it reproduces no part of the real bypass —
the `j:{}` string is an inert stand-in, and the
verifier double is a test-local model faithful only in
the property the scenario names (verification by
comparison against a stored token, where the stored
token is the genuine first token). Pulpo's claim here
is only about the gate it sits on: had the attacker
reached a console routing its consequential acts
through this kernel, the empty-object token, the
forged artifacts, and the stretched permit would each
have failed closed, for the reasons the steps record,
and every attempt would have been witnessed and
reconcilable. The replay also does not speak to the
parts of the incident outside the gate: the
VSA-2026-063 VM-import flaw itself (modeled only as
the host act it enabled, not reproduced), the pivot
VM, or the persistence mechanisms. And it proves
nothing about non-governed paths: a console whose
token lookup resolves an empty object to the first
stored token is governed by nothing here — a control
not on the execution path governs nothing. Whether any
given production console's token provider is
lookup-shaped is an audit question for that console;
this scenario pins only that the canonical kernel's
shape gives a malformed credential nothing to act
with, and that its audit is complete enough for
reconciliation to prove it.

One surfacing boundary, stated plainly rather than
smoothed over (Verified at this commit, by executable
probe, by the channel's derivation source, and by
step 5's pinned counts): a bare `evaluate` that returns
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
engineering around it. Note the asymmetry this creates
against the incident: reconciliation (step 5) DOES
witness the `require_approval` attempt — it is in the
attempt set the honest claim must disclose — so the
detection layer this replay claims is reconciliation
against the full audit, with the channel's narrower
derivation pinned alongside it, not conflated with it.

## 6. Claim classification

- Incident narrative: **Verified** (Vates advisory
  VSA-2026-062, disclosed 2026-11-10, and
  CVE-2026-133469, published 2026-11-23, CVSS 9.8: the
  REST cookie-parsing flaw, the `authenticationToken`
  value decoding to an empty object, the unfiltered
  lookup returning the first stored token, admin
  sign-in with no password, and the absence of a log
  entry on a successful bypass).
- Active exploitation: **Verified** (Vates-confirmed:
  an attacker IP and a Tor domain observed, a pivot
  VM, persistence files, and the same actor's chaining
  of VSA-2026-063 to compromise XCP-ng hosts as root).
- The victim's identity: **Unknown** (none named).
- The scale of exploitation: **Unknown** (undisclosed).
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 5).
- The mapping from the incident's pattern to kernel
  artifacts (the host act modeled as the consequential
  act; the empty-object token modeled in its three
  positions — presented permit, presented approval
  signature, and, via the genuine permit it would have
  resolved to, stored credential; the inventory read
  modeled as the one legitimate act): **Inferred** —
  the harness's modeling choices, stated in the module
  docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346 and #362–#388, including their
per-module helper-duplication pattern, the
test-level reconciliation construction of the
gainsight and filename-deception scenarios, and the
negative-control double construction of PR #386.

## 8. Temporal-transfer evidence

Executed 2026-11-24. The applicable historical
checkpoint is this branch's exact base, `9aca02e`: the
bindings and verification checks the scenario exercises
(exact-intent binding, single-use consumption, token
authentication at consume, approval verification with an
exact-`True` verdict, the approval-envelope structural
checks) all predate this change, so the checkpoint
comparison AGENTS.md requires was runnable and has been
run.

Method: a clean worktree was reconstructed at exactly
`9aca02e` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module). The scenario was run there under the canonical
command, then the full suite. Baseline at `9aca02e`
without the lesson in this environment is 1106 OK
(skipped=25); the branch adds no kernel code, so any
behavioral difference at the checkpoint would have been
a finding, not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 7 scenario tests pass identically at
  `9aca02e` — the positive control executing exactly
  once, the no-credential and wrong-verb denials, the
  empty-object consume refusals, the empty-object /
  forged / missing-signature approval denials, the
  genuine article's refusal to stretch on both
  boundaries, step 5's exact reconciliation and the
  incident channel's 0 incidents / 10 near-misses, and
  the negative control executing under the
  unfiltered-lookup double. Full suite at
  checkpoint-plus-lesson: 1113 OK (skipped=25),
  identical to the worktree head; the delta over the
  1106 baseline is exactly the 7 scenario tests.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not
  smoothed: the §5 bare-evaluate near-miss gap (issue
  #375) is a property of the base-era incident
  projection, present at `9aca02e` exactly as at the
  head — the replay neither introduces nor widens it.
  Step 5's reconciliation, by contrast, witnesses that
  same attempt at both states, which is the detection
  claim the replay actually makes.

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.

## 9. Fix pass — 2026-11-25 (Codex review of PR #397; multiplicity pass)

Review finding (Codex, P1, on
`tests/test_xen_orchestra_incident_scenario.py`):
the reconciliation helper collapses repeated attempts
into unique intent hashes. The step-5 reconciliation
derived **sets** of intent hashes from the audit and
converted the claimed values to sets as well, collapsing
every occurrence of a hash to one. A claimed history
listing a hash once therefore reconciled successfully
even when the audit held further attempts — or further
executions under separately issued permits — for that
same hash: the claim could underreport repeated activity
while returning `ok=True`. The finding is correct. It
was reproduced before the fix at head `3633b4b`: three
empty-object-token attempts on the target intent and two
legitimate inventory reads under separate permits (audit
truth: attempts {target: 3}, consequences {legit: 2})
reconciled `ok=True` under a claim listing each hash
once. Step 5's own sequence already held the proof in
embryo: its target intent is attempted six times under
one hash, and the presence-only comparison could not see
any of the six as more than one.

Change (test module only; no production code, no claim
narrowed — the reconciliation claim is strengthened, and
the prior presence-only limitation is recorded here
rather than smoothed over):

- `audited_sets` is replaced by `audited_counts`: the
  audit side now yields occurrence counts (multisets) per
  intent hash for consequences and attempts alike.
- `reconcile_against_audit` counts the claim's lists the
  same way (a hash listed twice claims two occurrences)
  and flags a hash in each direction whenever the counts
  diverge: underreported attempts are
  `undisclosed_attempts`, underreported executions are
  `missing_consequences`, and overreported claims are
  `phantom_attempts` / `unbacked_consequences`. `ok`
  requires exact count equality for every hash, on top of
  the unchanged fail-closed audit-chain verification.
- Step 5's assertions were updated to the count form
  without weakening — and strengthened in one place: the
  sequence's attempt counts are now asserted exactly
  (target 6, unknown 1, legit 1) instead of as a mere
  presence set, and its honest and inflated claims now
  carry the attempts at full multiplicity.
- New step 5b pins the behavior: the empty-object token
  presented three times (3 rejections, one hash) and the
  legitimate inventory read executed twice under two
  separately issued permits (2 consumptions, one hash).
  A claim collapsing each hash to a single listing fails
  on exactly the two underreported hashes; the same
  history with multiplicity reported honestly reconciles
  exactly; overreporting fails in each direction on its
  own hash.

Evidence (Verified, executed at the fix-pass head):

- Scenario: **8/8 pass** (was 7/7 at head `3633b4b`;
  the delta is exactly step 5b). The pre-fix reproduction
  now fails reconciliation on exactly the two
  underreported hashes.
- Full suite at the fix-pass head: **1114 tests ran, OK
  (skipped=13)** in this environment; the pristine
  original head measured in the same environment at
  **1113 ran, OK (skipped=13)** — the delta is again
  exactly the new test. (Skip counts are
  environment-dependent; the +1 test delta is not.)
- Temporal replay of the fix, per §8's method: a clean
  worktree reconstructed at exactly `9aca02e` with the
  updated module copied in (the only delta) passes the
  scenario identically, 8/8; the full suite at
  checkpoint-plus-lesson is **1114 ran, OK (skipped=13)**,
  identical to the fix-pass head. The multiplicity
  comparison is a property of this branch's test-level
  helper over the public audit read path; no kernel
  behavior is exercised differently at the two states,
  and consequential authority is unchanged
  (`authority_effect=none`).

Out of scope, recorded not smoothed: this pass does not
touch the review's separate P1 on the negative control
(the modeled malformed-input lookup). That finding
stands as reported; it is a different defect class and
awaits its own pass.

## 10. Second fix pass — 2026-11-25 (Codex P1 on the negative control)

This is the pass §9 recorded as out of scope. Review
finding (Codex, P1, on
`tests/test_xen_orchestra_incident_scenario.py`): the
negative control replaced the attack envelope's
signature with the genuine permit itself, so the
vulnerable verifier never received the empty-object
token `j:{}` and never performed the
empty-object-to-first-token lookup; the passing test
showed only that an attacker already possessing the
stored token could use it, not that the incident's
unauthenticated `j:{}` input resolves to that token
and executes. The finding is correct.

Change (test module only; no production code):

- `_UnfilteredLookupVerifier` now models the
  provider step explicitly: a `lookup` method treats
  the presented value as a lookup key — the empty
  object is an empty filter, so the unfiltered
  lookup returns the FIRST stored token; any other
  value resolves to itself — and `verify` accepts
  whatever the lookup returns if it is a stored
  token. The store is now a token tuple
  (`stored_tokens`) in place of the single
  `stored_token` string.
- The negative control presents ONLY the empty
  object as the envelope signature — the incident's
  exact input; the attacker never possesses the
  stored token's value — and asserts the lookup
  resolution directly
  (`lookup(EMPTY_OBJECT_TOKEN) == genuine_permit`)
  before the envelope verifies, a permit mints, and
  the host act executes. The random-string denial
  now runs through the lookup (resolves to itself,
  matches nothing); the empty-string denial and the
  governed-kernel contrast are unchanged.
- §4's negative-control bullet and the module
  docstring are updated to the modeled construction.

Evidence (Verified, executed at this pass's head):
scenario **8/8 pass**; full suite **1114 tests, OK
(skipped=13)** in this environment — identical
totals to the §9 head (this pass changed test
internals, added no tests). The reconciliation P1
was already fixed in §9 (head `6e2e317`); both
threads are replied to on the PR and left open for
Codex re-review.

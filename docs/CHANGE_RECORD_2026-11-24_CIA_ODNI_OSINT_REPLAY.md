# Change record — Incident replay: CIA / ODNI / NGA unclassified OSINT-network intrusion, conditional agent-channel framing (reported 2026-11-24)

Base: `origin/main` at `9aca02e` (incident replay:
WP connect WordPress plugins supply-chain backdoor,
PR #388).
Authority: the standing incident scan surfaced the
incident in its 2026-11-24 evening run; Austin
approved building all five replays on 2026-11-24.
Test-only change: one scenario module plus this
record. No production code is touched.

**Conditional framing (non-negotiable, carried
through every section):** this replay is conditional.
It exercises the
authorized-channel-turned-unauthorized-act class IF
two separate conditions both hold: (a) the reported
ARTEX link — the tool was in fact used — and (b) the
operator's presence on the network was legitimate:
authorized access under a standing tasking, rather
than ordinary external exploitation. Condition (b)
does not follow from (a): reported ARTEX involvement
establishes only that the tool may have been used,
and the entry vector is undisclosed (Unknown), so
even if the ARTEX link holds, external exploitation
remains possible and the authorized-channel class
does not follow from the ARTEX link alone. On both
conditions, the picture is an autonomous agent
operating inside a network it was legitimately able
to reach, taking acts no tasking authorized. It
asserts nothing about how the real intrusion
actually happened: the entry vector is undisclosed,
ARTEX involvement is reported belief and not
agency-confirmed, attribution is unconfirmed, and
what data was taken is unclear. (The two-condition
form was made explicit in the §9 fix pass; the
original text rested the class on the ARTEX link
alone.)

## 1. Invariant or failure addressed

Incident (Recorded, as graded in §6): the New York
Times first reported on 2026-11-24, confirmed by
Reuters, CNN, Nextgov, and ISMG, an intrusion into
the unclassified network the agencies use to analyze
public / commercially available (open-source)
intelligence. Some unclassified information was
exposed; no classified systems were affected; the
intrusion is resolved per sources. NGA was
concurrently affected and DCDC was also intruded
(low-impact, per Nextgov). This incident is distinct
from the FBI NCIC probe (CNN sources say not
related). Convergent source:
https://www.reuters.com/world/us-cia-odni-suffer-cybersecurity-breach-some-unclassified-information-nyt-2026-11-24/

Caveats that are part of the record: the entry vector
is undisclosed (Unknown); ARTEX (the open-source AI
penetration-testing framework) is believed to have
been used (Nextgov reporting; an ISMG / Times
reporter notes early indications suggesting possible
Chinese responsibility) — that is reported belief,
NOT agency-confirmed, so ARTEX involvement is
Inferred and attribution is Unknown; what data was
taken is unclear (Unknown).

Failure addressed, for the class and conditionally:
**presence on a network is not per-act authority.**
If both conditions hold — the ARTEX link, and
separately that the operator's presence was
legitimate (authorized access under a standing
tasking) rather than external exploitation — an
autonomous agent operated inside a network it was
legitimately able to reach and took acts no tasking
authorized; in any system
whose authorization is presence or standing tasking —
be on the network, or hold the mission credential,
perform the act — that is the whole attack:
``REACHABILITY_OF_A_NETWORK !=
AUTHORIZATION_FOR_EVERY_ACT_WITHIN_IT``. A standing
tasking credential binds no exact intent for a
different act, names no per-act accountable approver
for it, and carries no scope beyond the tasking it
was issued for. The governing invariants are the
fail-closed rule of AGENTS.md (unknown, malformed,
untrusted, expired, replayed, or unavailable authority
fails closed through the canonical kernel) and
exact-intent binding itself: under the kernel, a
consequential act requires a permit issued only after
an approval whose signature verifies against the
value computed from the payload under the enrolled
authority's key, bound to the exact intent —
principal, action, resource, cost, session — and
spent exactly once at consume, where the token is
itself authenticated and its state row re-checked. A
tasking credential is none of those things on any
route: not a token the kernel issued (consume refuses
it), not a signature the authority made (evaluation
refuses it), and not a scope (a genuine approval for
one act refuses to stretch to another).

What actually resolved the real incident, and by what
mechanism the intruder entered and acted, is not
established by the reporting (§5, §6). This replay
claims nothing about it; it models the gate the
class's acts would face at a gateway routing its
consequential acts through this kernel.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately vulnerable
double (`_StandingTaskingVerifier`) exists solely as
the negative control, is test-local, and is never
imported by runtime code — the same pattern as PRs
#346 and #362–#388.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `OsintGatewayExecutor` is a test
harness: it records a consequence only after a
successful kernel consume and holds no canonical
state. The incident-channel freeze is asserted
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
denied `evaluate` appends one decision record; a
`consume` rejection appends one `permit_rejected`
record; a denied approval-envelope evaluation appends
two records — an `approval_rejected` record and a
denied decision record. Growth stays bounded per
attempt (at most two records), which is the invariant
the scenario pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_cia_odni_osint_incident_scenario.py`
(7 tests, all passing at the worktree head):

- positive control: the one legitimate act (reading
  public / commercial OSINT feeds, the agent's actual
  tasking) executes exactly once under a genuine,
  well-formed verified approval envelope; replay of
  the spent permit is denied; the audit chain
  verifies.
- step 1: with no credential at all, `evaluate`
  returns `require_approval` for both target acts (the
  restricted-collection-store read and the dataset
  export), with no permit minted and nothing executed
  — reachability of the network is not an approval. An
  act the policy does not contain at all
  (`delete_resource`, a verb the gateway has never been
  given for anyone) is denied outright
  (`action_not_allowed`).
- step 2: the agent's standing tasking credential
  presented as a permit at the dispatch boundary is
  refused for both target acts (`permit_rejected`,
  reason `permit_signature_invalid`, bound to the exact
  intent hash each time). The credential was never
  issued as a permit: no state row stands behind it
  and no genuine token signature does either, so a
  tasking is not an issuance.
- step 3: the standing tasking credential offered as
  an approval signature, a fabricated signature offered
  for the export act, and an envelope signed with an
  unauthorized key are each denied
  (`approval_signature_invalid`); an empty signature is
  denied earlier and separately
  (`approval_signature_missing`). The governed path
  does not distinguish a legitimate-for-another-purpose
  non-authority from an invented one.
- step 4: the genuine envelope for the tasked feed
  read presented for each target act is denied
  (`approval_intent_mismatch`), and the genuine issued
  permit presented against each target act at consume
  is refused (`permit_intent_mismatch`); the denials do
  not poison the path — the same permit then performs
  its own act exactly once.
- step 5: the incident channel sees the attempts —
  freezing a report over the full attempt sequence in
  incident order for the class (the no-credential
  probe, the not-in-policy probe, the standing tasking
  credential spent as a permit, a fabricated approval
  for the export act, the genuine envelope stretched
  to the restricted-store act, the genuine permit spent
  against the export act, the one legitimate execution,
  and the spent-permit replay) yields zero incidents
  and exactly the near-miss records the channel's
  derivation produces from the audit: 3
  `permit_rejected`, 2 `approval_rejected`, and 3
  denied `decision` records (8 near-misses in total),
  each classified Recorded under a valid audit chain;
  the freeze appends nothing. The step also pins the
  surfacing boundary stated in §5: the sequence's 1
  `require_approval` decision is present in the audit
  and contributes zero near-miss records. The counts
  are from the executed run at this head, not
  estimates.
- negative control: with the verifier swapped for the
  class's own shape — a verifier whose `verify()`
  accepts the agent's standing tasking credential as
  the signature for ANY envelope, tasking treated as
  blanket authority — an envelope for the
  restricted-store read "signed" with the tasking
  credential VERIFIES, a permit mints, and the read
  EXECUTES. Under the same double, a fabricated string
  and the genuine authority's real HMAC signature are
  both denied: only the tasking credential verifies,
  because tasking is the whole check — the class's
  precision, reproduced at the exact layer it would
  happen. The denials in the steps above therefore
  come from the governed verification's shape (a
  computed expected signature under the enrolled key,
  bound to the exact intent), not from a harness that
  denies by construction.

Full suite at the worktree head: **1113 tests, OK
(skipped=25)** in this environment — the recorded
local baseline at the base commit `9aca02e` is 1106 OK
(skipped=25); the delta is exactly the 7 scenario
tests. (The skipped=25 figure is this environment's
count; CI records its own environment's skipped count
with the same test total modulo environment-specific
discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — the class is itself a flip of the trust
  direction: the component legitimately inside the
  network (an agent operating under a genuine tasking)
  is, conditionally, the hostile actor, and its
  legitimate presence is the attack surface. No control
  on the governed path depends on the agent's
  cooperation or on the legitimacy of its presence: no
  credential (step 1), the standing tasking credential
  (steps 2, 3), a fabricated signature (step 3), and a
  forged key (step 3) are the same denial, and flipping
  the presenter's standing (tasked agent vs. outside
  peer) changes nothing without the enrolled key.
- Reverse — each consequence (a restricted-store read,
  a dataset export) requires a consumed permit; the
  permit requires a verified approval; the approval
  requires a signature computed from the payload under
  the enrolled key by an accountable approver, bound to
  the exact intent. The earliest point at which the
  consequence becomes unreachable is the credential
  itself, and the chain does not collapse to one
  control: the tasking credential fails at token
  authentication at consume (step 2) and at signature
  verification at evaluate (step 3), fabricated and
  forged artifacts fail at verification (step 3), the
  genuine article fails to stretch at intent binding on
  both boundaries (step 4), and the spent permit cannot
  be replayed (positive control, step 5).
- Invert — outcome is not legitimacy: inside the
  incident as reported, reachability of the
  unclassified network and exposure of some information
  are outcome facts; nothing in the reporting shows any
  per-act authorization for the acts taken, and the
  replay asserts nothing about the real acts' mechanism
  (§5, §6). The governed record supports credit only
  for consumed acts under verified approvals, so a
  tasking-accepted read would stand in the record as a
  consequence with no per-act approval behind it,
  visible as such; the negative control produces
  exactly that shape, under the double rather than the
  kernel.
- Inside-Out — the governor cannot originate the
  authority it enforces: a tasking credential cannot
  produce an approval envelope or ceremony evidence at
  all; the test double is test-only; the orchestrator
  surface used for the incident report is read-only and
  its freeze is asserted to append nothing (step 5).
  One custody boundary is recorded, not smoothed
  (corrected in the §9 fix pass — the original text
  claimed the verifier "holds only verification"):
  this harness's approval verifier is the shared
  `HmacTestVerifier` double, which stores the HMAC
  secret, exposes `sign()`, and is passed directly as
  the kernel's `approval_verifier` — the enforcing
  component therefore possesses signing capability in
  this test (same-process signer custody; the
  double's own stated limit is "not evidence of
  independent authority"). The kernel consults it
  only through the verification interface, but this
  replay does NOT establish verification-only
  custody; that property belongs to a production
  asymmetric verifier and is outside this evidence.
- Darken — worst credible bounded case (a threat case,
  not a claim, and conditional on the Inferred ARTEX
  link and the separate legitimate-access assumption):
  an autonomous penetration-testing agent
  already legitimately able to reach a network holding
  intelligence-analysis material needs no new access to
  attempt beyond-tasking reads and exports — presence
  is the only prerequisite a presence-verified system
  asks for. Inside the governed path the maximum
  consequence per approval remains the one authorized
  act; every unauthorized attempt produces audit
  records only — one per attempt on the bare-evaluate
  and consume routes, two (an `approval_rejected`
  record and a denied decision record) on the denied
  approval-envelope route — and zero consequences.
  Outside the governed path stands the class's real
  worst case — presence- or tasking-verified systems,
  reachable by any agent operating under any tasking —
  and this replay does not mitigate it; it is the
  boundary in §5.
- Lighten — minimum benign interpretation: the
  affected network was unclassified, no classified
  systems were affected, some unclassified information
  was exposed in an amount the reporting does not
  quantify, and the intrusion is resolved per sources.
  The ARTEX link is reported belief, not confirmation;
  the entry vector may have had nothing to do with any
  agent's tasking at all, in which case this replay's
  class does not describe the incident — that is why
  the framing is conditional. The replay grades the
  mechanism — reachability or tasking treated as
  per-act authority — not any actor, and claims no harm
  the record does not show.
- Amplify — the class is cheap to replicate: many
  agents, many taskings, many networks, in parallel,
  each already legitimately present somewhere.
  Approvals are per-intent and permits single-use, so
  replication multiplies attempts, never authority;
  denial volume produces audit growth only, bounded per
  attempt.
- Negate — the smallest clean path: a consequential
  act on a network needs no presence- or
  tasking-verified route at all. A verified approval
  bound to the exact intent, checked against a value
  computed under the enrolled key, achieves the
  legitimate purpose — a tasked agent reads exactly the
  feeds it is tasked to read — with no standing
  credential whose mere possession performs further
  acts. Remove presence-as-authority and the incident
  class (as conditionally framed) does not happen.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models credentials and approval artifacts
presented at a governed gateway boundary, conditionally
on the Inferred ARTEX link and on the separate
assumption that the operator's network presence was
legitimate (authorized access/tasking) — an assumption
the reporting does not establish and ARTEX involvement
alone would not imply. It proves nothing about the
real intrusion: not its entry vector (Unknown), not
whether ARTEX was in fact used (Inferred — reported
belief, not agency-confirmed), not attribution
(Unknown), not what data was taken (Unknown), and not
the mechanism of any real act. If either condition
does not hold, this replay describes a class the
incident inspired, not the incident. The credential strings are
inert stand-ins, and the verifier double is a test-local
model faithful only in the property the scenario names
(acceptance of a standing tasking credential as the
signature for any envelope). Pulpo's claim here is only
about the gate it sits on: had an agent inside such a
network reached a gateway routing its consequential
acts through this kernel, the standing tasking
credential, the fabricated signature, and the stretched
permit would each have failed closed, for the reasons
the steps record. The replay also does not speak to the
parts of any such intrusion outside the gate: the
reconnaissance, the network movement, the initial
entry — the kernel governs the consequential act, not
the looking around that precedes it. And it proves
nothing about non-governed paths: a gateway that treats
network presence or a standing tasking as per-act
authority is governed by nothing here — a control not
on the execution path governs nothing. Whether any given
production gateway's authorization is presence-shaped
is an audit question for that gateway; this scenario
pins only that the canonical kernel's shape gives
presence and tasking nothing to act with beyond the
exact act approved.

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
engineering around it.

## 6. Claim classification

- The intrusion itself (an intrusion into the
  unclassified OSINT-analysis network; some
  unclassified information exposed; no classified
  systems affected; the intrusion resolved per sources;
  NGA concurrently affected; DCDC also intruded,
  low-impact per Nextgov; distinct from the FBI NCIC
  probe per CNN sources): **Recorded** (NYT reporting
  first published 2026-11-24, confirmed by Reuters,
  CNN, Nextgov, and ISMG).
- ARTEX involvement: **Inferred** (reported belief in
  Nextgov reporting — believed to have been used, NOT
  agency-confirmed).
- Attribution: **Unknown** (unconfirmed; early
  indications suggesting possible Chinese responsibility
  are a reporter's note, not an attribution).
- Entry vector: **Unknown** (undisclosed).
- What data was taken: **Unknown** (unclear in the
  reporting).
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 5).
- The mapping from the incident to the agent-tasking
  model (the restricted-store read and the dataset
  export modeled as the consequential acts; the standing
  tasking credential modeled in its three positions —
  presented permit, presented approval signature,
  blanket-authority acceptance): **Inferred** — the
  harness's modeling choices, stated in the module
  docstring, and flagged as conditional on the Inferred
  ARTEX link and on the separate legitimate-access
  assumption (the operator's presence being authorized
  access/tasking rather than external exploitation),
  which the reporting does not establish.
- The harness verifier's custody: same-process signer
  custody, recorded as an evidence boundary — the
  `HmacTestVerifier` double holds the HMAC secret and
  a `sign()` method and serves as the kernel's
  `approval_verifier`, so this replay does not
  establish verification-only custody (see §4,
  Inside-Out, as corrected in the §9 fix pass).
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346 and #362–#388, including their
per-module helper-duplication pattern, the
reporting-coverage construction of PR #378's step 6 as
amended, and the negative-control double construction
of PR #386.

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
  once, the no-credential and not-in-policy denials,
  the standing-tasking-credential consume refusals, the
  fabricated / forged / missing-signature denials, the
  genuine article's refusal to stretch on both
  boundaries, the incident channel's 0 incidents / 8
  near-misses, and the negative control executing under
  the tasking-as-blanket-authority double. Full suite at
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

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.

## 9. Post-review fix pass (Codex P2 x2 on PR #399, 2026-11-25)

Two Codex findings on the original head `f3171c6`,
both wording/framing defects, both accepted and
fixed; no code or test logic changed
(`authority_effect=none` throughout).

- **Separate ARTEX involvement from authorized
  access.** The conditional framing rested the
  authorized-channel class on the reported ARTEX
  link alone, treating ARTEX involvement as implying
  legitimate network reach and a standing tasking.
  Reported ARTEX involvement establishes only that
  the tool may have been used; the entry vector is
  Unknown, so external exploitation remains possible
  even if the link holds. The framing — in this
  record's header, §1, §4 (Darken), §5, §6, and the
  module docstring — now states two separate
  conditions: (a) the ARTEX link, and (b) the
  operator's presence being legitimate (authorized
  access under a standing tasking), with (b)
  explicitly not following from (a). ARTEX
  involvement remains **Inferred** and conditional,
  as before.
- **Remove the verification-only claim.** §4's
  Inside-Out pass claimed "the approval verifier
  holds only verification." The harness contradicts
  it: `self.verifier` is the shared
  `HmacTestVerifier`, which stores the HMAC secret
  and exposes `sign()`, and is passed directly as
  the kernel's `approval_verifier` — the enforcing
  component possesses signing capability in this
  test. The claim is removed and replaced with the
  custody boundary stated plainly: same-process
  signer custody, recorded as an evidence boundary
  in §4 and §6; this replay does not establish
  verification-only custody.

Re-verification at the fix-pass head: scenario 7/7;
full suite **1113 tests, OK (skipped=13)** in this
environment — identical totals to the pre-pass head,
as expected for a wording-only change.

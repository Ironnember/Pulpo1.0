# Change record — Incident replay: OpenRouter inference-provider incidents (announced 2026-11-22)

Base: `origin/main` at `2726e59` (incident replay: Microsoft
Entra Connect Health API tenant-metadata exposure, PR #379).
Authority: Austin approved this build on 2026-11-22 ("Build
the replay PR"), after the incident surfaced the day
OpenRouter announced it. Test-only change: one scenario
module plus this record. No production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from OpenRouter's own security
announcement, "Data Processing Incidents on Inference
Providers," 2026-11-22): following Dragos's canary-prompt
investigation (research led by HD Moore; roughly two million
seeded canary prompts carrying traceable fake secrets and
links, run July–November 2026), OpenRouter permanently
off-boarded three inference providers from its marketplace,
removed 125 endpoints from Zero Data Retention (ZDR)
eligibility, and notified affected customers. OpenRouter
states its own infrastructure was not breached. The three
removed providers are not named in the announcement.

Three failure modes are documented across the announcement
and the linked provider disclosures:

1. **Payload altered in transit.** Per the Dragos findings
   as reported, one seller silently injected roughly 1,000
   hidden tokens into prompts passing through it: the
   payload the model received was not the payload the
   customer sent.
2. **Traffic forwarded to an unauthorized destination.**
   Per Novita's own privacy notice, a routing configuration
   sent some MiniMax requests to MiniMax's official API from
   2026-05-28 to 2026-11-11, beyond what customers intended;
   Dragos additionally reported routers secretly forwarding
   traffic to unauthorized third parties.
3. **Policy flags not binding downstream.** Requests
   flagged ZDR / no-data-collection were copied and retained
   anyway, and attackers inside compromised providers copied
   requests — ZDR-marked ones among them — for months,
   undetected.

Failure addressed: **a dispatch through a trusted path
inherited its authority from the path, not from an
authorization for the exact act.** The payload could be
altered because nothing bound the dispatch to the exact
bytes approved; the traffic could be forwarded because
nothing bound the dispatch to the exact destination
approved; the ZDR flag governed nothing because a flag is
data about a request, not authority over it. The governing
invariants are `AUTHORIZED_OUTCOME !=
AUTHORIZATION_FOR_ARBITRARY_MEANS`, `ACCESS !=
AUTHORITY_FOR_THE_SPECIFIC_ACT`, and the exact-intent
binding itself: under the kernel, each dispatch requires
its own permit bound to the exact intent — principal,
action, resource (destination endpoint and payload digest
together), cost, session — rechecked at consume and spent
on use, so an altered payload, a different destination, or
a re-presentation under a flag is a different intent, and
one permit cannot be spent as any of them. Denial is
fail-closed at evaluate/consume, at execution time — not a
discovery made months later.

Scope discipline, stated up front: this replay models
failure modes 1 and 2 and the flag-versus-permit half of
mode 3. It claims nothing about confidentiality. A provider
that legitimately receives a payload can copy it, and no
permit changes that; the months of undetected copying by
attackers inside compromised providers is a custody and
detection failure this replay does not address (see §5).

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a test
module only: no production surface is added, narrowed, or
widened; no permit, policy, or state behavior changes. The
module's deliberately unguarded doubles (`_IntentBlindState`,
`_UnguardedConsumeKernel`) exist solely as the negative
control, are test-local, and are never imported by runtime
code — the same pattern as PRs #346 and #362–#379.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit read,
and incident-channel derivation paths, and adds no writer,
route, ledger, executor, or state backend. The
incident-channel freeze is asserted read-only in the scenario
itself (audit length unchanged across the freeze). Audit
growth is classified in the module docstring per AGENTS.md
(`NO_PERMIT != NO_GOVERNED_EFFECT`): each denied attempt
appends audit records — a governed effect (evidence
production), append-only, with `authority_effect=none` and
no capability accumulation — assessed separately from
governed external consequences throughout. The count is per
route, not uniformly one: a bare `evaluate` returning
`require_approval` appends one decision record; a
policy-denied `evaluate` appends one denied decision
record; a `consume` rejection appends one `permit_rejected`
record; a denied approval-envelope evaluation appends two
records — an `approval_rejected` record and a denied
decision record. Growth stays bounded per attempt (at most
two records), which is the invariant the scenario pins.

One kernel behavior the scenario exposes and pins rather
than fixes (it is pre-existing, at the base commit, and
outside this change's test-only scope): AgentGrant resource
matching is prefix-based (`str.startswith`, kernel
`_policy_failure`). A destination formed by appending a
suffix to the authorized endpoint's identity therefore
passes the grant layer. Step 3 pins this exactly — the
suffixed destination reaches `require_approval` at evaluate
rather than the scope denial a genuinely distinct
destination receives, and is denied at consume by the
exact-intent permit binding. See §5 for the claim boundary
this imposes, and §8 for its identical presence at the
base checkpoint.

## 4. Exact success and adversarial evidence

Scenario module `tests/test_openrouter_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the one authorized act (one exact
  prompt payload dispatched to one exact endpoint) executes
  exactly once under a verified approval envelope; replay
  of the spent permit is denied; the audit chain verifies.
- step 1: the unapproved dispatch is denied on every
  route — `evaluate` returns `require_approval` with no
  permit minted, and the customer's API key itself,
  presented as a permit, is rejected at consume
  (`permit_rejected` bound to the altered intent's hash).
  An account key is not a permit.
- step 2: the approved dispatch with an injected block
  appended to its payload in transit — the hidden-token
  shape — is denied under the genuine permit: the altered
  payload is a different intent, the rejection is bound to
  its hash, and the genuine permit spends afterward on its
  exact intent. The alteration fails at execution time.
- step 3: destination scope, in both of its shapes. The
  forward to the provider's upstream endpoint — a genuinely
  distinct destination sharing no string prefix with the
  authorized endpoint — is denied at `evaluate` with
  `agent_resource_not_allowed` (one denied decision record,
  no permit minted) and rejected at consume under the
  genuine permit. The suffixed destination (authorized
  identity plus `/mirror`) is pinned as it actually behaves:
  it passes the grant's prefix check (its bare evaluate
  reaches `require_approval`) and is denied at consume by
  the exact-intent permit binding. The permit still spends
  on the exact approved dispatch afterward.
- step 4: the spent permit replays for nothing —
  re-presented for the same dispatch and for the altered
  payload after consumption, both are rejected
  (2 `permit_rejected` against 1 `permit_consumed`). A
  consumed permit is not a reusable routing credential.
- step 5: an approval envelope for the dispatch signed with
  an unauthorized key is denied
  (`approval_signature_invalid`), and the genuine envelope
  presented for the altered payload's intent is denied
  (`approval_intent_mismatch`); the genuine pair still
  admits afterward.
- step 6: the incident channel sees the campaign — freezing
  a report over the full attempt sequence (every attack
  variant from steps 1–5 and 7: all four attack intents on
  every route, both approval-envelope attempts, and both
  spent-permit replays) yields zero incidents and exactly
  the near-miss records the channel's derivation produces
  from the audit: 10 `permit_rejected` (8 campaign-route
  rejections plus the 2 spent-permit replays),
  2 `approval_rejected`, and 3 denied `decision` records —
  the forward's `agent_resource_not_allowed` scope denial
  and the two step-5 envelope denials
  (`approval_signature_invalid`,
  `approval_intent_mismatch`) — 15 near-misses in total,
  each classified Recorded under a valid audit chain; the
  freeze appends nothing. The step also pins the surfacing
  boundary stated in §5: the sequence's 3 `require_approval`
  decisions are present in the audit and contribute zero
  near-miss records. The counts are from the executed run
  at this head, not estimates; the reporting sequence
  replays every variant and every denial route by
  construction, including the bare-evaluate route in both
  of its shapes (the lesson of the Codex P2 on PR #381,
  applied at first submission here rather than by
  amendment).
- step 7: a privacy flag is not authority — in a fresh
  session, the permitted dispatch re-presented carrying
  only its ZDR flag as a claim to authority is
  `require_approval` at evaluate and rejected at consume
  with the API key presented as its permit. The flag's
  presence changes nothing about what the kernel asks for.
- negative control: with consume unguarded at both layers
  (kernel double + intent-blind state double), the
  altered-payload dispatch EXECUTES under the genuine
  permit — the incident's own shape, a routing path that
  forwards whatever arrives, altered or not. The denials
  come from the binding layers, not from a harness that
  denies by construction.

Full suite at the worktree head: **1045 tests, OK
(skipped=13)** — the recorded baseline at the base commit
`2726e59` is 1036 OK (skipped=13); the delta is exactly the
9 scenario tests.

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — no control depends on how the request reached the
  router: the customer's own API key and an attacker's
  token are indistinguishable as authority artifacts, and
  neither mints anything; authority arrives only as
  verified per-dispatch approvals. The incident's own flip
  is that the marketplace built to route prompts became
  the path that altered and copied them.
- Reverse — the dispatch requires a consumed permit bound
  to the exact intent; the earliest unreachable point is
  the first altered or forwarded dispatch (denied at
  evaluate and at consume), and the chain does not collapse
  to one control: the genuine permit cannot be re-aimed at
  another destination (step 3), re-scoped to an altered
  payload (step 2), or replayed after use (step 4).
- Invert — outcome is not legitimacy: a model response
  returning normally would be "success" by outcome even
  for an altered prompt, but the governed record supports
  credit only for consumed acts (exactly one: the approved
  dispatch), so any claim that the altered or forwarded
  dispatches were authorized is unsupportable against the
  audit and visible as such in the incident channel
  (step 6).
- Inside-Out — the governor cannot originate the authority
  it enforces: an envelope signed with an unauthorized key
  is denied (step 5a); an API key or a ZDR flag cannot
  produce an approval envelope or ceremony evidence at
  all; the test verifiers are test-only; the orchestrator
  surface used for the incident report is read-only and
  its freeze is asserted to append nothing (step 6).
- Darken — worst credible bounded case: the compromise
  window ran from mid-2026 to the 2026-11-22 announcement
  across every customer routing through the affected
  providers, at API tempo. Inside the governed path the
  maximum consequence remains the one authorized dispatch;
  every altered, forwarded, or flagged attempt produces
  audit records only — one per attempt on the bare-evaluate
  and consume routes, two (an `approval_rejected` record
  and a denied decision record) on the denied
  approval-envelope route — and zero consequences. Outside
  the governed path stands the incident's real worst case —
  including the copying of legitimately delivered payloads,
  which no dispatch control governs — and this replay does
  not mitigate it; it is the boundary in §5.
- Lighten — minimum benign interpretation: a routing layer
  that sincerely wants one API key to carry a customer's
  traffic wherever the platform finds capacity, for
  convenience and price. The kernel still denies every
  unapproved dispatch, because a standing routing
  convenience, however sincere, is not a per-dispatch
  approval — and silent forwarding plus silent alteration
  is what unbounded routing convenience accumulates. The
  positive control shows the governed path exists: approve
  the exact dispatches intended.
- Amplify — the failure replicated across every provider
  on the marketplace at once; permits are per-intent,
  per-session, and single-use, so replication multiplies
  attempts, never authority. Denial volume produces audit
  growth only.
- Negate — the smallest clean path: the legitimate purpose
  (routing a customer's prompt to the provider they chose)
  needs only per-dispatch permits for the exact payload
  and destination intended. A standing key that authorizes
  any payload to any endpoint, and a privacy flag treated
  as a control, are both unnecessary.

Stop/continue decision: CONTINUE in the governed kernel path
only.

## 5. Boundary the evidence does not prove

The scenario models dispatches presented for consumption by
a caller on the governed path. It proves nothing about
OpenRouter, any inference provider, any model, or any real
traffic, and it reproduces no part of any routing service.
Four boundaries are stated plainly:

1. **Confidentiality is out of scope.** The incident's
   longest-running harm — attackers inside compromised
   providers copying requests they legitimately received,
   for months — is not a failure this replay's controls
   address. A permit governs whether a dispatch may occur;
   it does not govern what a destination does with a
   payload it was authorized to receive. No claim is made
   that Pulpo would have stopped the prompt theft.
2. **Grant resource matching is prefix-based at this
   commit** (Verified, kernel source and step 3's pinned
   behavior). The scenario's destination-scope claim is
   therefore exact only in the form the run proves: a
   genuinely distinct destination (no shared string prefix
   with the authorized endpoint) is denied at evaluate by
   the grant (`agent_resource_not_allowed`) and at consume
   by the permit binding; a prefix-sharing destination
   passes the grant layer and is denied at consume by the
   permit binding alone. The scenario does not establish
   exact-equality destination scope in the grant layer, and
   no wording in this record claims it does. Whether grant
   matching should be exact-equality is a kernel design
   question (first surfaced by PR #381's review); this
   replay records the behavior and takes no position by
   silently engineering around it.
3. **Non-governed paths.** A routing layer that forwards
   first and checks never — the incident's own shape — is
   governed by nothing here. A control not on the execution
   path governs nothing.
4. **Surfacing boundary (issue #375).** A bare `evaluate`
   that returns `require_approval` appends a decision
   record to the canonical audit, where it is complete and
   chain-verified, but the incident channel does NOT derive
   a near-miss record from it; the channel derives
   near-misses from `permit_rejected`, `approval_rejected`,
   denied decisions, and `directive_denial`. The act is
   still stopped — no permit exists to spend — so this is a
   derivation-coverage boundary in the owner-facing
   channel, not an authorization gap. Step 6 pins it: the
   sequence's 3 `require_approval` decisions contribute
   zero of its 15 near-misses. (The forward's bare evaluate
   is the other shape: a policy denial, which IS derived —
   1 of the 3 denied decisions in the pin.)

## 6. Claim classification

- Incident narrative: **Recorded** (OpenRouter's own
  security announcement, 2026-11-22 — the disclosing
  source's primary statement; Novita's privacy notice for
  the forwarding dates and destination; the Dragos findings
  as reported for the hidden-token injection and the canary
  method, attributed as reported rather than as
  independently verified here).
- The identities of the three removed providers:
  **Unknown** — not named in the announcement.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The prefix-matching behavior of AgentGrant resource
  scope, and the incident-channel surfacing boundary in §5:
  **Verified** (kernel source at the base commit, executable
  probe, and step 3 / step 6's pinned counts).
- The mapping from the incident's pattern to kernel intents
  (a dispatch names its destination endpoint and payload
  digest together in the resource identity; an injected
  block modeled as a distinct payload resource; an upstream
  forward modeled as a distinct destination resource; an
  API key and a ZDR flag modeled as no authority artifact
  at all): **Inferred** — the harness's modeling choices,
  stated in the module docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and assertion
style mirror the canonical scenario modules merged in PRs
#346–#350, #362–#368, and #374–#379, including their
per-module helper-duplication pattern, and the
reporting-coverage construction of PR #378's step 6 as
amended and PR #379's step 6 (every attack variant and
every denial route replayed into the frozen sequence).

## 8. Temporal-transfer evidence

Executed 2026-11-22. The applicable historical checkpoint
is this branch's exact base, `2726e59`: the bindings the
scenario exercises (exact-intent binding, single-use
consumption, approval verification, grant destination
scope) all predate this change, so the checkpoint
comparison AGENTS.md requires was runnable and has been
run.

Method: a clean worktree was reconstructed at exactly
`2726e59` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module). The scenario was run there under the canonical
command, then the full suite. Baseline at `2726e59`
without the lesson is 1036 OK (skipped=13); the branch
adds no kernel code, so any behavioral difference at the
checkpoint would have been a finding, not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 9 scenario tests pass identically at
  `2726e59` — the API-key refusal, the altered-payload
  denial, the forward's scope denial and consume
  rejection, the suffixed destination's grant-pass /
  binding-denial pin, the spent-permit replay denials, the
  forged/mismatched approval denials, the positive control
  executing exactly once, the ZDR-flag step, the negative
  control executing when unguarded, and the incident
  channel's 0 incidents / 15 near-misses. Full suite at
  checkpoint-plus-lesson: 1045 OK (skipped=13), identical
  to the worktree head; the delta over the 1036 baseline
  is exactly the 9 scenario tests.
- NO EFFECT: the lesson is tests and documentation only;
  it changes no kernel behavior at the checkpoint or at
  the head, and consequential authority is unchanged by
  the replay itself (`authority_effect=none` at both
  states).
- NEGATIVE TRANSFER: none observed. Two boundaries are
  identical at both states and are recorded, not smoothed:
  the §5 bare-evaluate near-miss gap (issue #375), and the
  §5 prefix-matching behavior of the grant layer — both
  are properties of the base, present at `2726e59` exactly
  as at the head; the replay neither introduces nor widens
  either.

The evidence is therefore valid at the checkpoint and at
the worktree head; reuse of the lesson at a later commit
still requires re-evaluation there.

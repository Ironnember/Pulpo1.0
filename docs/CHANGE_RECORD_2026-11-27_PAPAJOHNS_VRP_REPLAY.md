# Change record — Incident replay: Papa John's / TrueLayer VRP agent payment — a standing amount mandate treated as authority for the act (reported 2026-11-27)

Base: `origin/main` at `f734c97e` (PR #38 merged;
verified by fetch at build time, 2026-11-27).
Authority: Austin approved this build on 2026-11-27
in words ("Build the Papa John's replay PR"), for the
event surfaced the same day; the authorization covers
this build's fresh clone. Test-only change: one
scenario module plus this record. No production code
is touched.

## 1. Invariant or failure addressed

Event (graded from the public record): The Guardian
and The Times reported (Recorded, named-outlet
reporting, 2026-11-27) that a Papa John's UK AI agent
ordered nine mini margherita pizzas at a store in
Wokingham, Berkshire, and paid for them directly from
the customer's Lloyds Bank account -- no card -- via
TrueLayer's AI Agent Payments using commercial
Variable Recurring Payments (VRP), inside the FCA's
Supercharged Sandbox; the outlets describe it as a UK
first. The customer ("Charlotte") had her pizzas in
about twenty minutes, already paid for when she
arrived. Andy Piggott, Papa John's UK chief digital
officer, stated (Recorded) that the agent was given
the task of ordering the pizza and "went off and did
it, using the same data and tools" a human agent
would have. The authorization mechanics, as reported
(Recorded): the customer linked her bank account
inside her banking app and established a standing
mandate -- a maximum spend per transaction and a
maximum per month; each time the agent requests a
payment, the bank checks the amount against the
mandate and declines anything over the limit; the
agent never sees or stores account credentials; the
customer can revoke the agent's access at any time in
the app. No per-purchase human approval of the exact
payment -- this merchant, this amount, this
destination -- is part of the reported flow.

Claim discipline (load-bearing): the real transaction
was legitimate and as-intended -- the customer asked
for the pizzas and got them. This replay does NOT
claim the reported purchase was manipulated, steered,
or wrongful in any way. What it models is the
architectural property the reporting establishes: the
mandate checks the amount, not the intent, so a
steered or substituted payment instruction inside the
limits executes with no approval of that exact action
ever existing.

Failure addressed: **a standing amount mandate is not
approval of the act.** The mandate was the only
artifact the payment path checked, and presenting it
(with an in-cap amount) was treated as authority for
each payment it was presented for -- the genuine
purchase, and, indistinguishably, any other in-cap
payment, to any merchant, composed by whoever steered
the agent. At no point did the path ask the separate
question: was THIS payment approved? Under the
canonical kernel, the mandate reference is not a
permit at all -- presented at `consume` it is an
unauthenticated string and is refused. Authority for
a payment enters only as a verified approval envelope
-- signed by an enrolled authority and bound to the
exact intent hash (principal, action, resource,
cost, session) -- and mints a single-use permit for
exactly that intent: the genuine approved payment
executes under its permit, and a substituted payment
presented with that same permit is refused at consume,
the refusal burning nothing. The governing invariants
are `AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`
and fail-closed authorization: unknown, malformed,
untrusted, or merely possessed authority mints nothing
and spends nothing.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's `MandatePaymentBoundary`
double exists solely as the negative control, is
test-local, and is never imported by runtime code --
the same pattern as PRs #346 and #362-#393, #415,
#416, #422, and #423. The scenario's reconciliation
helper (`reconcile_consequences`) is likewise
test-local: it reads the harness's executed log and
holds no canonical state.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `PaymentBoundary` is a test harness: it
executes a payment only after a successful kernel
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
`tests/test_papajohns_vrp_incident_scenario.py`
(7 tests, all passing at the worktree head):

- positive control: the one authorized act (the
  genuine payment -- this merchant, this amount, this
  destination) executes exactly once under a genuine,
  well-formed verified approval envelope; the permit,
  spent at that consume, cannot pay twice;
  reconciliation of executed-vs-approved reports exact
  equality (1 approved, 1 executed, 0 unauthorized);
  the audit chain verifies.
- step 1: the substitution refused at consume, and the
  refusal is free -- the genuine permit, presented
  FIRST for the substituted payment (a different
  merchant, a different amount, an act no human
  approved), is refused at the kernel's intent binding,
  the rejection naming the substituted intent's hash;
  the refusal consumes nothing, and the genuine permit
  then spends on its own act, exactly once. Under the
  reported architecture this attempt never faces the
  question: the substitution is inside the caps, and
  the caps are the whole check.
- step 2: the standing mandate presented as a permit --
  the only authorization artifact the reported
  architecture issues, in the role it plays there --
  is refused at `consume` for the genuine payment and
  the substitution alike. A budget authenticates a
  limit, and authorizes no act.
- step 3: with no artifact presented at all,
  `evaluate` returns `require_approval` for the
  genuine payment and the substitution alike -- being
  the customer's agent confers no route to a permit;
  and an approval envelope for the substitution signed
  with a key the agent controls is denied
  (`approval_signature_invalid`). The kernel verifies
  against the enrolled authority, and the party
  requesting the payment cannot also be the party
  approving it.
- step 4: reconciliation over a governed sequence
  shaped like the event -- the genuine payment
  approved and executed, the substitution attempted
  under the event's two available forms (the genuine
  permit stretched, before the genuine spend; the
  standing mandate presented as authority), and the
  spent permit replayed -- reports exact equality:
  1 approved, 1 executed, 0 unauthorized occurrences,
  and no refused attempt recorded as fulfilled. The
  comparison the reported path never runs, run here,
  is clean precisely because every substituted attempt
  was denied before it could execute.
- step 5: the incident channel sees the attempts --
  freezing a report over the full attempt sequence
  exercisable on one kernel (the no-approval
  evaluation of the substitution, the mandate presented
  as a permit for the substitution, the genuine
  approval stretched to the substitution, the one
  legitimate execution, and the spent-permit replay)
  yields zero incidents and exactly the near-miss
  records the channel's derivation produces from the
  audit: 2 `permit_rejected`, 1 `approval_rejected`,
  1 denied `decision`, and 1 `require_approval`
  `decision` (5 near-misses in total), each classified
  Recorded under a valid audit chain; the freeze
  appends nothing. The `require_approval` decision
  contributes one near-miss per occurrence under the
  issue #375 derivation (PR #413) -- this module was
  authored after that fix landed, so its counts are
  born correct against it.
- negative control: with no governor at all, the
  mandate boundary double does exactly what the
  reporting describes -- it takes the presented
  standing mandate at face value and checks only the
  amounts, against the per-transaction cap and the
  monthly cap. The genuine reported purchase executes;
  the substituted payment -- different merchant,
  different amount, inside both caps, never approved
  by the human as an action -- executes on the same
  authority; and an over-limit pull is declined, which
  is the one check the architecture has, working
  exactly as reported. Per-occurrence reconciliation
  against exact-action approvals -- of which the
  mandate architecture produces none, for any payment
  -- reports the run exactly: 0 approved, 2 executed,
  2 unauthorized occurrences, named. The genuine pull
  was the customer's own request in fact; nothing in
  the boundary's records distinguishes it from the
  substitution, and that indistinguishability -- not
  any claim about the real purchase, which was
  legitimate -- is the finding the control isolates.
  The denials in the steps above therefore come from
  the governed path's fail-closed authorization,
  exact-intent binding, and signature verification,
  not from a harness that denies by construction, and
  the reconciliation demonstrably detects the modeled
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
  checkout throughput (the reported flow's actual
  condition: the mandate was accepted because accepting
  it is what makes agent commerce frictionless), the
  fastest route from an instruction to a payment is to
  check the amount and nothing else. On the governed
  path, throughput has no dimension to exploit: the
  mandate is an unauthenticated string at consume
  (step 2), genuine authority stops at its own intent
  (step 1), and flipping the presenter changes nothing
  without the enrolled key (step 3).
- Reverse -- the consequence (an executed payment)
  requires a consumed permit; the permit requires a
  verified approval; the approval is bound to the exact
  intent hash and signed by the enrolled authority. The
  earliest unreachable point is the payment itself: the
  executor runs nothing without a consume, and the chain
  does not collapse to one control -- possession of the
  mandate stops at consume (step 2), scope stops at
  intent binding (step 1), self-assertion stops at
  signature verification (step 3), replay stops at
  single-use consumption (positive control), and absence
  of any artifact stops at the approval requirement
  (step 3).
- Invert -- outcome is not legitimacy: on the reported
  path the genuine purchase DID produce its outcome --
  pizzas ordered, paid for, delivered -- and every part
  of that success rested on a standing budget. The
  negative control reproduces exactly that shape and
  extends it by one instruction: both in-cap executions
  "succeed," and the reconciliation still reports both
  as carrying no exact-action approval, so a successful
  execution under a mandate is classified by the record
  as unapproved, not as authorized.
- Inside-Out -- the governor cannot originate the
  authority it enforces: the boundary holds no approval
  capability, the reconciliation helper is read-only
  over the harness's log and holds no canonical state,
  the mandate double is test-only, and the orchestrator
  surface used for the incident report is read-only with
  its freeze asserted to append nothing (step 5). In
  particular, the kernel has no route by which material
  an agent presents -- a mandate reference included --
  becomes authority: `CANONICAL_STATE_MUTATION ==
  GOVERNED_CAPABILITY`, and a budget is not an approval
  transition.
- Darken -- worst credible bounded case, from the
  reporting's own shape: an agent with a standing
  mandate over a customer's bank account is steered --
  by a fake page, a poisoned instruction, a compromised
  tool -- to pay an attacker's merchant, repeatedly,
  each pull inside the per-transaction cap, until the
  monthly cap is the only remaining brake; revocation
  in the app stops future pulls but identifies none of
  the executed ones as unapproved, because the records
  never distinguished them. Inside the governed path
  the maximum consequence per approval remains the one
  approved payment, once; every unauthorized attempt
  produces audit records only -- one per attempt on the
  bare-evaluate and consume routes, two (an
  `approval_rejected` record and a denied decision
  record) on the denied approval-envelope route -- and
  zero executed payments. Outside the governed path
  stands the modeled worst case -- payment paths that
  execute on a standing mandate alone -- and this
  replay does not mitigate it; it is the boundary in
  section 5.
- Lighten -- minimum benign interpretation: standing
  mandates for agent payments are ordinary, useful
  tooling, and the reported transaction is the benign
  case working exactly as designed -- the customer
  asked, the agent paid, the caps held, the credentials
  were never exposed. The governed path preserves what
  is benign: the genuine payment works (positive
  control), the caps' protection is not denied (the
  negative control shows the over-limit decline working
  as reported), and each payment's authorization becomes
  a governed question instead of an implication of a
  budget set at link time.
- Amplify -- the modeled harm is amplification by
  standing authority: one mandate, valid for every
  in-cap payment to any merchant, multiplies a single
  steering success into as many payments as the monthly
  cap admits. On the governed path, amplification
  multiplies attempts, never authority: the mandate
  spends on nothing no matter how many payments it is
  presented for (step 2), approvals are per-intent and
  permits single-use (steps 1, 3), and the
  reconciliation counts occurrences, so amplification
  is measured, not averaged away (negative control:
  2 unauthorized occurrences over the modeled shape).
- Negate -- the smallest clean path: a consequential
  payment must require an approval the agent cannot
  supply by presenting a standing artifact -- signed by
  an enrolled authority and bound to the exact intent.
  The mandate reference, the stretched permit, and the
  agent-signed envelope are each unnecessary to the
  approved task; remove the signature check and step 3's
  route returns, remove intent binding and step 1's
  returns; with both, the substitution's shape has no
  governed route.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models governed payments at a kernel
boundary. It proves nothing about TrueLayer's, Lloyds',
or Papa John's actual systems, the VRP standard's
specification, or any deployed payment environment,
and it reproduces none of the event's mechanics -- the
boundary's log entries are inert labels, the mandate
double is a test-local model faithful only in the
properties the scenario names (a presented mandate
taken at face value; amounts checked against two caps;
payments executed as presented), and no credential,
account detail, mandate parameter, or payment content
from the real event appears anywhere in the module.
It proves nothing about non-governed paths: a payment
path that executes on a standing mandate alone is
governed by nothing here -- a control not on the
execution path governs nothing.

The event narrative itself rests on one day's
reporting by two named outlets, not independently
verified by this change beyond the reporting itself.
The replay takes the reported authorization mechanics
as its model and grades each element (section 6); it
does not independently verify TrueLayer's product
behavior or the sandbox's terms. In particular, the
load-bearing boundary is the modeled substitution:
nothing in the reporting says a substituted or steered
payment occurred, was attempted, or is possible
against the participants' production controls beyond
the mandate mechanics reported; the scenario models
one genuine intent, one substituted intent, and one
over-limit pull as the architectural pattern the
reporting describes, not a per-transaction
reconstruction. The reporting states no purchase
price; every amount in the module is a scenario
parameter, not a reported figure.

## 6. Claim classification

- A Papa John's UK AI agent ordered nine mini
  margherita pizzas at a Wokingham store and paid
  directly from a customer's Lloyds Bank account, no
  card, via TrueLayer's AI Agent Payments using
  commercial VRP, inside the FCA's Supercharged
  Sandbox; the customer received the pizzas in about
  twenty minutes, already paid for: **Recorded** (The
  Guardian and The Times, 2026-11-27, read firsthand).
- The transaction is a UK first of its kind:
  **Recorded** (the outlets' characterization, carried
  as theirs, not independently established).
- The authorization mechanics -- standing mandate with
  per-transaction and monthly maxima set at account
  link; the bank checks each pull's amount against the
  mandate and declines over-limit pulls; the agent
  never holds credentials; access revocable in the
  banking app; no per-purchase approval of the exact
  payment in the flow: **Recorded** (The Guardian and
  The Times, as above).
- Piggott's statement that the agent was given the task
  and executed it with the same data and tools a human
  agent would have: **Recorded** (quoted in both
  outlets).
- That the reported purchase was manipulated, steered,
  or wrongful: **not claimed** -- the record says the
  opposite (a legitimate, as-intended purchase), and
  no step models it as anything else.
- That a substituted in-cap payment would execute
  under the reported mechanics with no exact-action
  approval existing: **Inferred** -- the modeled
  property, demonstrated executably against the
  mandate double built to the reported mechanics
  (negative control), not an observed event.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree
  head commit).
- The mapping from the reported flow to kernel
  artifacts (the payment boundary as one boundary; the
  genuine purchase and the substitution as two distinct
  intents; the standing mandate modeled as a
  consume-presented string): **Inferred** -- the
  harness's modeling choices, stated in the module
  docstring.
- Any claim that this prevents the modeled class in a
  deployed payment system: **Proposed** -- not made by
  this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346-#350, #362-#368, #374-#382, #386,
and #391-#393, and the approval-path construction of
PRs #416, #422, and #423 (the sibling Cairn, Morris,
and SAP replay modules).

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
  once with exact reconciliation, the substitution
  refused at consume under the genuine permit with the
  refusal burning nothing, the mandate reference refused
  as a permit for both payments, the no-approval and
  agent-signed denials, the governed-sequence
  reconciliation reporting zero unauthorized, the
  incident channel's 0 incidents / 5 near-misses, and
  the negative control executing both in-cap payments
  under no governor (the over-limit pull declined) with
  reconciliation reporting 2 unauthorized occurrences.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed.

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.

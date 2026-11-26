# Change record — Incident replay: Jesta / OpenCode agent-led intrusion attempt (attempt 2026-11-16; publicized 2026-11-24)

Base: `origin/main` at `9aca02e` (incident replay:
WP connect WordPress plugins supply-chain backdoor,
PR #388).
Authority: the standing incident scan surfaced the
incident in its 2026-11-24 afternoon run; Austin
approved this build on 2026-11-24 ("Build the
Jesta/OpenCode replay PR"). Test-only change: one
scenario module plus this record. No production code
is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from The Register's reporting of
the report by Jesta, a Tel Aviv security firm that
builds defensive tools against autonomous AI attacks;
Jesta declined to name the customer, a major financial
services firm): on 2026-11-16 at 4:24:57 a.m. ET, an
operator in Bucharest pointed OpenCode -- a free,
open-source coding agent, nothing in which was built
for hacking -- at the firm's systems, using only a
Chrome browser and the curl that ships with every Mac.
The first request, for a system's front page, was
refused; six seconds later the same address retried
presenting itself as an Android Pixel 10 phone, and was
refused again. The agent then asked the system for its
API definition, which was also refused -- but a
different address it tried was a decoy set up by Jesta,
and the decoy answered with a readable file defining
how the API works. The agent read the document and
followed a link it contained. At 4:26:01 a.m. ET
Jesta's defenses marked the visitor as an AI agent,
opened a case, and from then on everything the agent
accessed was contained inside a fake environment built
to trick intruders -- including a phony key the
environment served it. The agent worked like a
developer: it read the API docs and did what they said,
included the planted key in a command-line request, and
tested three scenarios -- using the decoy key, no key,
and a fabricated key of its own -- to determine whether
what it had found was legit. It tried multiple URLs,
identified a valid endpoint, and attempted to read from
one that accepts only data submissions, so that request
was blocked too. Five minutes and 44 seconds after the
first request it gave up; nothing was stolen, and Jesta
and its customer disclosed the activity to law
enforcement. Jesta does not know which model the
attacker ran behind OpenCode -- nothing in the traffic
named it; OpenCode's web fetch tool named the agent
itself. Jesta's co-founder and CTO stated the
counterfactual plainly: if that key had been real, the
agent would have been in.

Failure addressed: **a discovered credential is not
authority.** The agent treated possession of a found
key as authorization to act, and in any system whose
verification is possession -- present the key, perform
the act -- that is the whole attack:
``POSSESSION_OF_A_CREDENTIAL != AUTHORIZATION_FOR_THE_ACT``.
A found key binds no intent, names no accountable
approver, and carries no scope; nobody authorized
anything, because the key existed to be found. The
governing invariants are the fail-closed rule of
AGENTS.md (unknown, malformed, untrusted, expired,
replayed, or unavailable authority fails closed through
the canonical kernel) and exact-intent binding itself:
under the kernel, a consequential act requires a permit
issued only after an approval whose signature verifies
against the value computed from the payload under the
enrolled authority's key, bound to the exact intent --
principal, action, resource, cost, session -- and spent
exactly once at consume, where the token is itself
authenticated and its state row re-checked. A string an
agent found in a document is none of those things on any
route: not a token the kernel issued (consume refuses
it), not a signature the authority made (evaluation
refuses it), and not a scope (a genuine approval for one
act refuses to stretch to another).

What actually stopped the real incident was the decoy
environment -- Jesta's control, exercised before the
agent reached a real system. This replay claims nothing
about that control; §5 states the boundary in full.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately vulnerable
double (`_PossessionVerifier`) exists solely as the
negative control, is test-local, and is never imported
by runtime code — the same pattern as PRs #346 and
#362–#388.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `ApiGatewayExecutor` is a test harness:
it records a consequence only after a successful kernel
consume and holds no canonical state. The
incident-channel freeze is asserted read-only in the
scenario itself (audit length unchanged across the
freeze). Audit growth is classified in the module
docstring per AGENTS.md (`NO_PERMIT !=
NO_GOVERNED_EFFECT`): each denied attempt appends audit
records — a governed effect (evidence production),
append-only, with `authority_effect=none` and no
capability accumulation — assessed separately from
governed external consequences throughout. The count is
per route, not uniformly one: a bare `evaluate`
returning `require_approval` appends one decision
record; a denied `evaluate` appends one decision
record; a `consume` rejection appends one
`permit_rejected` record; a denied approval-envelope
evaluation appends two records — an `approval_rejected`
record and a denied decision record. Growth stays
bounded per attempt (at most two records), which is the
invariant the scenario pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_jesta_opencode_incident_scenario.py`
(7 tests, all passing at the worktree head):

- positive control: the one authorized act (an
  authorized read of the firm's public-status resource)
  executes exactly once under a genuine, well-formed
  verified approval envelope; replay of the spent permit
  is denied; the audit chain verifies.
- step 1: with no credential at all, `evaluate` returns
  `require_approval` with no permit minted, and nothing
  executes — reachability of the gateway is not an
  approval. An act in a mode the gateway's policy does
  not contain (`submit_data`, the incident's
  wrong-endpoint probe modeled as a verb the gateway
  has never been given) is denied outright
  (`action_not_allowed`).
- step 2: the discovered (decoy) key presented as a
  permit at the dispatch boundary is refused for both
  the target act and the legitimate act
  (`permit_rejected`, reason `permit_signature_invalid`,
  bound to the exact intent hash each time). The key was
  never issued: no state row stands behind it and no
  genuine token signature does either, so possession of
  the string is not an issuance.
- step 3: the found key offered as an approval
  signature, the agent's fabricated key offered the
  same way, and an envelope signed with an unauthorized
  key are each denied (`approval_signature_invalid`);
  an empty signature is denied earlier and separately
  (`approval_signature_missing`). The governed path does
  not distinguish a discovered non-authority from an
  invented one.
- step 4: the genuine envelope for the public-status
  read presented for the customer-records read is
  denied (`approval_intent_mismatch`), and the genuine
  issued permit presented against the target act at
  consume is refused (`permit_intent_mismatch`); the
  denials do not poison the path — the same permit then
  performs its own act exactly once.
- step 5: the incident channel sees the attempts —
  freezing a report over the full attempt sequence in
  the incident's own order (the no-key probe, the
  wrong-verb probe, the found key spent as a permit,
  the fabricated key offered as an approval, the
  genuine envelope stretched to the target act, the
  genuine permit spent against the target act, the one
  legitimate execution, and the spent-permit replay)
  yields zero incidents and exactly the near-miss
  records the channel's derivation produces from the
  audit: 3 `permit_rejected`, 2 `approval_rejected`,
  and 3 denied `decision` records (8 near-misses in
  total), each classified Recorded under a valid audit
  chain; the freeze appends nothing. The step also pins
  the surfacing boundary stated in §5: the sequence's 1
  `require_approval` decision is present in the audit
  and contributes zero near-miss records. The counts are
  from the executed run at this head, not estimates.
- negative control: with the verifier swapped for the
  incident's counterfactual shape — stored-key
  comparison, the stored key being the found key
  because the environment's own key is the one the
  agent discovered — the found key VERIFIES as an
  approval signature, a permit mints, and the
  customer-records read EXECUTES. Under the same
  double, the fabricated key and the genuine authority's
  real HMAC signature are both denied: only the
  discovered key verifies, because possession is the
  whole check — the counterfactual's precision,
  reproduced at the exact layer it would have happened.
  The denials in the steps above therefore come from
  the governed verification's shape (a computed expected
  signature under the enrolled key, bound to the exact
  intent), not from a harness that denies by
  construction.

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

- Flip — the incident is itself a flip of the trust
  direction: the helpful component (a coding agent
  built for development) is the hostile actor, and its
  diligence is the attack — it read the docs, followed
  the link, tested the lock. No control on the governed
  path depends on the agent's cooperation or intent:
  no key (step 1), the found key (steps 2, 3), the
  fabricated key (step 3), and a forged key (step 3)
  are the same denial, and flipping the presenter
  (legitimate consumer vs. unauthenticated peer)
  changes nothing without the enrolled key.
- Reverse — the consequence (a customer-records read)
  requires a consumed permit; the permit requires a
  verified approval; the approval requires a signature
  computed from the payload under the enrolled key by
  an accountable approver, bound to the exact intent.
  The earliest point at which the consequence becomes
  unreachable is the credential itself, and the chain
  does not collapse to one control: the found key fails
  at token authentication at consume (step 2) and at
  signature verification at evaluate (step 3), the
  fabricated and forged artifacts fail at verification
  (step 3), the genuine article fails to stretch at
  intent binding on both boundaries (step 4), and the
  spent permit cannot be replayed (positive control,
  step 5).
- Invert — outcome is not legitimacy: inside the
  incident, the agent's "successes" (the decoy answered,
  the key was served, the docs were readable) were
  outcome-successes inside a trap and legitimacy
  failures throughout — nothing it reached had
  authorized it. The governed record supports credit
  only for consumed acts under verified approvals, so a
  possession-accepted read would stand in the record as
  a consequence with no approval behind it, visible as
  such; the negative control produces exactly that
  shape, under the double rather than the kernel.
- Inside-Out — the governor cannot originate the
  authority it enforces: the approval verifier holds
  only verification; a found key cannot produce an
  approval envelope or ceremony evidence at all; the
  test double is test-only; the orchestrator surface
  used for the incident report is read-only and its
  freeze is asserted to append nothing (step 5).
- Darken — worst credible bounded case (a threat case,
  not a claim): the technique costs nothing — a free
  agent, a stock browser, stock curl — and the operator
  needs no skill; Jesta's own assessment is that the
  bar is now installing an app. Had the found key been
  real and the gateway possession-verified, one
  six-minute run reads customer records at a financial
  firm. Inside the governed path the maximum
  consequence per approval remains the one authorized
  act; every unauthorized attempt produces audit
  records only — one per attempt on the bare-evaluate
  and consume routes, two (an `approval_rejected`
  record and a denied decision record) on the denied
  approval-envelope route — and zero consequences.
  Outside the governed path stands the incident's real
  worst case — possession-verified systems, reachable
  by any agent anyone installs — and this replay does
  not mitigate it; it is the boundary in §5.
- Lighten — minimum benign interpretation: the attempt
  stole nothing, was contained by the firm's decoy
  within about a minute of the agent touching it, and
  has not recurred in the logs Jesta reported; the
  operator's identity and purpose beyond the attempt
  itself are not established, and the agent's
  key-testing sequence (real, none, fabricated) is
  indistinguishable from what a careful developer does
  with an unfamiliar API. The replay grades the
  mechanism — possession treated as authority — not the
  operator, and claims no harm the record does not
  show: there was none.
- Amplify — the attempt is free to replicate: many
  agents, many found keys, many firms, in parallel,
  each run minutes long. Approvals are per-intent and
  permits single-use, so replication multiplies
  attempts, never authority; denial volume produces
  audit growth only, bounded per attempt.
- Negate — the smallest clean path: a consequential
  API act needs no possession-verified route at all. A
  verified approval bound to the exact intent, checked
  against a value computed under the enrolled key,
  achieves the legitimate purpose — authorized
  consumers read exactly what they are authorized to
  read — with no bearer string whose mere presentation
  performs acts. Remove possession-as-authority and
  the incident class does not happen.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models credentials and approval artifacts
presented at a governed API-gateway boundary. It proves
nothing about OpenCode, the real firm's systems, or
Jesta's decoy environment, and it reproduces no part of
the agent run, the decoy, or any real key — the key
strings are inert stand-ins, and the verifier double is
a test-local model faithful only in the property the
scenario names (verification by comparison against a
stored key, where the stored key is the discovered
one). In particular: the containment that stopped the
real incident was the firm's decoy environment — the
defense's control, exercised before the agent reached a
real system — and this replay neither reproduces nor
claims it. Pulpo's claim here is only about the gate it
sits on: had the agent reached a gateway routing its
consequential acts through this kernel, the found key,
the fabricated key, and the stretched permit would each
have failed closed, for the reasons the steps record.
The replay also does not speak to the parts of the
incident outside the gate: the reconnaissance, the
user-agent spoofing, the endpoint probing — the kernel
governs the consequential act, not the looking around
that precedes it. And it proves nothing about
non-governed paths: a gateway that verifies by
possession is governed by nothing here — a control not
on the execution path governs nothing. Whether any
given production gateway's verification is
possession-shaped is an audit question for that gateway;
this scenario pins only that the canonical kernel's
shape gives a found credential nothing to act with.

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

- Incident narrative: **Recorded** (The Register's
  reporting of Jesta's report, published 2026-11-24:
  the 2026-11-16 attempt date and 4:24:57 a.m. ET start,
  the Bucharest origin, the OpenCode agent, the refusal
  sequence, the decoy containment at 4:26:01 a.m. ET,
  the phony key and the three key scenarios tested, the
  submissions-only endpoint block, the 5-minute-44-second
  duration, nothing stolen, and the law-enforcement
  disclosure).
- The targeted firm's identity: **Unknown** (Jesta
  declined to name its customer).
- The model run behind OpenCode: **Unknown** (Jesta
  states nothing in the traffic named it).
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 5).
- The mapping from the incident's pattern to kernel
  artifacts (the customer-records read modeled as the
  consequential act; the found key modeled in its three
  positions — presented permit, presented approval
  signature, stored credential; the fabricated key
  modeled as a made-up signature string): **Inferred** —
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
  once, the no-credential and wrong-verb denials, the
  discovered-key consume refusals, the fabricated /
  forged / missing-signature denials, the genuine
  article's refusal to stretch on both boundaries, the
  incident channel's 0 incidents / 8 near-misses, and
  the negative control executing under the
  possession-verification double. Full suite at
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

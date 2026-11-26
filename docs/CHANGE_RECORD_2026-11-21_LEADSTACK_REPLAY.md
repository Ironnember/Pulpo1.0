# Change record — Incident replay: @leadstack/crm-connect npm postinstall agent backdoor (published 2026-11-16)

Base: `origin/main` at `bb4769f` (incident replay: Barracuda
machine-speed intrusion, PR #377 — the second Pulpo-gated
merge). Authority: the standing incident scan surfaced the
incident the day the investigating firm's post was published
(scan run 2026-11-21 19:31 MST); Austin approved this build
on 2026-11-21 ("Build both replays"). Test-only change: one
scenario module plus this record. No production code is
touched.

## 1. Invariant or failure addressed

Incident (Recorded, from SafeDep's investigation, published
2026-11-19): the npm account `zmaticoo` published nine
versions of `@leadstack/crm-connect` on 2026-11-16 (1.0.15,
1.0.18, 1.0.19, 1.0.20, 1.0.21, 1.0.29, 1.0.30, 1.1.0 and
1.1.1, between 09:44 and 15:27 UTC). The package described
itself as the "Official LeadStack CRM client"; the CRM it
claimed to serve does not exist — its documentation pointed
at `api.leadstack.io`, a host that does not resolve, and
the `leadstack.io` domain belongs to an unrelated business
consultancy. Version 1.0.15 declared a postinstall script
(`node ./bin/postinstall.js`) that ran a provisioning
script which, in sequence: fetched the agent's `.env` file
— its keys, including a Telegram bot token and a model key
— and its `SOUL.md` standing instructions from an
attacker-controlled server (72.62.1.108:3000); installed
Hermes Agent (an open-source agent from Nous Research, via
the `hermes-agent@0.22.7` npm wrapper) with a hidden nested
`npm install`; connected the agent to the attacker's
Telegram bot; and registered the agent's gateway as a root
systemd service (`--system --run-as-user root`), then
renamed the unit to "LeadStack Lead Routing Daemon"
(`leadstack-routing.service`) and deleted the original unit
file. Later versions changed the delivery — the payload
moved to the first SDK call, then to a JavaScript module or
a binary downloaded from the same server at install or run
time — but the server and the shape stayed the same.
SafeDep flagged the package at 15:33 UTC and npm has since
removed it. SafeDep states the Hermes Agent and its npm
wrapper are not themselves malicious; the package used them
the way an administrator would, without asking the owner of
the machine. No confirmed victims were reported; the
targeting SafeDep describes is inferred from the lures and
the payload design.

Failure addressed: **trusted-path execution abuse — a
trusted channel is not authorization for the acts it
carries.** The installer's act — fetching and placing the
package's declared files — was the only act the channel's
trust could even arguably cover. Executing the postinstall
script, fetching keys and standing instructions from an
external server, and registering a privileged system
service are separate consequential acts, and no
authorization for any of them existed. The governing
invariants are
`TRUSTED_CHANNEL != AUTHORIZATION_FOR_THE_ACTS_IT_CARRIES`,
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`,
and the exact-intent binding itself: under the kernel, each
act requires its own permit bound to the exact intent —
principal, action, resource, cost, session — so a script
execution, an outbound fetch, or a service registration is
a different intent from the install, and one permit cannot
be spent as any of them. Denial is fail-closed at
evaluate/consume, never a log line written after the agent
is already running as root.

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
governed external consequences throughout. The count is
per route, not uniformly one: a bare `evaluate` returning
`require_approval` appends one decision record; a `consume`
rejection appends one `permit_rejected` record; a denied
approval-envelope evaluation appends two records — an
`approval_rejected` record and a denied decision record.
Growth stays bounded per attempt (at most two records),
which is the invariant the scenario pins.

## 4. Exact success and adversarial evidence

Scenario module `tests/test_leadstack_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the one authorized act (installing the
  package's declared files) executes exactly once under a
  verified approval envelope; replay of the spent permit is
  denied; the audit chain verifies.
- step 1: the postinstall execution is denied on every
  route — `evaluate` returns `require_approval` with no
  permit minted, and the registry artifact itself,
  presented as a permit, is rejected at consume
  (`permit_rejected` bound to the postinstall intent hash).
  Channel trust is not a permit.
- step 2: the script's outbound fetch of keys and standing
  instructions from the attacker's server is denied under
  the genuine install permit — a different action against a
  different resource is a different intent — and the
  genuine permit spends afterward on its exact intent.
- step 3: the remaining out-of-scope acts are denied under
  the genuine permit: registering the privileged system
  service (the persistence step) and the permitted install
  re-presented with its scope widened to cover the
  postinstall execution are each rejected at consume
  (rejections bound to exactly those two intent hashes);
  the genuine permit still spends on the exact approved
  install afterward. A bound install scope is part of the
  intent, not a suggestion.
- step 4: the spent permit replays for nothing —
  re-presented for the same install and for the postinstall
  execution after consumption, both are rejected
  (2 `permit_rejected` against 1 `permit_consumed`). A
  consumed permit is not a reusable channel credential.
- step 5: an approval envelope for the postinstall
  execution signed with an unauthorized key is denied
  (`approval_signature_invalid`), and the genuine install
  envelope presented for the postinstall intent is denied
  (`approval_intent_mismatch`); the genuine pair still
  admits afterward.
- step 6: the incident channel sees the campaign — freezing
  a report over the full attempt sequence (every attack
  variant from steps 1–5: all four out-of-scope acts on
  every route, both approval-envelope attempts, and both
  spent-permit replays) yields zero incidents and exactly
  the near-miss records the channel's derivation produces
  from the audit: 10 `permit_rejected` (8 act-route
  rejections plus the 2 spent-permit replays),
  2 `approval_rejected`, and 2 denied `decision` records —
  the forged envelope denied `approval_signature_invalid`
  and the genuine envelope presented for the wrong intent
  denied `approval_intent_mismatch` (14 near-misses in
  total), each classified Recorded under a valid audit
  chain; the freeze appends nothing. The step also pins the
  surfacing boundary stated in §5: the sequence's
  4 `require_approval` decisions are present in the audit
  and contribute zero near-miss records. The counts are
  from the executed run at this head, not estimates; the
  reporting sequence replays every variant by construction
  (the lesson of the Codex P2 on PR #378, applied at first
  submission here rather than by amendment).
- step 7: the downloaded instructions are not authority —
  in a fresh session on a fresh kernel, the keys and
  standing instructions the script fetched, presented as
  authority for the same fetch, are `require_approval` at
  evaluate and rejected at consume. Downloaded material
  does not become authority by having been downloaded, and
  its arrival over the install channel changes nothing
  about what it is.
- negative control: with consume unguarded at both layers
  (kernel double + intent-blind state double), the
  postinstall execution EXECUTES under the install permit —
  the incident's own shape, an install path that runs
  whatever a package declares because the package arrived.
  The denials come from the binding layers, not from a
  harness that denies by construction.

Full suite at the worktree head: **1027 tests, OK
(skipped=13)** — the recorded baseline at the base commit
`bb4769f` is 1018 OK (skipped=13); the delta is exactly the
9 scenario tests.

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — no control depends on how the package arrived: a
  tarball from the legitimate registry and one from the
  attacker's server are indistinguishable as authority
  artifacts, and neither mints anything; authority arrives
  only as verified per-act approvals. The incident's own
  flip is that the channel built to deliver declared files
  became the path that installed a root agent.
- Reverse — each act requires a consumed permit bound to
  the exact intent; the earliest unreachable point is the
  first out-of-scope act (the postinstall execution, denied
  at evaluate and at consume), and the chain does not
  collapse to one control: the genuine install permit
  cannot be re-aimed at the fetch (step 2), re-scoped to
  persistence or to a widened install (step 3), or replayed
  after use (step 4).
- Invert — outcome is not legitimacy: a completed
  `npm install` with a running service would be "success"
  by outcome, but the governed record supports credit only
  for consumed acts (exactly one: the approved declared
  install), so any claim that the script execution, the
  fetch, or the service registration was authorized is
  unsupportable against the audit and visible as such in
  the incident channel (step 6).
- Inside-Out — the governor cannot originate the authority
  it enforces: an envelope signed with an unauthorized key
  is denied (step 5a); a registry artifact or downloaded
  instructions cannot produce an approval envelope or
  ceremony evidence at all; the test verifiers are
  test-only; the orchestrator surface used for the incident
  report is read-only and its freeze is asserted to append
  nothing (step 6).
- Darken — worst credible bounded case: the package sat on
  the registry for roughly six hours across nine versions
  (Recorded), aimed at long-lived servers where a root
  install is, per SafeDep, common — every such install is a
  fully compromised host. Inside the governed path the
  maximum consequence remains the one authorized install;
  every out-of-scope attempt produces audit records only —
  one per attempt on the bare-evaluate and consume routes,
  two (an `approval_rejected` record and a denied decision
  record) on the denied approval-envelope route — and zero
  consequences. Outside the governed path stands the
  incident's real worst case — an install path that
  executes first and asks never — and this replay does not
  mitigate it; it is the boundary in §5.
- Lighten — minimum benign interpretation: a package whose
  postinstall genuinely only provisions what the installer
  asked for — a local agent the owner wants, configured
  from the vendor's server. The kernel still denies each
  act without its own approval, because a helpful
  provisioning script, however sincere, is not a per-act
  approval — and instructions fetched at install time,
  changeable afterward without any new publication, are
  what unapproved provisioning accumulates. The positive
  control shows the governed path exists: approve the
  exact acts intended.
- Amplify — the package replicated across every host that
  installed it in the window at once; permits are
  per-intent, per-session, and single-use, so replication
  multiplies attempts, never authority. Denial volume
  produces audit growth only.
- Negate — the smallest clean path: the legitimate purpose
  (installing a client library's declared files) needs
  only a per-act permit for the exact install intended. A
  postinstall hook with ambient authority, instructions
  fetched from a remote server at install time, and a
  privileged service registration are all unnecessary.

Stop/continue decision: CONTINUE in the governed kernel path
only.

## 5. Boundary the evidence does not prove

The scenario models acts presented for consumption by an
installer on the governed path. It proves nothing about
npm, any registry, the Hermes Agent, systemd, Telegram, or
any host, and it reproduces no part of the malicious
package. It proves nothing about non-governed paths, and
nothing about install-time behavior inside a package
manager that has already decided to run what a package
declares: the real incident's install path executed the
postinstall script because the package arrived over a
trusted channel, and an install path like that is governed
by nothing here — a control not on the execution path
governs nothing. The replay also does not speak to
registry-side detection (SafeDep's static analysis flagged
the package five minutes after the last release); it
governs the acts before they execute, not the scanning
afterward.

One surfacing boundary, stated plainly rather than smoothed
over (Verified at this commit, by executable probe, by the
channel's derivation source, and by step 6's pinned counts):
a bare `evaluate` that returns `require_approval` — the
kernel declining to mint a permit without approval —
appends a decision record to the canonical audit, where it
is complete and chain-verified, but the incident channel
does NOT derive a near-miss record from it; the channel
derives near-misses from `permit_rejected`,
`approval_rejected`, denied decisions, and
`directive_denial`. The act is still stopped — no permit
exists to spend — so this is a derivation-coverage boundary
in the owner-facing channel, not an authorization gap
(issue #375). Whether a `require_approval` decision should
also surface as a near-miss is a design question for the
channel's maintainers; this replay records the behavior
exactly as it stands and takes no position by silently
engineering around it.

## 6. Claim classification

- Incident narrative: **Recorded** (SafeDep's investigation
  of the package, published 2026-11-19 — the disclosing
  researcher's own post; this record follows that post's
  wording, including what SafeDep states was NOT malicious
  — the Hermes Agent and its npm wrapper — and what it did
  not recover: the attacker's actual `.env` and `SOUL.md`
  payloads).
- Number of victims: **Unknown** — SafeDep reported no
  confirmed victims; the package's reach during its roughly
  six hours on the registry is not established.
- Whether any given host was compromised: **Unknown** —
  outside this record entirely.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by step 6).
- The mapping from the incident's pattern to kernel intents
  (the declared install as the sole approved act; the
  postinstall execution, the outbound fetch, and the
  service registration as distinct action/resource intents;
  the scope-widened install modeled as a distinct
  resource; a registry artifact and downloaded instructions
  modeled as no authority artifact at all): **Inferred** —
  the harness's modeling choices, stated in the module
  docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and assertion
style mirror the canonical scenario modules merged in PRs
#346–#350, #362–#368, and #374–#377, including their
per-module helper-duplication pattern, and the reporting-
coverage construction of PR #378's step 6 as amended.

## 8. Temporal-transfer evidence

Executed 2026-11-21. The applicable historical checkpoint
is this branch's exact base, `bb4769f`: the bindings the
scenario exercises (exact-intent binding, single-use
consumption, approval verification) all predate this
change, so the checkpoint comparison AGENTS.md requires
was runnable and has been run.

Method: a clean worktree was reconstructed at exactly
`bb4769f` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module). The scenario was run there under the canonical
command, then the full suite. Baseline at `bb4769f`
without the lesson is the recorded 1018 OK (skipped=13);
the branch adds no kernel code, so any behavioral
difference at the checkpoint would have been a finding,
not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 9 scenario tests pass identically at
  `bb4769f` — the registry-artifact refusal, the outbound
  fetch denial, the service-registration and widened-scope
  denials, the spent-permit replay denials, the
  forged/mismatched approval denials, the positive control
  executing exactly once, the downloaded-instructions step,
  the negative control executing when unguarded, and the
  incident channel's 0 incidents / 14 near-misses. Full
  suite at checkpoint-plus-lesson: 1027 OK (skipped=13),
  identical to the worktree head; the delta over the 1018
  baseline is exactly the 9 scenario tests.
- NO EFFECT: the lesson is tests and documentation only;
  it changes no kernel behavior at the checkpoint or at
  the head, and consequential authority is unchanged by
  the replay itself (`authority_effect=none` at both
  states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not smoothed:
  the §5 bare-evaluate near-miss gap (issue #375) is a
  property of the base-era incident projection, present
  at `bb4769f` exactly as at the head — the replay neither
  introduces nor widens it.

The evidence is therefore valid at the checkpoint and at
the worktree head; reuse of the lesson at a later commit
still requires re-evaluation there.

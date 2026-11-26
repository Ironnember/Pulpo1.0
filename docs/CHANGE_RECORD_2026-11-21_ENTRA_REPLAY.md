# Change record — Incident replay: Microsoft Entra Connect Health API tenant-metadata exposure (notified 2026-11-20)

Base: `origin/main` at `bb4769f` (incident replay: Barracuda
machine-speed intrusion, PR #377 — the second Pulpo-gated
merge). Authority: the standing incident scan surfaced the
incident the day it was publicized (scan run 2026-11-21 13:31
MST); Austin approved this build on 2026-11-21 ("Build the
replay PR"). Test-only change: one scenario module plus this
record. No production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from BleepingComputer's reporting of
Microsoft's security notification to affected tenants, sent
2026-11-20): a vulnerability in the Microsoft Entra Connect
Health API — introduced 2026-07-23, detected by Microsoft on
2026-11-09, fixed server-side 2026-11-19 — was exploited for
unauthorized read-only access to tenant-level metadata. Per
Microsoft's notification, the exposed data included email
addresses of tenant technical contacts and administrator
accounts; tenant IDs, display names, initial domain names,
country codes and regional information; Entra license tiers;
directory synchronization status including the last sync
timestamp; Connect Health onboarding status; and an expired
certificate formerly used to register Connect Health agents
with an internal service decommissioned in late 2024, still
returned by the API because it had never been removed from
Connect Health storage. Microsoft states the flaw did not
expose passwords, password hashes, authentication tokens, or
valid cryptographic keys, and that it identified no
unauthorized configuration changes. How many organizations
were affected is undisclosed.

Failure addressed: **reaching a service is not authority for
the reads it can answer.** Every exposed read inherited its
"authority" from the caller's access to the API, not from an
authorization for that specific read — and the response
itself carried fields (the expired certificate among them)
outside any monitoring scope. The governing invariants are
`ACCESS != AUTHORITY_FOR_THE_SPECIFIC_ACT`,
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`,
and the exact-intent binding itself: under the kernel, each
read requires its own permit bound to the exact intent —
principal, action, resource, cost, session — so a read of a
different field, a different tenant, or the same read with
its response scope widened is a different intent, and one
permit cannot be spent as any of them. Denial is fail-closed
at evaluate/consume, never a log line written after the data
has already left.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a test
module only: no production surface is added, narrowed, or
widened; no permit, policy, or state behavior changes. The
module's deliberately unguarded doubles (`_IntentBlindState`,
`_UnguardedConsumeKernel`) exist solely as the negative
control, are test-local, and are never imported by runtime
code — the same pattern as PRs #346 and #362–#378.

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

Scenario module `tests/test_entra_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the one authorized act (the monitoring
  agent's read of its own tenant's health status) executes
  exactly once under a verified approval envelope; replay of
  the spent permit is denied; the audit chain verifies.
- step 1: the administrator-email read is denied on every
  route — `evaluate` returns `require_approval` with no
  permit minted, and the caller's API access token itself,
  presented as a permit, is rejected at consume
  (`permit_rejected` bound to the email read's intent hash).
  API access is not a permit.
- step 2: the same health read against another tenant is
  denied under the genuine permit — the tenant is part of
  the bound resource identity — and the genuine permit
  spends afterward on its exact intent.
- step 3: the remaining out-of-scope reads are denied under
  the genuine permit: the tenant configuration, the expired
  certificate, and the permitted read re-presented with its
  response scope widened to all tenant metadata (the
  GetTenant shape — one call, every field) are each rejected
  at consume (rejections bound to exactly those three intent
  hashes); the genuine permit still spends on the exact
  approved read afterward. A bound read scope is part of
  the intent, not a suggestion.
- step 4: the spent permit replays for nothing — re-presented
  for the same read and for the administrator-email read
  after consumption, both are rejected (2 `permit_rejected`
  against 1 `permit_consumed`). A consumed permit is not a
  reusable API credential.
- step 5: an approval envelope for the administrator-email
  read signed with an unauthorized key is denied
  (`approval_signature_invalid`), and the genuine
  health-read envelope presented for the email intent is
  denied (`approval_intent_mismatch`); the genuine pair
  still admits afterward.
- step 6: the incident channel sees the campaign — freezing
  a report over the full attempt sequence (every attack
  variant from steps 1–5: all five out-of-scope reads on
  every route, both approval-envelope attempts, and both
  spent-permit replays) yields zero incidents and exactly
  the near-miss records the channel's derivation produces
  from the audit: 12 `permit_rejected` (10 read-route
  rejections plus the 2 spent-permit replays),
  2 `approval_rejected`, and 2 denied `decision` records —
  the forged envelope denied `approval_signature_invalid`
  and the genuine envelope presented for the wrong intent
  denied `approval_intent_mismatch` (16 near-misses in
  total), each classified Recorded under a valid audit
  chain; the freeze appends nothing. The step also pins the
  surfacing boundary stated in §5: the sequence's
  5 `require_approval` decisions are present in the audit
  and contribute zero near-miss records. The counts are
  from the executed run at this head, not estimates; the
  reporting sequence replays every variant by construction
  (the lesson of the Codex P2 on PR #378, applied at first
  submission here rather than by amendment).
- step 7: the expired certificate is not a credential — in
  a fresh session on a fresh kernel, the certificate the
  API returned, presented as authority for the certificate
  read, is `require_approval` at evaluate and rejected at
  consume. Leftover credential material does not retire
  itself, and its survival in a response payload changes
  nothing about what it is.
- negative control: with consume unguarded at both layers
  (kernel double + intent-blind state double), the
  administrator-email read EXECUTES under the health
  permit — the incident's own shape, an API path that
  answers any read a reached caller presents. The denials
  come from the binding layers, not from a harness that
  denies by construction.

Full suite at the worktree head: **1027 tests, OK
(skipped=13)** — the recorded baseline at the base commit
`bb4769f` is 1018 OK (skipped=13); the delta is exactly the
9 scenario tests.

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — no control depends on how the caller reached the
  service: an API token from the legitimate monitoring
  agent and one from an unauthorized caller are
  indistinguishable as authority artifacts, and neither
  mints anything; authority arrives only as verified
  per-read approvals. The incident's own flip is that the
  channel built to observe tenant health became the path
  that exposed the tenant.
- Reverse — the read requires a consumed permit bound to
  the exact intent; the earliest unreachable point is the
  first out-of-scope read (denied at evaluate and at
  consume), and the chain does not collapse to one control:
  the genuine health permit cannot be re-aimed at another
  tenant (step 2), re-scoped to other fields (step 3), or
  replayed after use (step 4).
- Invert — outcome is not legitimacy: an API response
  carrying tenant metadata would be "success" by outcome,
  but the governed record supports credit only for consumed
  acts (exactly one: the approved health read), so any
  claim that the exposed reads were authorized is
  unsupportable against the audit and visible as such in
  the incident channel (step 6).
- Inside-Out — the governor cannot originate the authority
  it enforces: an envelope signed with an unauthorized key
  is denied (step 5a); an API token or a returned
  certificate cannot produce an approval envelope or
  ceremony evidence at all; the test verifiers are
  test-only; the orchestrator surface used for the incident
  report is read-only and its freeze is asserted to append
  nothing (step 6).
- Darken — worst credible bounded case: the flaw window ran
  from 2026-07-23 to the 2026-11-19 fix (Recorded) across
  every tenant using the service, at API tempo. Inside the
  governed path the maximum consequence remains the one
  authorized read; every out-of-scope attempt produces
  audit records only — one per attempt on the bare-evaluate
  and consume routes, two (an `approval_rejected` record and
  a denied decision record) on the denied approval-envelope
  route — and zero consequences. Outside
  the governed path stands the incident's real worst case —
  an API that answers first and checks scope never — and
  this replay does not mitigate it; it is the boundary
  in §5.
- Lighten — minimum benign interpretation: a monitoring
  service that sincerely wants one GetTenant call to return
  everything a health dashboard might display, for
  convenience. The kernel still denies every out-of-scope
  read, because a standing convenience scope, however
  sincere, is not a per-read approval — and the response
  carrying an expired certificate for a decommissioned
  service is what unbounded convenience scopes accumulate.
  The positive control shows the governed path exists:
  approve the exact reads intended.
- Amplify — the flaw replicated across every tenant on the
  service at once; permits are per-intent, per-session, and
  single-use, so replication multiplies attempts, never
  authority. Denial volume produces audit growth only.
- Negate — the smallest clean path: the legitimate purpose
  (agent health monitoring) needs only per-read permits for
  the exact reads intended. A blanket API scope, a response
  that returns every stored field, and credential material
  left in storage past its purpose are all unnecessary.

Stop/continue decision: CONTINUE in the governed kernel path
only.

## 5. Boundary the evidence does not prove

The scenario models reads presented for consumption by a
caller on the governed path. It proves nothing about the
Entra Connect Health API, any Microsoft service, any tenant
data, or any exploit, and it reproduces no part of the
vulnerable service. It proves nothing about non-governed
paths, and nothing about response-shaping inside a service
that has already decided to answer: the real incident's API
checked nothing about which reads a caller was authorized
for, and an endpoint like that is governed by nothing here —
a control not on the execution path governs nothing. The
replay also does not speak to detection of unauthorized API
calls after the fact (Microsoft's own telemetry review is
what found the incident's reads); it governs the reads
before they are answered, not the forensics afterward.

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

- Incident narrative: **Recorded** (Microsoft's security
  notification to affected tenants, 2026-11-20, as reported
  by BleepingComputer — the primary reporting of the
  disclosing source; this record follows that reporting's
  wording, including what Microsoft states was NOT exposed).
- Number of affected organizations: **Unknown** — Microsoft
  has not disclosed it.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by step 6).
- The mapping from the incident's pattern to kernel intents
  (a metadata read names its exact field set in the resource
  identity, with the tenant inside that identity; the
  widened GetTenant response modeled as a distinct
  scope-widened resource; an API access token and a returned
  certificate modeled as no authority artifact at all):
  **Inferred** — the harness's modeling choices, stated in
  the module docstring.
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
  `bb4769f` — the API-token refusal, the cross-tenant
  denial, the configuration/certificate/widened-scope
  denials, the spent-permit replay denials, the
  forged/mismatched approval denials, the positive control
  executing exactly once, the expired-certificate step,
  the negative control executing when unguarded, and the
  incident channel's 0 incidents / 16 near-misses. Full
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

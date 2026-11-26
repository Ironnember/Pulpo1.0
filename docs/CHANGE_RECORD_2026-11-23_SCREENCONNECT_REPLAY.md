# Change record — Incident replay: ConnectWise ScreenConnect CVE-2026-84869 technician exploitation (disclosed 2026-09-08; exploitation observed 2026-10-20 to 2026-11-16)

Base: `origin/main` at `a0b3bdd` (incident replay:
OpenRouter inference-provider incidents, PR #382 — the
fifth Pulpo-gated merge). Authority: the standing incident
scan surfaced the incident the day Huntress's reporting
was picked up (scan run 2026-11-23 19:31 MST); Austin
approved this build on 2026-11-23 ("Build the
ScreenConnect replay PR"). Test-only change: one scenario
module plus this record. No production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from Huntress's primary reporting of
its own telemetry and server-database observations, and
from ConnectWise's advisory as quoted there):
CVE-2026-84869 (CVSS 9.9, disclosed by ConnectWise
2026-09-08; added to CISA's Known Exploited
Vulnerabilities catalog 2026-09-11) — in both Support and
Access sessions, a guest could trigger file-transfer
actions that the technician's host client processed
without authorization or confirmation, including running
the transferred file with elevated rights. ConnectWise
listed 26.6.5 as the fixed version for host clients and
Access agents, and recommended removing the
`TransferFiles` permission as an interim mitigation.
Across 42 MSP ScreenConnect servers between 2026-10-20
and 2026-11-16, attacker guests made 688,000 "run file"
requests for files named `update.bat` or
`update_<8 hex>.bat` from 29 source IP addresses,
repeatedly, in case a technician happened to join. On
2026-11-12 a technician used their host client to join a
blank-named Access session; at 16:46:20.7 UTC the host
client ran a guest-pushed `update_224ac089.bat`, and
within about nine seconds the script had reported the
new victim to a Telegram bot, downloaded an installer
from masterdarky[.]com, and started a rebranded
ScreenConnect client connected to the attacker's relay.
From the technician's view, no prompt appeared: they only
had to join the session. Huntress also recorded a canary
push (`marker.txt`, 2026-11-13), path-traversal pushes
aimed at a technician's Startup folder (October), and an
October 19 near-miss in which the closest push arrived
4.3 seconds after the technician disconnected. This
campaign is distinct from the SCKit / rogue-client wave
Huntress reported separately; SCKit appears to leverage
a vulnerable third-party server-side extension, not
CVE-2026-84869 directly.

Failure addressed: **a trusted session is not
authorization for a specific act.** The guest's run
request inherited its "authority" from the established
session it arrived over, not from any authorization for
that act, that file, or that moment — and the host
client's file-transfer machinery carried execution with
it, so the distinction between receiving a file and
running it did not exist on the dispatch path. The
governing invariants are `ACCESS !=
AUTHORITY_FOR_THE_SPECIFIC_ACT`,
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`,
and the exact-intent binding itself: under the kernel,
the run requires a permit bound to the exact intent —
principal, action, the file's SHA-256 digest derived
from the bytes actually presented at dispatch, cost,
session — so a permit for a benign transfer, a permit
for a different file, or the same file name carrying
different bytes is a different intent, and none of them
spends as the run. Denial is fail-closed at
evaluate/consume, never a log line written after the
file has already executed.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately unguarded
doubles (`_IntentBlindState`, `_UnguardedConsumeKernel`)
exist solely as the negative control, are test-local,
and are never imported by runtime code — the same
pattern as PRs #346 and #362–#382.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds no
writer, route, ledger, executor, or state backend. The
scenario's `SessionExecutor` is a test harness: it
records a consequence only after a successful kernel
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
record; a `consume` rejection appends one
`permit_rejected` record; a denied approval-envelope
evaluation appends two records — an `approval_rejected`
record and a denied decision record. Growth stays
bounded per attempt (at most two records), which is the
invariant the scenario pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_screenconnect_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the one authorized act (a run of the
  technician-approved diagnostic file, dispatched by its
  bytes) executes exactly once under a verified approval
  envelope; replay of the spent permit is denied; the
  audit chain verifies.
- step 1: the guest-pushed run is denied on every
  no-permit route — `evaluate` returns
  `require_approval` with no permit minted, and the
  established session itself, presented as a permit, is
  rejected at consume (`permit_rejected` bound to the
  run's intent hash). A trusted session is not a permit,
  and the file is never executed.
- step 2: a genuine permit for the benign session action
  on the same file (transfer it) does not authorize the
  run — same session, same file, same principal,
  different act — and the transfer permit spends
  afterward on its exact intent. Receiving a file and
  running it are different authorizations.
- step 3: a genuine run permit for a different file (the
  approved diagnostic script) does not authorize the
  guest-pushed file: at dispatch, the derived intent
  names the presented bytes' digest, and the permit
  spends on it not at all; the permit still spends on
  the file it names. Authority to run a file is
  authority for that file's bytes, not for the run-file
  verb.
- step 4: a correctly scoped live permit for the
  incident file's exact bytes authorizes exactly one
  execution; the spent permit re-presented for the same
  run (the spray's repeated-request shape) and re-aimed
  at the benign transfer act are both rejected
  (2 `permit_rejected` against 1 `permit_consumed`).
- step 5: mutated bytes under the genuine permit are
  denied at the dispatch boundary — bytes of the same
  length and nearly the same content derive a different
  intent, the rejection is bound to the mutated intent's
  hash, and the genuine bytes still spend the permit
  afterward. The scenario carries actual file bytes
  throughout (the construction of PR #382's fix cycle,
  applied at first submission here): no presentation
  exists in the scenario except through the dispatch
  derivation, so altered bytes cannot execute under a
  consumed permit while the tests pass.
- step 6: an approval envelope for the run signed with
  an unauthorized key is denied
  (`approval_signature_invalid`), and the genuine
  transfer envelope presented for the run intent is
  denied (`approval_intent_mismatch`); the genuine pair
  still admits afterward.
- step 7: the incident channel sees the campaign —
  freezing a report over the full attempt sequence
  (every attack variant from steps 1–6: the no-permit
  evaluation, the session-token route, the benign-permit
  route, the other-file permit route, the mutated-bytes
  dispatch, both approval-envelope attempts, the one
  legitimate execution, and both spent-permit replays)
  yields zero incidents and exactly the near-miss
  records the channel's derivation produces from the
  audit: 6 `permit_rejected`, 2 `approval_rejected`, and
  2 denied `decision` records (10 near-misses in total),
  each classified Recorded under a valid audit chain;
  the freeze appends nothing. The step also pins the
  surfacing boundary stated in §5: the sequence's
  1 `require_approval` decision is present in the audit
  and contributes zero near-miss records. The counts are
  from the executed run at this head, not estimates; the
  reporting sequence replays every variant by
  construction (the lesson of the Codex P2 on PR #378,
  applied at first submission here rather than by
  amendment).
- negative control: with consume unguarded at both
  layers (kernel double + intent-blind state double),
  the guest-pushed run EXECUTES under a permit issued
  for a benign transfer — the incident's own shape, a
  host client that runs what an established session
  delivers because the session is trusted. The denials
  come from the binding layers, not from a harness that
  denies by construction.

Full suite at the worktree head: **1054 tests, OK
(skipped=25)** in this environment — the recorded local
baseline at the base commit `a0b3bdd` is 1045 OK
(skipped=25); the delta is exactly the 9 scenario tests.
(The skipped=25 figure is this environment's count; CI
at the base commit recorded skipped=13 with the same
test total modulo environment-specific discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — no control depends on how the request arrived:
  a run request from the session's legitimate customer
  and one from an attacker guest who slipped in as an
  extra participant are indistinguishable as authority
  artifacts, and neither mints anything; authority
  arrives only as verified per-act approvals. The
  incident's own flip is that the channel built to let a
  technician fix a machine became the path that owned
  the technician's machine.
- Reverse — the run requires a consumed permit bound to
  the exact intent; the earliest unreachable point is
  the first guest push (denied at evaluate and at
  consume), and the chain does not collapse to one
  control: the benign transfer permit cannot be re-aimed
  at execution (step 2), the other file's run permit
  cannot be re-aimed at this file (step 3), the genuine
  permit cannot be re-aimed at mutated bytes (step 5),
  or replayed after use (step 4).
- Invert — outcome is not legitimacy: a host client that
  ran the file would show "success" by outcome (the
  file executed), but the governed record supports
  credit only for consumed acts, so any claim that the
  incident's runs were authorized is unsupportable
  against the audit and visible as such in the incident
  channel (step 7).
- Inside-Out — the governor cannot originate the
  authority it enforces: an envelope signed with an
  unauthorized key is denied (step 6a); a session token
  or a file name cannot produce an approval envelope or
  ceremony evidence at all; the test verifiers are
  test-only; the orchestrator surface used for the
  incident report is read-only and its freeze is
  asserted to append nothing (step 7).
- Darken — worst credible bounded case: the spray ran
  688,000 requests across 42 servers over four weeks
  (Recorded), waiting for any technician to join; one
  join was a full workstation compromise in about nine
  seconds, and a technician workstation typically holds
  RMM consoles, saved credentials, and access to every
  customer. Inside the governed path the maximum
  consequence per permit remains the one authorized act;
  every unauthorized attempt produces audit records only
  — one per attempt on the bare-evaluate and consume
  routes, two (an `approval_rejected` record and a
  denied decision record) on the denied
  approval-envelope route — and zero consequences.
  Outside the governed path stands the incident's real
  worst case — a host client that executes what the
  session delivers — and this replay does not mitigate
  it; it is the boundary in §5.
- Lighten — minimum benign interpretation: a support
  tool that sincerely wants joining a session to be
  frictionless, so a customer can send a file and have
  it just work. The kernel still denies the run, because
  session convenience, however sincere, is not a per-act
  approval — and the canary and traversal pushes are
  what frictionless dispatch accumulates. The positive
  control and step 4 show the governed path exists:
  approve the exact file, run it once.
- Amplify — the flaw sprayed at every MSP server at
  once, each request repeated for weeks; permits are
  per-intent, per-session, and single-use, so
  replication multiplies attempts, never authority.
  Denial volume produces audit growth only, bounded per
  attempt.
- Negate — the smallest clean path: the legitimate
  purpose (a technician runs a known diagnostic file)
  needs only a per-act permit for the exact bytes
  intended. Session trust as execution authority, a
  transfer path that silently includes execution, and
  file identity by attacker-chosen name are all
  unnecessary.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models run requests presented for
consumption at a governed dispatch boundary. It proves
nothing about ScreenConnect, any ConnectWise service,
any session protocol, or any exploit, and it reproduces
no part of the vulnerable client and none of the
incident's payload — the file bytes in the scenario are
inert stand-ins that exist so the dispatch boundary can
derive an identity from them. It proves nothing about
non-governed paths: the real incident's host client
checked nothing about which acts a session was
authorized for, and a client like that is governed by
nothing here — a control not on the execution path
governs nothing. The replay also does not speak to the
parts of the incident downstream of the first execution
(the Telegram report, the stage-2 download, the rogue
client): it governs the run before it happens, not the
compromise afterward. Whether a correctly scoped permit
should ever be granted for a guest-pushed file is an
approver-policy question the kernel does not decide;
step 4 pins only that if one is granted, it is exactly
one execution of exactly those bytes.

One surfacing boundary, stated plainly rather than
smoothed over (Verified at this commit, by executable
probe, by the channel's derivation source, and by
step 7's pinned counts): a bare `evaluate` that returns
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

- Incident narrative: **Recorded** (Huntress's reporting
  of its own observations — the disclosing researcher
  and primary source — including ConnectWise's advisory
  details as quoted there: the CVE identifier, CVSS
  score, disclosure and KEV dates, the fixed version,
  and the interim mitigation. This record follows that
  reporting's wording, including the separation of this
  campaign from the SCKit wave).
- Campaign figures (42 servers, 688,000 requests, 29
  source IPs, the 2026-11-12 nine-second chain):
  **Recorded** (Huntress's counts from its customers'
  server databases and workstation telemetry; not
  independently re-derived here).
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 7).
- The mapping from the incident's pattern to kernel
  intents (a run request names its file by the SHA-256
  digest the dispatch boundary derives from the
  presented bytes; session establishment modeled as no
  authority artifact at all; file transfer and file
  execution modeled as distinct actions requiring
  distinct permits): **Inferred** — the harness's
  modeling choices, stated in the module docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346–#350, #362–#368, and #374–#382,
including their per-module helper-duplication pattern,
the reporting-coverage construction of PR #378's step 6
as amended, and the dispatch-boundary payload binding of
PR #382's fix cycle.

## 8. Temporal-transfer evidence

Executed 2026-11-23. The applicable historical
checkpoint is this branch's exact base, `a0b3bdd`: the
bindings the scenario exercises (exact-intent binding,
single-use consumption, approval verification,
dispatch-time intent derivation) all predate this
change, so the checkpoint comparison AGENTS.md requires
was runnable and has been run.

Method: a clean worktree was reconstructed at exactly
`a0b3bdd` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module). The scenario was run there under the canonical
command, then the full suite. Baseline at `a0b3bdd`
without the lesson in this environment is 1045 OK
(skipped=25); the branch adds no kernel code, so any
behavioral difference at the checkpoint would have been
a finding, not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 9 scenario tests pass identically at
  `a0b3bdd` — the trusted-session refusal, the
  benign-permit denial, the other-file permit denial,
  the single-execution step, the mutated-bytes denial,
  the forged/mismatched approval denials, the positive
  control executing exactly once, the negative control
  executing when unguarded, and the incident channel's
  0 incidents / 10 near-misses. Full suite at
  checkpoint-plus-lesson: 1054 OK (skipped=25),
  identical to the worktree head; the delta over the
  1045 baseline is exactly the 9 scenario tests.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not
  smoothed: the §5 bare-evaluate near-miss gap (issue
  #375) is a property of the base-era incident
  projection, present at `a0b3bdd` exactly as at the
  head — the replay neither introduces nor widens it.

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.

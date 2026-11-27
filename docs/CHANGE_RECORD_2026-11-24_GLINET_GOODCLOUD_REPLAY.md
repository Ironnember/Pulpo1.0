# Change record — Incident replay: GL.iNet GoodCloud trusted-channel root shell execution (vendor notice 2026-11-20; mechanism detail reported 2026-11-23)

Base: `origin/main` at `5297d1c` (incident replay:
ConnectWise ScreenConnect CVE-2026-84869, PR #386).
Authority: the standing incident scan surfaced the
incident on 2026-11-24; Austin approved this build the
same day ("Build the replay PR"). Test-only change: one
scenario module plus this record. No production code is
touched.

EXECUTION STATUS: the scenario module was executed at
this head and at the clean base checkpoint `5297d1c` on
2026-11-24, after Austin's explicit approval to work in
the build worktree. Every count below is the executed
run's actual figure: scenario 9/9 at both states; full
suite 1098 tests, OK (skipped=25) at both states (see
§4 and §8).

## 1. Invariant or failure addressed

Incident (Recorded, from GL.iNet's vendor notice of
2026-11-20 and from The Hacker News's 2026-11-23
reporting of RemoteToHome Consulting's research,
https://thehackernews.com/2026/11/hackers-exploited-glinet-cloud-flaw-to.html):
an unauthorized party exploited a flaw in GL.iNet's
GoodCloud cloud-management service to install malware —
root reverse shells calling back to 170.39.226[.]219 —
on GL.iNet routers and KVM devices. Per the researcher's
finding as reported, the GoodCloud client handler on the
device runs two cloud-message values as root via a shell
without checking them: values carried in a message that
arrived over the trusted cloud channel were passed to a
shell as a command. The mechanism is researcher-reported
and has NOT been confirmed by the vendor; this record
grades it Recorded on that basis and asserts nothing
stronger about the real service. No CVE, device count,
or victim count is carried here, because no primary or
convergent source in hand states one.

Failure addressed: **a trusted channel is not
authorization for a specific act.** The message's
command-shaped values inherited their "authority" from
the established cloud channel they arrived over, not
from any authorization for that act, those values, or
that moment — and the handler's message processing
carried shell execution with it, so the distinction
between receiving values and running them did not exist
on the dispatch path. The governing invariants are
`ACCESS != AUTHORITY_FOR_THE_SPECIFIC_ACT`,
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`,
and the exact-intent binding itself: under the kernel,
the execution requires a permit bound to the exact
intent — principal, action, the SHA-256 digest of the
values actually presented at dispatch, cost, session —
so a permit for a benign configuration sync, a permit
for a different command, or the same label carrying
different bytes is a different intent, and none of them
spends as the execution. Denial is fail-closed at
evaluate/consume, never a log line written after the
command has already run.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately unguarded
doubles (`_IntentBlindState`, `_UnguardedConsumeKernel`)
exist solely as the negative control, are test-local,
and are never imported by runtime code — the same
pattern as PRs #346 and #362–#386.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds no
writer, route, ledger, executor, or state backend. The
scenario's `DeviceAgentExecutor` is a test harness: it
records a consequence only after a successful kernel
consume, holds no canonical state, and never invokes a
shell — the command is modeled as data throughout. The
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
`tests/test_glinet_goodcloud_incident_scenario.py`
(9 tests, all passing at this head — executed):

- positive control: the one authorized act (an
  operator-issued maintenance command, dispatched by its
  bytes) executes exactly once under a verified approval
  envelope; replay of the spent permit is denied; the
  audit chain verifies.
- step 1: the cloud message's execution is denied on
  every no-permit route — `evaluate` returns
  `require_approval` with no permit minted, and the
  established channel itself, presented as a permit, is
  rejected at consume (`permit_rejected` bound to the
  execution's intent hash). A trusted channel is not a
  permit, and nothing executes.
- step 2: a genuine permit for the benign cloud act on
  the same message (sync its configuration) does not
  authorize the execution — same channel, same message,
  same principal, different act — and the sync permit
  spends afterward on its exact intent. Receiving values
  and running them are different authorizations.
- step 3: a genuine execution permit for a different
  command (the approved maintenance command) does not
  authorize the cloud values: at dispatch, the derived
  intent names the presented bytes' digest, and the
  permit spends on it not at all; the permit still
  spends on the command it names. Authority to execute a
  command is authority for that command's bytes, not for
  the execute verb.
- step 4: a correctly scoped live permit for the
  incident values' exact bytes authorizes exactly one
  execution; the spent permit re-presented for the same
  execution (the replayed-message shape: a valid channel
  re-delivering a message with a stale, already-used
  authorization) and re-aimed at the benign sync act are
  both rejected (2 `permit_rejected` against 1
  `permit_consumed`).
- step 5: mutated bytes under the genuine permit are
  denied at the dispatch boundary — bytes of the same
  length and nearly the same content derive a different
  intent, the rejection is bound to the mutated intent's
  hash, and the genuine bytes still spend the permit
  afterward. The scenario carries actual value bytes
  throughout (the construction of PR #382's fix cycle,
  applied at first submission here): no presentation
  exists in the scenario except through the dispatch
  derivation, so altered bytes cannot execute under a
  consumed permit while the tests pass.
- step 6: an approval envelope for the execution signed
  with an unauthorized key is denied
  (`approval_signature_invalid`), and the genuine sync
  envelope presented for the execution intent is denied
  (`approval_intent_mismatch`); the genuine pair still
  admits afterward.
- step 7: the incident channel sees the campaign —
  freezing a report over the full attempt sequence
  (every attack variant from steps 1–6: the no-permit
  evaluation, the channel-token route, the benign-permit
  route, the other-command permit route, the
  mutated-bytes dispatch, both approval-envelope
  attempts, the one legitimate execution, and both
  spent-permit replays) yields zero incidents and
  exactly the near-miss records the channel's derivation
  produces from the audit: 6 `permit_rejected`, 2
  `approval_rejected`, and 2 denied `decision` records
  (10 near-misses in total), each classified Recorded
  under a valid audit chain; the freeze appends nothing.
  The step also pins the surfacing boundary stated in
  §5: the sequence's 1 `require_approval` decision is
  present in the audit and contributes zero near-miss
  records. These counts are the executed run's, at this
  head and identically at the clean base checkpoint
  (§8); the reporting sequence replays every variant by
  construction (the lesson of the Codex P2 on PR #378,
  applied at first submission here rather than by
  amendment).
- negative control: with consume unguarded at both
  layers (kernel double + intent-blind state double),
  the cloud command EXECUTES under a permit issued for
  a benign configuration sync — the incident's own
  shape, a handler that runs what an established channel
  delivers because the channel is trusted. The denials
  come from the binding layers, not from a harness that
  denies by construction.

Full suite at the worktree head (executed): 1098 tests,
OK (skipped=25). The base commit `5297d1c` without this
module runs 1089 tests; the delta is exactly the 9
scenario tests. The checkpoint run at clean `5297d1c`
with the scenario module as the only delta also runs
1098 tests, OK (skipped=25), with the scenario 9/9 —
see §8.

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — no control depends on how the message arrived:
  a command from the operator's legitimate cloud session
  and one from an attacker who compromised the channel
  are indistinguishable as authority artifacts, and
  neither mints anything; authority arrives only as
  verified per-act approvals. The incident's own flip is
  that the channel built to let an operator manage a
  device became the path that owned the device.
- Reverse — the execution requires a consumed permit
  bound to the exact intent; the earliest unreachable
  point is the first cloud message (denied at evaluate
  and at consume), and the chain does not collapse to
  one control: the benign sync permit cannot be re-aimed
  at execution (step 2), the other command's execution
  permit cannot be re-aimed at these values (step 3),
  the genuine permit cannot be re-aimed at mutated bytes
  (step 5), or replayed after use (step 4).
- Invert — outcome is not legitimacy: a handler that ran
  the command would show "success" by outcome (the
  command executed), but the governed record supports
  credit only for consumed acts, so any claim that the
  incident's executions were authorized is unsupportable
  against the audit and visible as such in the incident
  channel (step 7).
- Inside-Out — the governor cannot originate the
  authority it enforces: an envelope signed with an
  unauthorized key is denied (step 6a); a channel token
  or a message label cannot produce an approval envelope
  or ceremony evidence at all; the test verifiers are
  test-only; the orchestrator surface used for the
  incident report is read-only and its freeze is
  asserted to append nothing (step 7).
- Darken — worst credible bounded case: a compromised
  cloud-management channel reaches every enrolled device
  at once, and the reported payload ran as root — full
  device compromise, a pivot into every network the
  device routes for. Inside the governed path the
  maximum consequence per permit remains the one
  authorized act; every unauthorized attempt produces
  audit records only — one per attempt on the
  bare-evaluate and consume routes, two (an
  `approval_rejected` record and a denied decision
  record) on the denied approval-envelope route — and
  zero consequences. Outside the governed path stands
  the incident's real worst case — a handler that
  executes what the channel delivers — and this replay
  does not mitigate it; it is the boundary in §5.
- Lighten — minimum benign interpretation: a management
  service that sincerely wants remote administration to
  be frictionless, so an operator can send a command and
  have it just run. The kernel still denies the
  execution, because channel convenience, however
  sincere, is not a per-act approval — and a channel
  compromise is what frictionless dispatch accumulates.
  The positive control and step 4 show the governed path
  exists: approve the exact command, run it once.
- Amplify — the flaw reaches the whole enrolled fleet
  through one channel at once, each message repeatable;
  permits are per-intent, per-session, and single-use,
  so replication multiplies attempts, never authority.
  Denial volume produces audit growth only, bounded per
  attempt.
- Negate — the smallest clean path: the legitimate
  purpose (an operator runs a known maintenance command
  on their own device) needs only a per-act permit for
  the exact bytes intended. Channel trust as execution
  authority, a message handler that silently includes
  shell execution, and command identity by
  sender-chosen label are all unnecessary.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models cloud messages presented for
consumption at a governed dispatch boundary. It proves
nothing about GoodCloud, any GL.iNet service or
firmware, any channel protocol, or any exploit, and it
reproduces no part of the vulnerable handler and none of
the incident's payload — the command values in the
scenario are inert labeled stand-ins that exist so the
dispatch boundary can derive an identity from them, and
no shell is invoked anywhere in the module. It proves
nothing about non-governed paths: the real incident's
handler checked nothing about which acts the channel was
authorized for, and a handler like that is governed by
nothing here — a control not on the execution path
governs nothing. The replay also does not speak to the
parts of the incident downstream of the first execution
(the reverse shell, persistence, any lateral movement):
it governs the execution before it happens, not the
compromise afterward. Whether a correctly scoped permit
should ever be granted for channel-delivered command
values is an approver-policy question the kernel does
not decide; step 4 pins only that if one is granted, it
is exactly one execution of exactly those bytes.

One surfacing boundary, stated plainly rather than
smoothed over (recorded from PR #386's change record,
where it was Verified by executable probe and by the
channel's derivation source; step 7 of this scenario
re-pins it at this head by execution — see §4): a bare
`evaluate` that returns `require_approval` — the kernel
declining to mint a permit without approval — appends a
decision record to the canonical audit, where it is
complete and chain-verified, but the incident channel
does NOT derive a near-miss record from it; the channel
derives near-misses from `permit_rejected`,
`approval_rejected`, denied decisions, and
`directive_denial`. The act is still stopped — no permit
exists to spend — so this is a derivation-coverage
boundary in the owner-facing channel, not an
authorization gap (issue #375). Whether a
`require_approval` decision should also surface as a
near-miss is a design question for the channel's
maintainers; this replay records the behavior exactly
as it stands and takes no position by silently
engineering around it.

## 6. Claim classification

- Incident narrative: **Recorded** (GL.iNet's vendor
  notice of 2026-11-20 for the compromise itself; The
  Hacker News's 2026-11-23 reporting of RemoteToHome
  Consulting's research for the mechanism — the handler
  running two cloud-message values as root via shell.
  The mechanism is researcher-reported, NOT
  vendor-confirmed, and is graded no higher than
  Recorded on that basis).
- Callback address (170.39.226[.]219, defanged here):
  **Recorded** (as reported; not independently verified
  here).
- Kernel behavior asserted by the scenario tests:
  **Verified** — executed at this head and at the clean
  base checkpoint `5297d1c` (scenario 9/9 and full suite
  1098 tests, OK (skipped=25) at both states; §4, §8).
- The incident-channel surfacing boundary in §5:
  **Recorded** from PR #386's change record (Verified
  there at its base) and re-pinned by this scenario's
  step 7, **Verified** by execution at this head and at
  the checkpoint (the sequence's 1 `require_approval`
  decision contributes zero near-miss records at both
  states).
- The mapping from the incident's pattern to kernel
  intents (an execution request names its command by the
  SHA-256 digest the dispatch boundary derives from the
  presented values; channel establishment modeled as no
  authority artifact at all; configuration sync and
  shell execution modeled as distinct actions requiring
  distinct permits): **Inferred** — the harness's
  modeling choices, stated in the module docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346–#350, #362–#368, #374–#382, and
#386, including their per-module helper-duplication
pattern, the reporting-coverage construction of PR
#378's step 6 as amended, and the dispatch-boundary
payload binding of PR #382's fix cycle.

## 8. Temporal-transfer evidence

The applicable historical checkpoint is this branch's
exact base, `5297d1c`: the bindings the scenario
exercises (exact-intent binding, single-use consumption,
approval verification, dispatch-time intent derivation)
all predate this change, so the checkpoint comparison
AGENTS.md requires is runnable. IT WAS RUN on
2026-11-24: a clean worktree was reconstructed at
exactly `5297d1c` (no tree rewriting), the scenario
module copied in as the only delta, and the scenario
plus the full suite run there and at the worktree head.

Results, in the TRANSFERS / NO EFFECT / NEGATIVE
TRANSFER form:

- TRANSFERS — all 9 scenario tests pass identically at
  clean `5297d1c` and at the worktree head, including
  step 7's counts (6 `permit_rejected`, 2
  `approval_rejected`, 2 denied decisions, 10
  near-misses, 0 incidents). The lesson — a trusted
  channel is not a permit, and an execution's identity
  is the digest of the bytes actually presented at
  dispatch — holds at the base-era kernel exactly as at
  this head.
- NO EFFECT — the full suite at the checkpoint with the
  module as the only delta runs 1098 tests, OK
  (skipped=25), identical to the head; the base without
  the module runs 1089, so the delta is exactly the 9
  scenario tests. The lesson is tests and documentation
  only, `authority_effect=none` at both states.
- NEGATIVE TRANSFER — none. The §5 bare-evaluate
  near-miss gap (issue #375) appears identically at the
  checkpoint — the sequence's 1 `require_approval`
  decision contributes zero near-miss records at both
  states — recorded as a property of the base-era
  incident projection, unchanged by this lesson, and
  not engineered around.

# Change record — Incident replay: Binance wallet-signing heist via deployment-token authority stretch (2026-10-29; report 2026-11-03)

Base: `origin/main` at `9aca02e` (incident replay:
WP connect WordPress plugins supply-chain backdoor,
PR #388).
Authority: the standing incident scan surfaced the
incident in its 2026-11-24 evening run (a catch-up
find; Binance's report is dated 2026-11-03); Austin
approved building all five replays on 2026-11-24.
Test-only change: one scenario module plus this
record. No production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from Binance's own initial
incident report, published 2026-11-03): a five-month
campaign. In June 2026 a Wallet DevOps engineer
downloaded a tampered Homebrew installer while seeking
a popular AI coding tool — a supply-chain entry; the
device was replaced and credentials rotated, but the
attackers learned the wallet team's org chart. In
September a second engineer fell for a fake-recruitment
interview and ran a malicious coding "assignment" that
replaced pyenv with a poisoned binary. On Oct 20 the
attackers used a compromised machine and an internal
AI tool to take control of two engineers' computers.
On Oct 29, 17:15–19:56 (the report states this
window with no timezone; its explicit UTC labels
attach to specific transaction times elsewhere), the
attackers used Engineer A's container-deployment
token on Engineer C's machine
to deploy a container and trigger a script that
exploited unauthorized access to the internal
wallet-signing service, moving ~$6.34B (233.46M XRP in
4 minutes; EIP-7702 delegation abuse on ETH; a final
2,961.9 ETH at 23:56 UTC). ~$2.85B was
frozen/intercepted. The FBI attributes the campaign to
DPRK (TraderTraitor), as reported by Binance. Binance
does not explain how the internal AI tool was used for
the lateral movement.

Failure addressed: **authority for one act was treated
as a path to a categorically different act.**
``AUTHORIZATION_TO_DEPLOY != AUTHORIZATION_TO_SIGN``.
A token legitimately issued for one act (deploy a
container) was treated by the environment as a path to
a categorically different act (sign wallet
transactions) it never authorized. The governing
invariants are the fail-closed rule of AGENTS.md
(unknown, malformed, untrusted, expired, replayed, or
unavailable authority fails closed through the
canonical kernel) and the mechanisms this replay
exercises: exact-intent binding (an approval and a
permit bind principal, action, resource, cost, and
session, and refuse any other intent on both the
evaluate and consume boundaries), single-use (a permit
spends exactly once at consume), and revocation at
consume (a permit bound to a directive is re-checked
against the directive's live status when it is
presented, so revoking the directive retires unspent
permits where the act would happen). A deployment
credential is none of those things for a signing act
on any route: not a token the kernel issued for that
act (consume refuses a never-issued string), not a
signature the authority made for that act (evaluation
refuses it), and not a scope (a genuine deployment
approval refuses to stretch to signing).

What enabled the real incident — the compromised
machines and the unauthorized access to the signing
service — happened before and around the gate this
replay models; §5 states the boundary in full.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately vulnerable
double (`_StandingTokenVerifier`) exists solely as the
negative control, is test-local, and is never imported
by runtime code — the same pattern as PRs #346 and
#362–#388.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`,
directive activation/revocation and governed
projection, audit read, and incident-channel derivation
paths, and adds no writer, route, ledger, executor, or
state backend. The scenario's `WalletExecutor` is a
test harness: it records a consequence only after a
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
the scenario pins. The revocation step exercises an
existing governed mutation — directive revocation
through `DirectiveAuthorityController` — on a
test-local kernel; it introduces no new mutation.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_binance_wallet_incident_scenario.py`
(8 tests, all passing at the worktree head):

- positive control: the one authorized act (deploying
  a container to the wallet infrastructure) executes
  exactly once under a genuine, well-formed verified
  approval envelope; replay of the spent permit is
  denied; the audit chain verifies.
- step 1: with no credential at all, `evaluate` of the
  signing act returns `require_approval` with no permit
  minted, and nothing executes. An act the policy does
  not contain (`export_signing_keys`) is denied
  outright (`action_not_allowed`).
- step 2: an inert stand-in for the stolen deployment
  token, presented as a permit at consume, is refused
  for both the signing act and the deployment act
  (`permit_rejected`, reason
  `permit_signature_invalid`, bound to the exact intent
  hash each time). It was never issued: no state row
  stands behind it and no genuine token signature does
  either, so possession of the string is not an
  issuance.
- step 3: the deployment token offered as an approval
  signature, a fabricated signature string, and an
  envelope signed with an unauthorized key are each
  denied (`approval_signature_invalid`); an empty
  signature is denied earlier and separately
  (`approval_signature_missing`).
- step 4 (the incident's core): the genuine deployment
  envelope presented for the signing act is denied
  (`approval_intent_mismatch`), and the genuine issued
  deployment permit presented at consume for the
  signing act is refused (`permit_intent_mismatch`);
  the denials do not poison the path — the same permit
  then performs its own deployment act exactly once.
- step 5 (revocation at consume): on a directive-bound
  kernel, a genuine permit is issued for the bounded
  deployment act through `GovernedDirectiveProjection`
  under an active directive (`wallet-deployment-engagement`),
  the directive is then revoked through the governed
  path (`DirectiveAuthorityController.revoke`), and the
  permit presented at consume is refused: the
  `permit_rejected` record carries
  `directive_status` `directive_revoked` (the store's
  consume payload names the directive status on this
  route; observed in the executed run, not assumed).
  No governed consequence for the deployment intent is
  consumed on that kernel.
- step 6: the incident channel sees the attempts —
  freezing a report over the full attempt sequence in
  the incident's own order (the no-credential probe,
  the unknown-act probe, the stolen token spent as a
  permit, the fabricated signature offered as an
  approval, the genuine envelope stretched to the
  signing act, the genuine permit spent against the
  signing act, the one legitimate execution, and the
  spent-permit replay) yields zero incidents and
  exactly the near-miss records the channel's
  derivation produces from the audit: 3
  `permit_rejected`, 2 `approval_rejected`, and 3
  denied `decision` records, plus 1 `require_approval`
  `decision` record (9 near-misses in total),
  each classified Recorded under a valid audit chain;
  the freeze appends nothing. The step also pins the
  surfacing boundary stated in §5: the sequence's 1
  `require_approval` decision is present in the audit
  and contributes one near-miss record since the issue
  #375 fix (PR #413; §10). The counts
  are from the executed run at this head, not
  estimates.
- negative control: with the verifier swapped for the
  incident environment's shape — a standing-token
  verifier whose `verify()` accepts the deployment
  credential itself as the signature for ANY envelope —
  an envelope for the SIGNING act "signed" with the
  deployment-token stand-in VERIFIES, a permit mints,
  and the signing act EXECUTES. Under the same double,
  a fabricated string and the genuine authority's real
  HMAC signature are both denied: only the deployment
  credential verifies, because possession of it is the
  whole check. The denials in the steps above therefore
  come from the governed verification's shape (a
  computed expected signature under the enrolled key,
  bound to the exact intent), not from a harness that
  denies by construction.

Full suite at the worktree head: **1114 tests, OK
(skipped=25)** in this environment — the recorded local
baseline at the base commit `9aca02e` is 1106 OK
(skipped=25); the delta is exactly the 8 scenario
tests. (The skipped=25 figure is this environment's
count; CI records its own environment's skipped count
with the same test total modulo environment-specific
discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — the incident is itself a flip of credential
  scope: a legitimate credential for a routine act
  (deployment) is the hostile instrument for a
  catastrophic act (signing). No control on the
  governed path depends on which act a credential was
  "meant" for in prose: no credential (step 1), the
  stolen token (steps 2, 3), a fabricated signature
  (step 3), and a forged key (step 3) are the same
  denial, and the genuine deployment article fails to
  stretch (step 4) — legitimacy is per exact intent,
  not per credential pedigree.
- Reverse — the consequence (a signed transaction)
  requires a consumed permit; the permit requires a
  verified approval; the approval requires a signature
  computed from the payload under the enrolled key by
  an accountable approver, bound to the exact intent.
  The chain does not collapse to one control: the
  stolen token fails at token authentication at
  consume (step 2) and at signature verification at
  evaluate (step 3), forged artifacts fail at
  verification (step 3), the genuine article fails to
  stretch at intent binding on both boundaries
  (step 4), revocation retires an unspent genuine
  permit at consume (step 5), and the spent permit
  cannot be replayed (positive control, step 6).
- Invert — outcome is not legitimacy: inside the
  incident, the deployment itself was, in isolation,
  the kind of act the token existed for; the outcome
  (a container deployed) does not legitimate the
  signing acts it was used to trigger. The governed
  record supports credit only for consumed acts under
  verified approvals for those exact acts, so a
  deployment-authorized signing would stand in the
  record as a consequence with no approval behind it,
  visible as such; the negative control produces
  exactly that shape, under the double rather than the
  kernel.
- Inside-Out — the governor cannot originate the
  authority it enforces: the approval verifier holds
  only verification; a deployment token cannot produce
  an approval envelope or ceremony evidence at all; the
  test double is test-only; the orchestrator surface
  used for the incident report is read-only and its
  freeze is asserted to append nothing (step 6).
- Darken — worst credible bounded case (a threat case,
  not a claim): the campaign ran five months, crossed
  from one engineer's token to another's machine, and
  moved ~$6.34B in hours, including 233.46M XRP in 4
  minutes — once a signing service is reachable by a
  deployment credential, the loss rate is bounded by
  the service, not by the attacker. Inside the governed
  path the maximum consequence per approval remains the
  one authorized act; every unauthorized attempt
  produces audit records only — one per attempt on the
  bare-evaluate and consume routes, two (an
  `approval_rejected` record and a denied decision
  record) on the denied approval-envelope route — and
  zero consequences. Outside the governed path stands
  the incident's real worst case, and this replay does
  not mitigate it; it is the boundary in §5.
- Lighten — minimum benign interpretation: ~$2.85B was
  frozen/intercepted, Binance published its own initial
  report promptly with the timeline and mechanisms
  above, and the deployment the token performed was of
  a kind the token legitimately existed to perform —
  the failure was the reach from that act to signing,
  not the existence of deployment authority. The replay
  grades the mechanism — one act's authority treated as
  another act's — not any individual engineer, whose
  machines and credentials were taken by a state
  campaign over five months.
- Amplify — the technique scales by credential, not by
  effort: any deployment-scoped credential in any
  organization whose signing (or payment, or release)
  service it can reach is the same incident waiting for
  a presenter. Approvals are per-intent and permits
  single-use, so replication multiplies attempts, never
  authority; revocation at consume retires what
  replication would otherwise reuse; denial volume
  produces audit growth only, bounded per attempt.
- Negate — the smallest clean path: a signing act needs
  no deployment-credential route at all. A verified
  approval bound to the exact signing intent, checked
  against a value computed under the enrolled key,
  achieves every legitimate purpose — deployments
  deploy, signings sign, each under its own approval —
  with no credential whose legitimate possession
  performs a different act. Remove cross-act authority
  stretch and the incident class does not happen.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models credentials and approval artifacts
presented at a governed dispatch boundary for a
wallet-signing service. The supply-chain entry (the
tampered Homebrew installer, the poisoned pyenv), the
fake-recruitment social engineering, and the internal
AI tool's role in lateral movement (Unknown — Binance
does not explain it) are all outside the gate; the
replay models only the authorization failure at the
signing service: a deployment-scoped authority reaching
a signing act. It proves nothing about Binance's real
systems, the container deployment, the script, or the
EIP-7702 delegation abuse, and it reproduces no part of
the campaign or any real token — the token string is an
inert stand-in, and the verifier double is a test-local
model faithful only in the property the scenario names
(verification by possession of the deployment
credential). Pulpo's claim here is only about the gate
it sits on: had the signing service routed its
consequential acts through this kernel, the stolen
token, the forged artifacts, and the stretched genuine
deployment permit would each have failed closed, for
the reasons the steps record, and revoking the
governing directive would have retired an unspent
permit at consume. It proves nothing about non-governed
paths: a signing service reachable by a deployment
credential is governed by nothing here — a control not
on the execution path governs nothing.

One surfacing boundary, stated plainly rather than
smoothed over (Verified at this commit, by executable
probe, by the channel's derivation source, and by
step 6's pinned counts): a bare `evaluate` that returns
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

- Incident narrative: **Recorded** (Binance's own
  initial incident report, published 2026-11-03: the
  June 2026 tampered Homebrew installer and org-chart
  exposure, the September fake-recruitment interview
  and poisoned pyenv, the Oct 20 takeover of two
  engineers' computers using a compromised machine and
  an internal AI tool, the Oct 29 17:15–19:56 use
  (window timezone not stated in the report) of
  Engineer A's container-deployment token on
  Engineer C's machine to deploy a container and trigger
  a script exploiting unauthorized access to the
  internal wallet-signing service, and the final
  2,961.9 ETH at 23:56 UTC).
- Dollar and asset figures (~$6.34B moved, 233.46M XRP
  in 4 minutes, ~$2.85B frozen/intercepted): **Recorded**
  as Binance states them.
- Attribution to DPRK (TraderTraitor): **Recorded**
  (FBI attribution as reported by Binance).
- The internal AI tool's lateral-movement mechanism:
  **Unknown** (Binance does not explain it).
- The timezone of the Oct 29 17:15–19:56 deployment
  window: **Unknown** — the report appends UTC
  explicitly to the XRP and final-ETH transaction
  times but gives the window itself with no timezone;
  no timezone is attributed to it anywhere in this
  change. (Corrected in the §9 fix pass; the original
  text asserted UTC.)
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit, including the revocation-at-consume payload
  shape in step 5, observed in the executed run).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 6).
- The mapping from the incident's pattern to kernel
  artifacts (the signing act modeled as the
  consequential act; the deployment token modeled in
  its three positions — presented permit, presented
  approval signature, standing verification check; the
  deployment engagement modeled as a directive for the
  revocation step): **Inferred** — the harness's
  modeling choices, stated in the module docstring.
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
amended, the negative-control double construction of
PR #386, and the directive-revocation construction of
PR #387.

## 8. Temporal-transfer evidence

Executed 2026-11-24. The applicable historical
checkpoint is this branch's exact base, `9aca02e`: the
bindings and verification checks the scenario exercises
(exact-intent binding, single-use consumption, token
authentication at consume, approval verification with an
exact-`True` verdict, the approval-envelope structural
checks, and directive revocation re-checked at consume)
all predate this change, so the checkpoint comparison
AGENTS.md requires was runnable and has been run.

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

- TRANSFERS: all 8 scenario tests pass identically at
  `9aca02e` — the positive control executing exactly
  once, the no-credential and unknown-act denials, the
  stolen-token consume refusals, the forged / fabricated
  / missing-signature denials, the genuine deployment
  article's refusal to stretch on both boundaries, the
  revocation at consume retiring an unspent
  directive-bound permit, the incident channel's 0
  incidents / 8 near-misses, and the negative control
  executing under the standing-token verification
  double. Full suite at checkpoint-plus-lesson: 1114 OK
  (skipped=25), identical to the worktree head; the
  delta over the 1106 baseline is exactly the 8
  scenario tests.
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

## 9. Post-review fix pass (Codex P2 on PR #398, 2026-11-25)

Review finding (Codex, P2): the change record and
module docstring attributed **UTC** to the Oct 29
17:15–19:56 deployment window and classified the
narrative as Recorded wholesale. Binance's report
gives that window with no timezone, appending UTC
explicitly only to the XRP and final-ETH transaction
times elsewhere. The finding is correct.

Change (wording only; no code, no test logic): the
window is now stated with no timezone in §1, §6, and
the module docstring, each noting the report's
silence; §6 classifies the window's timezone as
**Unknown**. The transaction times the report does
label UTC (including the final 2,961.9 ETH at 23:56
UTC) keep their labels.

Re-verification at the fix-pass head: scenario 8/8;
full suite **1114 tests, OK (skipped=13)** in this
environment — identical totals to the pre-pass head,
as expected for a wording-only change.

## 10. Addendum — #413 near-miss derivation pin refresh (2026-11-27)

Cause (Verified): PR #413 (merged 2026-11-26 as
`b1cea2f`, fixing issue #375) changed the incident
channel's derivation so a `decision` record with
outcome `require_approval` derives one near-miss per
occurrence, mirroring the deny path. This branch was
built before #413 and pinned the pre-#413 total;
step 6 failed deterministically at the old head
(8 != 9). The delta is exactly this scenario's 1
`require_approval` decision — the same update shape
#413 itself applied to its twelve scenarios.

Change (test pins and this record only; no kernel or
production code touched; `authority_effect=none`):
step 6's near-miss identity and `decision`
source-detail count now include
`len(require_approval_decisions)`; the pinned total
moves 8 → 9; the module docstring and §4 counts
state the new derivation. §5 and §8 describe the
pre-#413 boundary and checkpoint states as they
stood when recorded and are left as written; this
addendum supersedes them for the current head.

Re-verification at this head: scenario 8/8; full
suite **1183 tests, OK (skipped=13)**.

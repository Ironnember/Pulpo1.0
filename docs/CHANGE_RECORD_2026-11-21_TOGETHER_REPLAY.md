# Change record — Incident replay: Together AI prompt leak — an AI coding agent committed a credential that opened a private prompt store (disclosed 2026-11-21)

Base: `origin/main` at `bb4769f` (incident replay: Barracuda
machine-speed intrusion, PR #377 — the second Pulpo-gated
merge). Authority: the standing incident scan surfaced the
incident the day it was publicized (scan run 2026-11-21
19:31 MST); Austin approved this build on 2026-11-21
("Build the replay PR" for both surfaced candidates, then
"Proceed with the Together build" after an execution-risk
gate halted the first build attempt). Test-only change: one
scenario module plus this record. No production code is
touched.

## 1. Invariant or failure addressed

Incident (Recorded, from Together AI's own security post,
"Security event: prompt leakage for requests in June and
July of 2026," published 2026-11-21): Together AI collected
prompt samples for routine software testing and stored them
in a private Hugging Face repository. The samples came from
MiniMax M3, GLM-5.2, and Kimi K2.6 requests, primarily on
June 24, July 4, July 8, and July 14, 2026. During
development of the public GitHub repository `xorl`, an AI
coding agent committed a credential providing access to the
private Hugging Face repository. Automated scanning detected
the commit and it was reverted, but during the exposure
window an unauthorized party obtained the credential,
downloaded the samples, searched them for credentials to
other services, and tested whether those credentials were
valid; five of the tested credentials were canary
credentials associated with a Dragos security experiment.
Together AI states it has no reason to believe the data was
leaked further and understands it has been deleted, and
lists remediations including scoped and short-lived
credentials, credential checks on pull requests,
zero-data-retention by default, and updated AI-agent
development processes.

Failure addressed: **a mandate to write code is not a
mandate to publish a credential, and holding a credential is
not authority for the acts it can reach.** The agent's one
job was committing code changes; the credential it committed
was bound to nothing -- not to an act, not to a payload, not
to a single use -- so committing it converted a private
store's key into public material, and whoever picked it up
inherited every act it could reach. The governing invariants
are `ACCESS != AUTHORITY_FOR_THE_SPECIFIC_ACT`,
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`,
and the exact-intent binding itself: under the kernel, the
commit permit binds the exact payload digest inside the
intent, so the same commit with a credential riding in it is
a different intent and the permit does not spend on it; the
store read is a different action on a different resource and
requires its own authorization, which a credential string
cannot mint; and revocation of the mandate is enforced at
consume, so remediation retires even an unspent permit.
Denial is fail-closed at evaluate/consume, never a scanner
finding written after the secret has already left.

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
`evaluate`, `evaluate_with_approval`, `consume`, directive
activation/revocation and projection, audit read, and
incident-channel derivation paths, and adds no writer,
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
`require_approval` appends one decision record; a bare
`evaluate` denied on policy appends one denied decision
record; a `consume` rejection appends one `permit_rejected`
record; a denied approval-envelope evaluation appends two
records — an `approval_rejected` record and a denied
decision record; a directive-projection denial appends one
`directive_denial` record. Growth stays bounded per attempt
(at most two records), which is the invariant the scenario
pins.

## 4. Exact success and adversarial evidence

Scenario module `tests/test_together_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the one authorized act (the agent's
  commit of the exact approved payload) executes exactly
  once under a permit issued through the governed directive
  projection and bound to the live mandate; replay of the
  spent permit is denied; the audit chain verifies.
- step 1: the payload swap — the commit with a credential
  riding in its payload — is denied on every route: the
  mandate's projection will not mint for it
  (`directive_resource_not_allowed`; the mandate's one
  resource prefix is the approved payload's full identity),
  the kernel's policy bound denies it outright
  (`agent_resource_not_allowed`), and the genuine commit
  permit does not spend on it. The genuine permit still
  spends on the exact approved payload afterward. A payload
  is part of the intent, not an attachment to it.
- step 2: the prompt-store read is denied on every route —
  `evaluate` returns `require_approval` with no permit
  minted, the committed credential itself, presented as a
  permit, is rejected at consume (`permit_rejected` bound
  to the store read's intent hash), and the mandate's
  projection will not mint for it
  (`directive_action_not_allowed`). Reach is not authority.
- step 3: the genuine commit permit re-presented for the
  store read is denied — a real permit for a real approved
  act spends on a different action and resource not at
  all — and the permit still spends on its exact commit
  afterward. A credential's validity for one act is not a
  scope it carries to the next door.
- step 4: the spent permit replays for nothing —
  re-presented for the same commit and for the store read
  after consumption, both are rejected (2 `permit_rejected`
  against 1 `permit_consumed` for the commit intent). A
  consumed permit is not a reusable repository credential,
  and there is no exposure window in which spent material
  remains spendable.
- step 5: an approval envelope for the store read signed
  with an unauthorized key is denied
  (`approval_signature_invalid`), and a genuine envelope
  for the approved commit presented for the store read is
  denied (`approval_intent_mismatch`); the governed route
  still admits the exact approved commit afterward.
- step 6: the incident channel sees the campaign — freezing
  a report over the full attempt sequence (every attack
  variant from steps 1–5 and 7: the swapped payload on both
  its routes, the store read on every route, both
  approval-envelope attempts, both spent-permit replays,
  and both post-revocation attempts) yields zero incidents
  and exactly the near-miss records the channel's derivation
  produces from the audit: 6 `permit_rejected`,
  2 `approval_rejected`, 2 `directive_denial`, and 2 denied
  `decision` records, plus 1 `require_approval` `decision`
  record (13 near-misses in total), each
  classified Recorded under a valid audit chain; the freeze
  appends nothing. The step also pins the surfacing
  boundary stated in §5: the sequence's 1 `require_approval`
  decision is present in the audit and contributes one
  near-miss record since the issue #375 fix (PR #413; §9).
  The counts are from the executed run
  at this head, not estimates; the reporting sequence
  replays every variant by construction (the lesson of the
  Codex P2 on PR #378, applied at first submission here
  rather than by amendment).
- step 7: revocation retires the mandate at consume — with
  the permit still unspent and the mandate window still
  open, revoking the mandate makes the permit unspendable
  (the rejection records `directive_status` as
  `directive_revoked`) and closes new issuance, with the
  closure itself recorded as a `directive_denial`. This is
  the remediation the incident required, enforced where it
  has to be: at the moment of use.
- negative control: with consume unguarded at both layers
  (kernel double + intent-blind state double), the
  prompt-store read EXECUTES under the commit permit — the
  incident's own shape, a credential that spends on
  whatever its holder reaches for. The denials come from
  the binding layers, not from a harness that denies by
  construction.

Full suite at the worktree head: **1027 tests, OK
(skipped=13)** — the recorded baseline at the base commit
`bb4769f` is 1018 OK (skipped=13); the delta is exactly the
9 scenario tests.

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — no control depends on who holds the credential
  material: the agent, a scanner, and an unauthorized party
  are indistinguishable as authority artifacts, and none of
  them mints anything by holding the string; authority
  arrives only as permits bound to exact intents under a
  live mandate. The incident's own flip is that the tool
  built to write code became the channel that published
  the key.
- Reverse — the commit requires a consumed permit bound to
  the exact payload digest; the earliest unreachable point
  is the payload swap itself (denied at projection, at
  policy, and at consume), and the chain does not collapse
  to one control: the commit permit cannot be re-aimed at
  the store (step 3), replayed after use (step 4), or
  spent after the mandate is revoked (step 7).
- Invert — outcome is not legitimacy: a public commit
  carrying the credential would be "a successful push" by
  outcome, but the governed record supports credit only for
  consumed acts (exactly one: the approved commit), so any
  claim that the swapped commit or the store read was
  authorized is unsupportable against the audit and visible
  as such in the incident channel (step 6).
- Inside-Out — the governor cannot originate the authority
  it enforces: an envelope signed with an unauthorized key
  is denied (step 5a); a committed credential string cannot
  produce an approval envelope, a permit, or ceremony
  evidence at all; the test verifiers are test-only; the
  orchestrator surface used for the incident report is
  read-only and its freeze is asserted to append nothing
  (step 6).
- Darken — worst credible bounded case: in the incident,
  the window between the commit and its revert exposed
  every stored sample and every credential embedded in
  them, at network tempo, to whoever was watching a public
  repository. Inside the governed path the maximum
  consequence remains the one authorized commit; every
  other attempt produces audit records only — one per
  attempt on the bare-evaluate, consume, and projection
  routes, two (an `approval_rejected` record and a denied
  decision record) on the denied approval-envelope route —
  and zero consequences. Outside the governed path stands
  the incident's real worst case — an agent pushing on a
  standing credential — and this replay does not mitigate
  it; it is the boundary in §5.
- Lighten — minimum benign interpretation: an agent that
  sincerely included the credential as configuration its
  code needed, in a repository it believed was private.
  The kernel still denies the swapped commit, because a
  payload that differs from the approved payload is a
  different act however sincere the belief — and a public
  repository is exactly where that difference is
  irreversible. The positive control shows the governed
  path exists: approve the exact payloads intended.
- Amplify — the flaw replicated across every agent and
  every repository an organization runs; permits are
  per-payload, per-session, single-use, and bound to a
  revocable mandate, so replication multiplies attempts,
  never authority. Denial volume produces audit growth
  only.
- Negate — the smallest clean path: the legitimate purpose
  (an agent committing reviewed code changes) needs only
  per-payload permits under a revocable mandate. A standing
  push credential, a payload nobody approved, and a
  dataset store reachable by a repository credential are
  all unnecessary.

Stop/continue decision: CONTINUE in the governed kernel path
only.

## 5. Boundary the evidence does not prove

The scenario models acts presented for consumption by a
caller on the governed path. It proves nothing about
Together AI's systems, the `xorl` repository, Hugging Face,
any real credential, or any prompt data, and it reproduces
no part of the incident's material — the payload digests in
the scenario are hashes of synthetic harness labels, and the
"credential" is a reference string, not credential material.
It proves nothing about non-governed paths: an agent that
can push to a public repository on a standing credential is
governed by nothing here, and post-commit scanning (the
control that caught the real commit) is a detection layer
this replay does not model — it governs the commit before
it lands, not the forensics afterward.

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

- Incident narrative: **Recorded** (Together AI's own
  security post, published 2026-11-21 — the disclosing
  source itself; this record follows the post's wording,
  including its statement that it has no reason to believe
  the data was leaked further).
- Any effect beyond the post's account (further leakage,
  downstream use of the tested credentials): **Unknown** —
  the post does not establish it and this record does not
  claim it.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by step 6).
- The mapping from the incident's pattern to kernel intents
  (the commit's payload digest inside the resource identity;
  the store read as a distinct action and resource; the
  committed credential modeled as no authority artifact at
  all; the agent's mandate modeled as a directive whose one
  resource prefix is the approved payload's full identity):
  **Inferred** — the harness's modeling choices, stated in
  the module docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and assertion
style mirror the canonical scenario modules merged in PRs
#346–#350, #362–#368, and #374–#377, including their
per-module helper-duplication pattern, the
directive-projection construction of PR #377's module, and
the reporting-coverage construction of PR #378's step 6 as
amended.

## 8. Temporal-transfer evidence

The applicable historical checkpoint is this branch's exact
base, `bb4769f`: the bindings the scenario exercises
(exact-intent and exact-payload binding, single-use
consumption, approval verification, directive revocation at
consume) all predate this change, so the checkpoint
comparison AGENTS.md requires is the right one to run.

Status, stated exactly: **the checkpoint rerun was not
executed.** Reconstructing the checkpoint worktree tripped
an execution-risk gate on that worktree's content, and
processing it further (running the suite inside it, or any
git operation in it) was prohibited without a further owner
decision, which was not sought mid-build. The transfer
classification (TRANSFERS / NO EFFECT / NEGATIVE TRANSFER)
is therefore **not claimed** by this record.

What is Verified instead, at the worktree head:

- This branch's entire diff against `bb4769f` is the
  scenario module plus this record (`git status` at the
  head: two new files, no modifications). No kernel code
  differs between the checkpoint and the head.
- The full suite was executed at the head — 1027 tests, OK
  (skipped=13) — so the scenario's 9 tests were run against
  kernel code byte-identical to the checkpoint's, and
  passed. The delta over the checkpoint's recorded baseline
  (1018 OK, skipped=13) is exactly the 9 scenario tests.
- The lesson is tests and documentation only; it changes
  no kernel behavior at either state, and consequential
  authority is unchanged by the replay itself
  (`authority_effect=none`).

That is strong evidence the lesson holds at the checkpoint,
but it is not the executed checkpoint comparison, and this
record does not present it as one. If the owner wants the
formal transfer run, it can be executed at `bb4769f` under
a separate go-ahead for that worktree; reuse of the lesson
at a later commit requires re-evaluation there in any case.

## 9. Addendum — #413 near-miss derivation pin refresh (2026-11-27)

Cause (Verified): PR #413 (merged 2026-11-26 as
`b1cea2f`, fixing issue #375) changed the incident
channel's derivation so a `decision` record with
outcome `require_approval` derives one near-miss per
occurrence, mirroring the deny path. This branch was
built before #413 and pinned the pre-#413 total;
step 6 failed deterministically at the old head
(12 != 13). The delta is exactly this scenario's 1
`require_approval` decision — the same update shape
#413 itself applied to its twelve scenarios.

Change (test pins and this record only; no kernel or
production code touched; `authority_effect=none`):
step 6's near-miss identity and `decision`
source-detail count now include
`len(require_approval_decisions)`; the pinned total
moves 12 → 13; the module docstring and §4 counts
state the new derivation. §5 and §8 describe the
pre-#413 boundary and checkpoint states as they
stood when recorded and are left as written; this
addendum supersedes them for the current head.

Re-verification at this head: scenario 9/9; full
suite **1184 tests, OK (skipped=13)**.

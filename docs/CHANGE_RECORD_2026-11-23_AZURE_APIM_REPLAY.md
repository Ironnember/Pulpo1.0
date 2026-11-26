# Change record — Incident replay: Azure API Management Classic credential theft (publicized 2026-11-23)

Base: `origin/main` at `a0b3bdd` (incident replay: OpenRouter
inference-provider incidents, PR #382). Authority: the
standing incident scan surfaced the incident the day it was
publicized (scan run 2026-11-23 19:31 MST); Austin approved
this build on 2026-11-23 ("Build the Azure APIM replay PR").
Test-only change: one scenario module plus this record. No
production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from BleepingComputer's reporting of
Microsoft's advisory and of Norway's National Security
Authority (NSM) public notice): Microsoft identified a flaw
on 2026-11-18 in Azure API Management Classic — on instances
not configured to recommended best practices, an unauthorized
party could reach management functions and perform
administrative operations, including reading stored secrets:
Named Values secrets, identity-provider and OpenID Connect
client secrets, subscription keys, and direct management API
tokens. Microsoft mitigated the flaw on 2026-11-19, and
warned that the mitigation does not invalidate credentials
already taken. Per NSM, an unknown actor targeted APIM
tokens and secrets; the targeting was first found by Norway's
energy sector, and NSM links it to the Equinor attack
disclosed 2026-11-17. How many instances or customers were
affected is not disclosed in the sources used.

Failure addressed: **possession of a valid credential is not
authorization for a specific act.** The credentials the
attacker held were valid, and validity was the whole of the
check: reaching the management plane with a credential the
plane accepts was treated as authority for each act the
plane can perform — above all reading the stored secrets,
which are themselves credentials for the next system. The
governing invariants are
`ACCESS != AUTHORITY_FOR_THE_SPECIFIC_ACT`,
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`,
and the exact-intent binding itself: under the kernel, each
secret read requires its own permit bound to the exact
intent — principal, action, resource, cost, session — so a
read of a different secret, a different instance, or a write
against the same secret is a different intent, and one
permit cannot be spent as any of them. The incident's second
failure is also addressed: the mitigation left already-taken
credentials valid because their validity consulted nothing
live. On the governed path, revocation is enforced at
consume time against the binding's live directive status, so
retiring the engagement retires even genuine, unexpired,
unspent permits — the invalidation the incident's
remediation could not perform. Denial is fail-closed at
consume, never a log line written after the secret has
already been returned.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a test
module only: no production surface is added, narrowed, or
widened; no permit, policy, or state behavior changes. The
module's deliberately unguarded doubles (`_IntentBlindState`,
`_UnguardedConsumeKernel`) exist solely as the negative
control, are test-local, and are never imported by runtime
code — the same pattern as PRs #346 and #362–#382.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
directive activation/revocation, governed projection
issuance, `consume`, audit read, and incident-channel
derivation paths, and adds no writer, route, ledger,
executor, or state backend. The incident-channel freeze is
asserted read-only in the scenario itself (audit length
unchanged across the freeze). Audit growth is classified in
the module docstring per AGENTS.md
(`NO_PERMIT != NO_GOVERNED_EFFECT`): each denied consume or
projection denial appends exactly one audit record — a
governed effect (evidence production), append-only, with
`authority_effect=none` and no capability accumulation —
assessed separately from governed external consequences
throughout.

## 4. Exact success and adversarial evidence

Scenario module `tests/test_azure_apim_incident_scenario.py`
(8 tests, all passing at the worktree head):

- positive control: the one authorized act (the operator
  reads the instance's identity-provider client secret under
  the live engagement) executes exactly once; the permit is
  recorded bound to the directive at issuance; replay of the
  spent permit is denied; the audit chain verifies.
- step 1: the stolen credentials with no permit get nothing.
  The direct management token and the subscription key —
  both valid credentials in the incident — are each refused
  at consume as fabricated tokens (`permit_rejected`,
  reason `permit_signature_invalid`, bound to the target
  read's intent hash), and the attacker naming itself as
  principal is denied at the projection
  (`directive_principal_mismatch`): holding the instance's
  credentials does not make the attacker the engagement's
  operator, and no minting route exists for it.
- step 2: exact-intent binding. A genuine permit issued for
  a different named secret is refused for the target read at
  the kernel's token-to-intent binding
  (`permit_intent_mismatch`, a kernel-layer refusal — the
  store is never reached), and the reverse presentation
  fails the same way; the projection refuses to mint at all
  for the second instance's identical secret
  (`directive_resource_not_allowed`) and for a write against
  the very secret the engagement may read
  (`directive_action_not_allowed`). Both genuine permits
  still spend afterward on the exact reads they were issued
  for — the denials were scope, not lockout.
- step 3: revocation at consume. A genuine, unexpired,
  unspent permit presented after the owner revokes the
  engagement mid-window is refused twice, each rejection
  carrying the store's `directive_status`
  `directive_revoked`; new issuance is denied on the same
  ground and the denial is recorded. Revocation is enforced
  where the act would happen, not merely at issuance.
- step 4: the spent permit and the stolen strings replay
  for nothing, inside the window and inside the permit's
  signed expiry: the spent permit's rejection carries
  `directive_status` "active" (the engagement was live; the
  spend itself was the bar) and the strings are refused as
  fabricated, exactly as in step 1. What was stolen is not a
  standing capability, so there is nothing standing to
  steal.
- step 5: the incident channel sees the campaign — freezing
  a report over the full attempt sequence (the attacker's
  minting attempt; the cross-instance and write-action
  minting attempts; every exposed secret class attempted
  with both stolen tokens and with the wrong-intent permit;
  the wrong-secret permit against the target read; the one
  legitimate execution; the spent-permit replay; and the
  post-revocation consume and issuance attempts) yields
  zero incidents and exactly the near-miss records the
  channel's derivation produces from the audit:
  18 `permit_rejected` and 4 `directive_denial` (22
  near-misses in total), each classified Recorded under a
  valid audit chain; the freeze appends nothing. The counts
  are from the executed run at this head, not estimates;
  the reporting sequence replays every variant by
  construction (the lesson of the Codex P2 on PR #378,
  applied at first submission here rather than by
  amendment).
- step 6: the stolen material persists without becoming
  authority — in a later session on a fresh kernel, where
  no engagement has been activated at all, both stolen
  strings are refused again and the projection denies
  issuance (`directive_not_authorized`). Leftover
  credential material does not retire itself, and its
  survival past the mitigation changes nothing about what
  it is: never a permit.
- negative control: with consume unguarded at both layers
  (kernel double + intent-blind state double), the target
  secret read EXECUTES under the permit issued for a
  different named secret — the incident's own shape, a
  management plane that answers any read a reached
  credential presents. The denials come from the binding
  layers, not from a harness that denies by construction.

Full suite at the worktree head: **1053 tests, OK
(skipped=25)** — the baseline executed at the base commit
`a0b3bdd` in this environment is 1045 OK (skipped=25); the
delta is exactly the 8 scenario tests. (The skipped count
is environment-dependent: CI at the base commit recorded
skipped=13 for the same 1045-test suite, per PR #382's
commit record. The test count and the OK result are
identical in both environments.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — no control depends on how the caller reached the
  management plane: a stolen direct management token and
  the operator's own are indistinguishable as authority
  artifacts, and neither mints anything; authority arrives
  only as per-act permits bound under a live engagement.
  The incident's own flip is that the store built to hold
  the instance's secrets became the inventory the attacker
  read first.
- Reverse — the read requires a consumed permit bound to
  the exact intent; the earliest unreachable point is the
  first unauthorized read (denied at consume and at
  issuance), and the chain does not collapse to one control:
  the genuine permit cannot be re-aimed at another secret
  (step 2), cannot be spent after retirement (step 3), and
  cannot be replayed after use (step 4).
- Invert — outcome is not legitimacy: an API response
  carrying a secret value would be "success" by outcome,
  but the governed record supports credit only for consumed
  acts (exactly one: the approved client-secret read), so
  any claim that the incident's reads were authorized is
  unsupportable against the audit and visible as such in
  the incident channel (step 5).
- Inside-Out — the governor cannot originate the authority
  it enforces: the attacker naming itself as principal is
  denied at the projection (step 1); a stolen credential
  string cannot produce a permit, an approval, or ceremony
  evidence at all; the test verifiers are test-only; the
  orchestrator surface used for the incident report is
  read-only and its freeze is asserted to append nothing
  (step 5).
- Darken — worst credible bounded case: the flaw window ran
  from identification on 2026-11-18 to mitigation on
  2026-11-19 (Recorded), across every Classic instance not
  configured to recommended practices, at API tempo — and
  the credentials taken inside it remained valid after it
  closed. Inside the governed path the maximum consequence
  remains the one authorized read; every other attempt
  produces exactly one audit record and zero consequences,
  and retirement closes even the unspent remainder (step
  3). Outside the governed path stands the incident's real
  worst case — a management plane that checks credential
  validity and nothing else — and this replay does not
  mitigate it; it is the boundary in §5.
- Lighten — minimum benign interpretation: a management
  plane that sincerely treats any valid instance credential
  as the operator's standing authority, for convenience.
  The kernel still denies every unauthorized read, because
  a standing credential, however sincere, is not a per-act
  approval — and a store in which every secret answers to
  the same credential is what standing authority
  accumulates. The positive control shows the governed path
  exists: approve the exact reads intended.
- Amplify — the flaw replicated across every reachable
  instance at once; permits are per-intent, per-session,
  and single-use, and engagements are per-instance in
  scope, so replication multiplies attempts, never
  authority. Denial volume produces audit growth only, one
  record per attempt.
- Negate — the smallest clean path: the legitimate purpose
  (an operator reading the secrets its work requires) needs
  only per-read permits for the exact secrets intended. A
  standing management credential that can read every stored
  secret, and credential material that stays valid after
  the engagement that justified it ends, are both
  unnecessary.

Stop/continue decision: CONTINUE in the governed kernel path
only.

## 5. Boundary the evidence does not prove

The scenario models management-plane acts presented for
consumption on the governed path. It proves nothing about
Azure, API Management, the flaw itself, any instance, any
tenant data, or any exploit, and it reproduces no part of
the vulnerable service: the replay models the authorization
layer, not the vulnerability. It proves nothing about
non-governed paths — the real incident's management plane
checked credential validity and nothing about which acts
the caller was authorized for, and an endpoint like that is
governed by nothing here; a control not on the execution
path governs nothing. It also does not speak to invalidating
credentials in systems that have already issued them as
standing material: the governed path's answer is that the
authorization was never the credential, and that revocation
binds at consume — it cannot retroactively retire a token
some other system still honors.

One surfacing boundary, recorded rather than smoothed over:
this scenario's attempts route through `consume` and the
directive projection, both of which the incident channel
derives near-misses from, so step 5's coverage is complete
on these routes. The bare-`evaluate` route — a
`require_approval` decision, audit-recorded but not derived
as a near-miss (issue #375) — is not exercised here, and
this replay neither reproduces that boundary nor claims to
close it.

## 6. Claim classification

- Incident narrative: **Recorded** (Microsoft's advisory as
  reported by BleepingComputer, 2026-11-23, and NSM's
  public notice as reported in the same coverage — the
  primary reporting of the disclosing sources; this record
  follows that reporting's wording, including the warning
  that mitigated instances' already-taken credentials are
  not invalidated).
- Number of affected instances or customers: **Unknown** —
  not disclosed in the sources used.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The mapping from the incident's pattern to kernel intents
  (each exposed secret class modeled as a distinct named
  resource inside the intent identity; the instance inside
  that identity; a management credential or subscription
  key modeled as no authority artifact at all; retirement
  of the engagement modeled as directive revocation):
  **Inferred** — the harness's modeling choices, stated in
  the module docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and assertion
style mirror the canonical scenario modules merged in PRs
#346–#350, #362–#368, and #374–#382 — the directive
engagement, projection issuance, revocation-at-consume, and
campaign-freeze construction of PR #377 (Barracuda), and
the credential-presented-as-permit and later-session
constructions of PR #379 (Entra) — including their
per-module helper-duplication pattern.

## 8. Temporal-transfer evidence

Executed 2026-11-23. The applicable historical checkpoint
is this branch's exact base, `a0b3bdd`: the bindings the
scenario exercises (exact-intent binding, single-use
consumption, directive revocation at consume, projection
scope denial) all predate this change, so the checkpoint
comparison AGENTS.md requires was runnable and has been
run.

Method: a clean worktree was reconstructed at exactly
`a0b3bdd` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module). The scenario was run there under the canonical
command, then the full suite. Baseline at `a0b3bdd` without
the lesson is the 1045 OK (skipped=25) executed in this
environment; the branch adds no kernel code, so any
behavioral difference at the checkpoint would have been a
finding, not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 8 scenario tests pass identically at
  `a0b3bdd` — the stolen-credential refusals, the
  attacker-principal minting denial, the cross-secret and
  cross-instance and write-action denials, the
  revocation-at-consume refusals, the spent-permit replay
  denial, the positive control executing exactly once, the
  later-session step, the negative control executing when
  unguarded, and the incident channel's 0 incidents / 22
  near-misses. Full suite at checkpoint-plus-lesson: 1053
  OK (skipped=25), identical to the worktree head; the
  delta over the 1045 baseline is exactly the 8 scenario
  tests.
- NO EFFECT: the lesson is tests and documentation only;
  it changes no kernel behavior at the checkpoint or at
  the head, and consequential authority is unchanged by
  the replay itself (`authority_effect=none` at both
  states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not smoothed:
  the §5 bare-evaluate near-miss derivation boundary
  (issue #375) is a property of the base-era incident
  projection, present at `a0b3bdd` exactly as at the head,
  on a route this scenario does not exercise — the replay
  neither introduces nor widens it.

The evidence is therefore valid at the checkpoint and at
the worktree head; reuse of the lesson at a later commit
still requires re-evaluation there.

# Change record — Incident replay: 1Password backend intrusion via a compromised corporate GitHub account (November 2026)

Base: `origin/main` at `d7b7506` (incident replay:
OpenSSH SSHole CVE-2026-123158, PR #393).
Authority: Austin Irvan, owner of Ironnember/Pulpo1.0,
confirmed directly in the main chat on Nov 25, 2026
at 17:12 MST, in response to the execution-risk
notice itself: "Confirmed — build 1Password and
Railway despite the notice" (earlier the same day,
15:34 MST: "Go and build on number 2"). Test-only
change: one scenario module plus this record. No
production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from 1Password's own published
update on the incident): on November 19, 2026,
1Password began investigating indications that an
attacker had gained access to an employee's
corporate GitHub account. The actor used the account
to access source code and push malicious code to
backend services; the pushed code downloaded
administrative data pertaining to customers. The
downloaded account records covered a subset of users
and included names and email addresses; account and
user identifiers, and account creation and last
sign-in times; public keys (public by design);
Secure Remote Password protocol parameters (which,
per the post, cannot be used to access an account);
tokens present in certain emailed links for
invitations, provisioning, and account recovery
(usable, per the post, only combined with an SSO
sign-in or a code sent to the user's registered
email address); and other non-secret account
metadata. The attacker also copied source code from
private repositories and gained access to the CI/CD
system, which holds infrastructure-related secrets;
1Password triggered a rotation of all credentials
which may have been exposed, disabled the affected
GitHub account, revoked a stolen token, and removed
the access the attacker created. It also lengthened
invitation/recovery codes from six digits to ten
alphanumeric characters and recorded validation of
no internal evidence of user account takeovers using
the exposed provisioning tokens. What was NOT
affected (Recorded, same source): customer vaults
and the items in them; the keys that protect vaults
(1Password does not store the account password or
Secret Key); account recovery keys; and the
1Password apps and browser extensions. How the
attacker first gained access to the GitHub account
is not stated in the post — **Unknown** — and this
replay does not model the account compromise. It
models the boundary that must hold even when an
account is fully controlled by an attacker.

Failure addressed: **a trusted account is not an
authorization to deploy.** This is a trusted-path
execution failure: code was pushed to production
backend services and executed after arriving through
a trusted channel — a genuine corporate account on
the corporate code host. What the post establishes
(Recorded) is the push and its consequences. The
deployment pipeline's authorization mechanism is
not described in the post: that the channel's trust
was itself the authorization — a push from the right
account deploying with no per-action authorization
by a named accountable human bound to the exact
change — is **Inferred**, and it is the model this
scenario tests (classified in §6). On that model,
account identity answered "who pushed"; nothing
answered "was THIS change, exactly, approved by the
human accountable for it" — and under full account
compromise the first answer is the attacker's to
give. The governing invariants are
the fail-closed rule of AGENTS.md (unknown,
malformed, untrusted, expired, replayed, or
unavailable authority fails closed through the
canonical kernel), the rule that no governed agent
may create, derive, invoke, or impersonate a human
signing credential (account control confers no
approval key), and the exact-intent binding itself:
under the kernel, deploying a code change to a
backend service is a consequential action requiring
a permit issued only after a verified approval bound
to the exact change — repository, commit, source,
and content hash, all carried in the intent's
resource string so the intent hash binds all four. A
different commit through the same account, or the
reviewed commit identifier carrying substituted
content, makes a different intent whose approval
does not exist, so deployment is refused and the
refusal is recorded.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds
a test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately
ungoverned double (`AccountTrustDeployer`) exists
solely as the negative control, is test-local, and
is never imported by runtime code — the same pattern
as PRs #346 and #362–#403.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`,
audit read, and incident-channel derivation paths,
and adds no writer, route, ledger, executor, or
state backend. The scenario's `DeployExecutor` is a
test harness: it records a consequence only after a
successful kernel consume and holds no canonical
state. (At the §9 fix-pass head the executor also
derives the artifact identity from the presented
bytes before consume — a harness-local comparison
against the intent's bound hash; it writes nothing.) The incident-channel freeze is asserted
read-only in the scenario itself (audit length
unchanged across the freeze). Audit growth is
classified in the module docstring per AGENTS.md
(`NO_PERMIT != NO_GOVERNED_EFFECT`): each denied
attempt appends audit records — a governed effect
(evidence production), append-only, with
`authority_effect=none` and no capability
accumulation — assessed separately from governed
external consequences throughout. The count is per
route, not uniformly one: a bare `evaluate`
returning `require_approval` appends one decision
record; a `consume` rejection appends one
`permit_rejected` record; a denied approval-envelope
evaluation appends two records — an
`approval_rejected` record and a denied decision
record. Growth stays bounded per attempt (at most
two records), which is the invariant the scenario
pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_1password_backend_intrusion_incident_scenario.py`
(8 tests, all passing at the worktree head):

- positive control: the one authorized act
  (deployment of the exact reviewed change) executes
  exactly once under a genuine, well-formed verified
  approval envelope; replay of the spent permit is
  denied; the audit chain verifies.
- step 1: with no approval at all, `evaluate` of the
  attacker's change returns `require_approval` with
  no permit minted, and nothing deploys. A push is
  not an approval.
- step 2: the genuine approval for the reviewed
  change, presented for the attacker's change pushed
  through the same trusted account to the same
  repository (the incident's route — every channel
  signal identical, only the change different), is
  denied (`approval_intent_mismatch`); the genuine
  pair still admits afterward.
- step 3: the substitution in both of its forms.
  Declared: the genuine approval presented for the
  reviewed commit identifier carrying the attacker's
  substituted content hash is denied
  (`approval_intent_mismatch`) — the label a reviewer
  saw, with content no reviewer saw. Undeclared: the
  approved intent itself, with its genuine permit,
  but the attacker's bytes handed to the deployer —
  every declared signal genuine, only the content
  false — is refused at the consequence boundary:
  the executor derives the artifact identity from
  the actual bytes (SHA-256) and compares it against
  the content hash bound in the intent, refusing
  before any permit is consumed. The refusal spends
  nothing: the genuine bytes then deploy under the
  same permit, exactly once. (This form was added in
  the §9 fix pass; at the original head the executor
  trusted the intent's declared resource string and
  this catch did not exist.)
- step 4: an approval envelope for the attacker's
  change signed with an unauthorized (attacker) key
  is denied (`approval_signature_invalid`). Whoever
  controls the GitHub account cannot mint the deploy
  authority: the accountable human's key is a
  different thing from the account's session.
- step 5: multiplicity — the spent permit
  re-presented for the same change deploys nothing
  and consumes nothing a second time; reconciliation
  is per-item counted (`Counter` / multiset), never
  set-based: an exact claim reconciles, a claim
  listing the same consumed change twice is a
  phantom of count exactly 1, and an empty claim
  under-reports by exactly 1. A set-based check
  would collapse the duplicate and report a match.
- step 6: the incident channel sees the attempts —
  freezing a report over the full attempt sequence
  exercisable on one kernel (the no-approval
  evaluation, the genuine-approval mismatch, the
  forged envelope, the trusted account's name
  presented as a permit, the one legitimate
  deployment, and the spent-permit replay) yields
  zero incidents and exactly the near-miss records
  the channel's derivation produces from the audit:
  2 `permit_rejected`, 2 `approval_rejected`, and 2
  denied `decision` records, plus 1 `require_approval`
  `decision` record (7 near-misses in
  total), each classified Recorded under a valid
  audit chain; the freeze appends nothing. The step
  also pins the surfacing boundary stated in §5: the
  sequence's 1 `require_approval` decision is
  present in the audit and contributes one
  near-miss record since the issue
  #375 fix (PR #413; §10). The counts are from the executed
  run at this head, not estimates.
- negative control: with the governed boundary
  swapped for the inferred model of the incident — a
  test-local deployer that authorizes deployment by
  the pushing account alone, as a trusted-channel
  pipeline on that model does — the attacker's
  change DEPLOYS, and so does the reviewed commit
  carrying substituted content, while an outside
  account does not pass. The
  double's defect is that the account is all it
  checks: it cannot tell a reviewed change from an
  attacker's change arriving through the same
  genuine account, which is the one distinction the
  incident turned on. The denials in the steps above
  therefore come from the exact binding (repository
  + commit + source + hash), not from a harness that
  denies by construction.

Full suite at the worktree head: **1147 tests, OK
(skipped=13)** in this environment — the recorded
local baseline at the base commit `d7b7506` in this
same environment is 1139 OK (skipped=13); the delta
is exactly the 8 scenario tests. (Skipped counts are
environment-dependent; other environments record
skipped=25 at the same base with the same test
totals. The comparison here is same-interpreter,
same environment, before and after.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — the incident is itself a flip: the account
  was genuine while the change was malicious; every
  channel check saw the right identity and never saw
  the change. On the governed path the flip has
  nowhere to live: the change identity is inside the
  bound intent (steps 2–3), so swapping the change
  under a genuine account swaps the intent and voids
  the approval.
- Reverse — the consequence requires a consumed
  permit; the permit requires a verified approval;
  the approval binds the exact change and the
  accountable human's key, which the pushing account
  does not hold. The chain does not collapse to one
  control: the no-approval route (step 1), the
  attacker's change under a genuine approval (step
  2), the substituted content (step 3), and the
  forged key (step 4) are each stopped at a distinct
  check, and the spent permit cannot be replayed
  (positive control, steps 5–6).
- Invert — outcome is not legitimacy: the incident's
  pushes "succeeded" by outcome and were wholly
  unauthorized; the governed record supports credit
  only for consumed acts under verified approvals
  bound to the exact change, so any claim that a
  deployment was authorized because the account was
  genuine is unsupportable against the audit and
  visible as such in the incident channel (step 6).
- Inside-Out — the governor cannot originate the
  authority it enforces: a GitHub account, a push,
  or a pipeline cannot produce an approval envelope
  or ceremony evidence at all; the account's name
  presented as a permit is rejected at consume (step
  6); the test doubles are test-only; the
  orchestrator surface used for the incident report
  is read-only and its freeze is asserted to append
  nothing (step 6).
- Darken — worst credible bounded case: the trusted
  channel reached backend customer data for a subset
  of users and a CI/CD system holding
  infrastructure secrets; a deploy pipeline with
  production reach is among the highest-consequence
  surfaces an account can hold. Inside the governed
  path the maximum consequence per approval remains
  the one authorized deployment of the one exact
  change; every unauthorized attempt produces audit
  records only — one per attempt on the
  bare-evaluate and consume routes, two on the
  denied approval-envelope route — and zero
  consequences. Outside the governed path stands
  the inferred model's worst case — a pipeline that
  deploys on account trust — and this replay does
  not mitigate it; it is the boundary in §5.
- Lighten — minimum benign interpretation: employees
  push code through corporate accounts all day; that
  is ordinary work, not an attack. Nothing in the
  governed path bans pushes, accounts, or pipelines:
  the positive control shows deployment proceeding
  normally when a named accountable human has
  approved the exact change. What is refused is only
  deployment that no accountable human approved, of
  a change no one reviewed.
- Amplify — a compromised account can push to many
  services at once and retry indefinitely; approvals
  are per-change and permits single-use, so
  replication multiplies attempts, never authority.
  Denial volume produces audit growth only, bounded
  per attempt, and duplicate presentations never
  double-count or double-authorize (step 5).
- Negate — the smallest clean path: deployment must
  be authorized against the exact change that will
  run — repository, commit, source, and hash — by a
  named accountable human whose key the pushing
  account does not hold. Account trust is
  unnecessary as authority on the deploy path —
  remove account-as-authority and the incident's
  push deploys nothing.

Stop/continue decision: CONTINUE in the governed
kernel path only.

## 5. Boundary the evidence does not prove

The scenario models approval artifacts presented for
deployment at a governed kernel boundary. It proves
nothing about GitHub, any code host, any CI/CD
system, or any deployment pipeline, and it
reproduces no part of the malicious code or the data
download — the push, the download, and the CI/CD
reach are described from the source, not reproduced.
It governs the deployment before it happens, not the
compromise afterward: the downloaded data and the
CI/CD access were consequences of code already
running. It does not speak to the account compromise
itself: how the attacker first gained access to the
GitHub account is **Unknown** (not stated in the
source) and is not modeled; the scenario's claim is
narrower and stronger for it — the deploy boundary
holds even under total account compromise, because
approval authority never lived in the account. It
also does not speak to the exposed emailed-link
tokens (a separate surface, whose use the source
records as additionally gated and unexploited) or to
credential rotation after the fact.

The scenario's artifact identities are harness
constructions, stated plainly (the wording
discipline of PR #403 applied from the start): the
incident post publishes no commit SHA and no content
hash for any change, reviewed or malicious — a
Recorded absence. The binding proof is therefore a
proof about the kernel's treatment of exact
identities in the incident's shape, and it claims
nothing about any real 1Password commit, hash, or
repository. Whether any given production pipeline
binds deployment to exact change identity is an
audit question for that pipeline; this scenario pins
only that the canonical kernel's exact-intent
binding gives a trusted account's unauthorized
change nothing to travel on. A control not on the
execution path governs nothing.

One surfacing boundary, stated plainly rather than
smoothed over (Verified at this commit, by
executable probe, by the channel's derivation
source, and by step 6's pinned counts): a bare
`evaluate` that returns `require_approval` — the
kernel declining to mint a permit without approval
— appends a decision record to the canonical audit,
where it is complete and chain-verified, but the
incident channel does NOT derive a near-miss record
from it; the channel derives near-misses from
`permit_rejected`, `approval_rejected`, denied
decisions, and `directive_denial`. The act is still
stopped — no permit exists to spend — so this is a
derivation-coverage boundary in the owner-facing
channel, not an authorization gap (issue #375).
Whether a `require_approval` decision should also
surface as a near-miss is a design question for the
channel's maintainers; this replay records the
behavior exactly as it stands and takes no position
by silently engineering around it.

## 6. Claim classification

- Incident narrative: **Recorded** (1Password's own
  published update: the November 19, 2026
  investigation start; the employee corporate GitHub
  account used to access source code and push
  malicious code to backend services; the downloaded
  data classes as enumerated in §1; source code
  copied from private repositories; CI/CD accessed;
  the credential rotation; the account disabled, the
  stolen token revoked, and attacker-created access
  removed; the invitation/recovery code lengthening;
  the validation of no evidence of account takeovers
  via the exposed provisioning tokens).
- What was not affected (vaults and items, vault
  keys, account passwords and Secret Keys, account
  recovery keys, apps and browser extensions):
  **Recorded** (the post's "What was not affected").
- How the attacker first gained access to the
  GitHub account: **Unknown** — not stated in the
  source. (That a token was stolen is **Recorded**
  from the remediation section; the initial access
  vector is not specified.)
- Scale of the download: a subset of users
  (**Recorded**); no user count is published in the
  post (Recorded as an absence) and no count is
  asserted anywhere in this change.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree
  head commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 6).
- The scenario's artifact identities (repository,
  commits, hashes): harness constructions in the
  incident's shape — the post publishes no commit or
  hash for any change (Recorded absence), and no
  identity here is presented as a real 1Password
  artifact.
- The mapping from the incident's pattern to kernel
  artifacts (deployment of a code change modeled as
  the consequential act; change identity — repository,
  commit, source, hash — carried in the intent's
  resource string; the reviewed change modeled as
  the approved artifact and the attacker's push as a
  distinct intent through the same account):
  **Inferred** — the harness's modeling choices,
  stated in the module docstring.
- The deployment pipeline's authorization mechanism
  (account trust alone authorizing deployment, a
  push deploying automatically, no per-action
  approval in the loop): **Inferred** — the post
  does not describe the mechanism; the negative
  control reproduces this inferred model, not a
  verified property of 1Password's pipeline.
  (Classified explicitly in the §9 fix pass.)
- Any claim that this prevents the incident class
  in a deployed system: **Proposed** — not made by
  this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no
legacy control path was copied. Structure, helpers,
and assertion style mirror the canonical scenario
modules merged in PRs #346–#350, #362–#368,
#374–#382, #386, and #393, and the replay built in
PR #403, including their per-module
helper-duplication pattern, the reporting-coverage
construction of PR #378's step 6 as amended, and
the negative-control double construction of PR #386
and #393. The per-item (`Counter`) reconciliation
follows the multiplicity discipline of the merged
replay suite.

## 8. Temporal-transfer evidence

Executed 2026-11-25. The applicable historical
checkpoint is this branch's exact base, `d7b7506`:
the bindings and verification checks the scenario
exercises (exact-intent binding, single-use
consumption, approval verification, the
approval-envelope structural checks) all predate
this change, so the checkpoint comparison AGENTS.md
requires was runnable and has been run.

Method: a clean worktree was reconstructed at
exactly `d7b7506` (no tree rewriting; `git status`
verified the only delta from the checkpoint was the
copied scenario module). The scenario was run there
under the canonical command, then the full suite.
Baseline at `d7b7506` without the lesson in this
environment is 1139 OK (skipped=13); the branch adds
no kernel code, so any behavioral difference at the
checkpoint would have been a finding, not an
expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 8 scenario tests pass identically
  at `d7b7506` — the positive control deploying
  exactly once, the no-approval denial, the
  attacker-change binding failure, the
  substituted-content binding failure, the
  forged-approval denial, the multiplicity probe
  (duplicate presentation neither double-deploys nor
  double-counts), the incident channel's 0 incidents
  / 6 near-misses, and the negative control deploying
  under the account-trust deployer double. Full
  suite at checkpoint-plus-lesson: 1147 OK
  (skipped=13), identical to the worktree head; the
  delta over the 1139 baseline is exactly the 8
  scenario tests.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the
  checkpoint or at the head, and consequential
  authority is unchanged by the replay itself
  (`authority_effect=none` at both states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not
  smoothed: the §5 bare-evaluate near-miss gap
  (issue #375) is a property of the base-era incident
  projection, present at `d7b7506` exactly as at the
  head — the replay neither introduces nor widens
  it.

The evidence is therefore valid at the checkpoint
and at the worktree head; reuse of the lesson at a
later commit still requires re-evaluation there.

## 9. Post-review fix pass (Codex P1 + P2 on PR #404, 2026-11-25)

Two Codex findings on the original head `df69a76`,
both accepted and fixed in the scenario module and
this record; no kernel code touched
(`authority_effect=none` throughout).

- **P1 — bind the deployed bytes, not
  caller-supplied metadata.** At the original head
  the `DeployExecutor` received only the caller's
  `Intent` and recorded its declared resource
  string, so step 3 caught only an attacker who
  truthfully declared the substituted hash. The
  executor now takes the actual artifact bytes,
  derives their SHA-256 at the consequence
  boundary, and compares it against the content
  hash bound in the intent before consume; the
  scenario's content hashes are now the real
  digests of the harness byte strings, computed in
  the module. Step 3 exercises both substitution
  forms: the declared form (a substituted-hash
  intent under the genuine approval —
  `approval_intent_mismatch`, unchanged) and the
  undeclared form (the approved intent and its
  genuine permit presented with the attacker's
  bytes — refused at the boundary before consume,
  the permit unspent, the genuine bytes then
  deploying under the same permit exactly once).
- **P2 — classify the account-only deploy rule as
  Inferred.** The incident post establishes the
  push and its consequences (Recorded); it does
  not establish that account trust was the
  pipeline's authorization mechanism, that a push
  deployed automatically, or that no per-action
  approval existed. §1, §4, §6, the module
  docstring, and the negative-control wording now
  classify that mechanism as **Inferred** — the
  model the scenario tests and the negative
  control reproduces — not incident fact.

Re-verification at the fix-pass head: scenario 8/8;
full suite 1147 OK (skipped=13) in this
environment — identical totals to the original
head (the pass changed test internals and wording,
added no tests), delta over the `d7b7506` baseline
still exactly the 8 scenario tests. Temporal
transfer re-run per §8's method: the amended
scenario passes 8/8 at the exact base `d7b7506`,
so the §8 transfer result stands for the amended
module.

## 10. Addendum — #413 near-miss derivation pin refresh (2026-11-27)

Cause (Verified): PR #413 (merged 2026-11-26 as
`b1cea2f`, fixing issue #375) changed the incident
channel's derivation so a `decision` record with
outcome `require_approval` derives one near-miss per
occurrence, mirroring the deny path. This branch was
built before #413 and pinned the pre-#413 total;
step 6 failed deterministically at the old head
(6 != 7). The delta is exactly this scenario's 1
`require_approval` decision — the same update shape
#413 itself applied to its twelve scenarios.

Change (test pins and this record only; no kernel or
production code touched; `authority_effect=none`):
step 6's near-miss identity and `decision`
source-detail count now include
`len(require_approval_decisions)`; the pinned total
moves 6 → 7; the module docstring and §4 counts
state the new derivation. §5 and §8 describe the
pre-#413 boundary and checkpoint states as they
stood when recorded and are left as written; this
addendum supersedes them for the current head.

Re-verification at this head: scenario 8/8; full
suite **1183 tests, OK (skipped=13)**.

## Sources

- 1Password, "Update on a security incident
  involving 1Password's backend systems" (November
  2026):
  https://1password.com/blog/update-on-nov-2026-security-incident

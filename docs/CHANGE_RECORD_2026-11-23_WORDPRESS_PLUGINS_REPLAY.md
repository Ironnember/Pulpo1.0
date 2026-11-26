# Change record — Incident replay: WP connect WordPress plugins supply-chain backdoor (publicized 2026-11-23)

Base: `origin/main` at `a0b3bdd` (incident replay:
OpenRouter inference-provider incidents, PR #382).
Authority: Austin approved this build on 2026-11-23 ("Build
the replay PR," extended to all three surfaced candidates
the same evening, with an explicit go-ahead to execute in
this checkout at 19:41 MST after a prior builder stopped at
an execution-risk flag on the fresh clone). Test-only
change: one scenario module plus this record. No production
code is touched.

**READ FIRST — the caveat.** The backdoored versions in
this incident were **never released to sites**.
WordPress.org's Protect The Shire cooling-off release hold,
together with its Gandalf automated reviewer, stopped the
releases; all six plugins were closed the same evening, and
no exploitation of live sites has been reported. This
replay claims Pulpo caught nothing in the real event. The
release hold is the real-world analogue of the gate the
scenario models — a pre-distribution check that does not
take the publisher's say-so as the release's authority —
and the replay is of the mechanism, with the caveat carried
throughout, per the caught-before-distribution precedent of
PR #380 (@leadstack).

## 1. Invariant or failure addressed

Incident (Recorded, from Wordfence's report, "Supply Chain
Compromise Backdoors Six WP Connect Plugins," 2026-11-23 —
the disclosing researcher's primary statement): on
2026-11-22, over roughly two hours (about 4:30–5:40 PM ET),
backdoored releases of six WordPress plugins from the same
connect-plugin family were committed to WordPress.org from
the developer's own account: Air WP Sync (`air-wp-sync`)
2.9.1–2.9.4, WP Sync for Notion (`wp-sync-for-notion`)
1.7.4, Add-on Brevo for Gravity Forms 2.6.3, Add-On for
Contact Form 7 to Airtable 2.5.4, Add-On for Contact Form 7
to Notion 1.6.4, and Orders Sync to Airtable for WooCommerce
1.0.2 — more than 3,600 active installs combined. Each
backdoored release added one file,
`includes/airwp-online.php`, plus one `require_once` line.
The added module hooks `init` and a half-hourly cron event,
POSTs a site fingerprint (site URL, PHP, WordPress and OS
versions, server user) to tascredit-pay.com with TLS
certificate verification disabled, and `eval()`s whatever
PHP the server returns; the reported command set includes
shell execution, file read/write/delete, database dump
including password hashes, webshell drop, and hourly
persistence. CVE-2026-135202, CVSS 9.8.

Attribution grading: that the developer's account was
compromised is **Recorded/reported, not Verified** —
Wordfence states the evidence "strongly suggests" the
account was compromised and the developer reports that it
was; details are pending. The scenario does not depend on
the attribution: the failure modeled is identical whoever
held the account.

Failure addressed: **a publish through a trusted channel
inherited its authority from the account and the channel,
not from an authorization for the exact act.** The account
authenticated the publisher but authorized no specific
release, so whoever held it could publish arbitrary code as
official updates to more than 3,600 sites; the backdoored
releases presented under genuine version labels, because
nothing bound distribution to the exact artifact bytes
anyone had reviewed; and sites would have installed them
because the channel is trusted, not because the specific
act — this artifact, this version — was authorized. The
governing invariants are `AUTHORIZED_OUTCOME !=
AUTHORIZATION_FOR_ARBITRARY_MEANS`, `ACCESS !=
AUTHORITY_FOR_THE_SPECIFIC_ACT`, and the exact-intent
binding itself: under the kernel, each publish requires its
own permit bound to the exact intent — principal, action,
resource (plugin, version, and the digest of the artifact's
actual bytes together), cost, session — rechecked at
consume and spent on use, so a tampered artifact, a
different version, a different plugin, or the account
credential itself is a different intent, or no authority
artifact at all, and one permit cannot be spent as any of
them. Denial is fail-closed at evaluate/consume, at
distribution time — the same point in the path where the
real release hold intervened.

Scope discipline, stated up front: this replay models the
authorization the distribution path lacked. It does not
model WordPress.org's review pipeline, the Gandalf
reviewer, or the cooling-off hold's own mechanics, and it
claims nothing about the real event beyond the mechanism —
in which, per the caveat above, the hold is what stopped
the releases and no site was reached.

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
governed external consequences throughout. The count is per
route, not uniformly one: a bare `evaluate` returning
`require_approval` appends one decision record; a
policy-denied `evaluate` appends one denied decision
record; a `consume` rejection appends one `permit_rejected`
record; a denied approval-envelope evaluation appends two
records — an `approval_rejected` record and a denied
decision record. Growth stays bounded per attempt (at most
two records), which is the invariant the scenario pins.

One kernel behavior the scenario exposes and pins rather
than fixes (it is pre-existing, at the base commit, and
outside this change's test-only scope): AgentGrant resource
matching is prefix-based (`str.startswith`, kernel
`_policy_failure`). A resource formed by appending a suffix
to the authorized release identity therefore passes the
grant layer. Step 3 pins this exactly — the suffixed
resource reaches `require_approval` at evaluate rather than
the scope denial a genuinely distinct plugin identity
receives, and is denied at consume by the exact-intent
permit binding. See §5 for the claim boundary this imposes,
and §8 for its identical presence at the base checkpoint.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_wordpress_plugins_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the one authorized act (one exact
  plugin, version 2.9.0, one exact artifact) distributes
  exactly once under a verified approval envelope; replay
  of the spent permit is denied; the audit chain verifies.
- step 1: the unapproved publish is denied on every
  route — `evaluate` returns `require_approval` with no
  permit minted, and the developer's account credential
  itself, presented as a permit, is rejected at consume
  (`permit_rejected` bound to the backdoored intent's
  hash). Possession of the account is not a permit — the
  incident's exact failure, in which the account was the
  only authority artifact on the path.
- step 2: the approved intent and the genuine permit
  presented at the governed distribution gate with the
  backdoored artifact bytes — the added module file and its
  `require_once` line, the incident's own additions. The
  gate derives the SHA-256 of the bytes actually presented
  and submits the act those bytes constitute; the genuine
  permit rejects that derived intent at consume (the
  rejection is bound to the derived intent's hash, not the
  approved intent's), and the genuine permit spends
  afterward on its exact intent when the bytes presented
  are the bytes approved. The substitution fails at
  distribution time.
- step 3: scope, in its three shapes. The re-aimed version
  (the approved artifact's bytes published as 2.9.1 — the
  first version number of the incident's backdoored
  sequence) reaches `require_approval` at evaluate and is
  rejected at consume: version is part of the bound
  identity. The different plugin (WP Sync for Notion, a
  genuinely distinct identity sharing no string prefix with
  the authorized plugin) is denied at `evaluate` with
  `agent_resource_not_allowed` (one denied decision record,
  no permit minted) and rejected at consume under the
  genuine permit. The suffixed resource (authorized identity
  plus `/staging`) is pinned as it actually behaves: it
  passes the grant's prefix check (its bare evaluate reaches
  `require_approval`) and is denied at consume by the
  exact-intent permit binding. The permit still spends on
  the exact approved release afterward.
- step 4: the spent permit replays for nothing —
  re-presented for the same release and for the backdoored
  artifact after consumption, both are rejected
  (2 `permit_rejected` against 1 `permit_consumed`). A
  consumed permit is not a reusable publishing credential.
- step 5: an approval envelope for the release signed with
  an unauthorized key is denied
  (`approval_signature_invalid`), and the genuine envelope
  presented for the backdoored artifact's intent is denied
  (`approval_intent_mismatch`); the genuine pair still
  admits afterward.
- step 6: the incident channel sees the campaign — freezing
  a report over the full attempt sequence (every attack
  variant from steps 1–5: all four attack intents on every
  route, step 2's governed-gate route, both approval-envelope
  attempts, and both spent-permit replays) yields zero
  incidents and exactly the near-miss records the channel's
  derivation produces from the audit: 11 `permit_rejected`
  (8 campaign-route rejections, step 2's gate-route
  rejection, plus the 2 spent-permit replays), 2
  `approval_rejected`, and 3 denied `decision` records — the
  different plugin's `agent_resource_not_allowed` scope
  denial and the two step-5 envelope denials
  (`approval_signature_invalid`,
  `approval_intent_mismatch`) — 16 near-misses in total,
  each classified Recorded under a valid audit chain; the
  freeze appends nothing. The step also pins the surfacing
  boundary stated in §5: the sequence's 3 `require_approval`
  decisions are present in the audit and contribute zero
  near-miss records. The counts are from the executed run
  at this head, not estimates; the reporting sequence
  replays every variant and every denial route by
  construction, including the bare-evaluate route in both
  of its shapes (the lesson of the Codex P2 on PR #381,
  applied at first submission here rather than by
  amendment).
- step 7: reconciliation, derived from the canonical audit
  alone. After the backdoored artifact is submitted on both
  of its routes (genuine permit via the gate, account
  credential) and the re-aimed version is submitted under
  the genuine permit — all refused — and the one approved
  release distributes, the audit's `permit_consumed` intent
  hashes are exactly the approved release's hash, once; the
  `permit_rejected` hashes are exactly the backdoored
  intent's hash (twice, one per route) and the re-aimed
  version's hash; the tampered artifact appears only in
  rejections, never in a consumption; and the permitted and
  submitted sets are disjoint and jointly complete. This is
  the question the incident leaves a platform answering
  after the fact — which artifacts were authorized, which
  were merely submitted — answered from the governed record
  rather than from the publisher's account history.
- negative control: the identical presentation as step 2
  (approved intent, genuine permit, backdoored bytes at the
  same gate) with consume unguarded at both layers (kernel
  double + intent-blind state double) DISTRIBUTES — the
  gate still derives the backdoored intent from the bytes,
  and no layer binds the permit to it. That is the
  incident's own shape, a distribution path that publishes
  whatever the account presents, tampered or not. The
  denials come from the real consume path's binding, not
  from the gate's derivation or a harness that denies by
  construction.

Full suite at the worktree head: **1054 tests, OK
(skipped=25 in this worktree's environment)** — the
recorded baseline at the base commit `a0b3bdd` is 1045 OK;
the delta is exactly the 9 scenario tests. (The skipped
count is environment-dependent; the base's own change
record for PR #382 recorded skipped=13 in its run
environment. The pass/fail and total counts are identical
across both.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — no control depends on how the release reached the
  gate: the developer's own account credential and an
  attacker's fabricated token are indistinguishable as
  authority artifacts, and neither mints anything; authority
  arrives only as verified per-release approvals. The
  incident's own flip is that the channel built to deliver
  the developer's updates became the path that would have
  delivered the attacker's.
- Reverse — a distribution requires a consumed permit bound
  to the exact intent; the earliest unreachable point is the
  first tampered or re-aimed publish (denied at evaluate and
  at consume), and the chain does not collapse to one
  control: the genuine permit cannot be re-aimed at another
  plugin (step 3b), another version (step 3a), or a tampered
  artifact (step 2), or replayed after use (step 4).
- Invert — outcome is not legitimacy: a release appearing
  on the distribution list would be "success" by outcome
  even for a backdoored artifact, but the governed record
  supports credit only for consumed acts (exactly one: the
  approved release), so any claim that the tampered or
  re-aimed releases were authorized is unsupportable against
  the audit — and step 7's reconciliation makes that visible
  mechanically, from the audit alone.
- Inside-Out — the governor cannot originate the authority
  it enforces: an envelope signed with an unauthorized key
  is denied (step 5a); an account credential cannot produce
  an approval envelope or ceremony evidence at all; the
  test verifiers are test-only; the orchestrator surface
  used for the incident report is read-only and its freeze
  is asserted to append nothing (step 6).
- Darken — worst credible bounded case: six plugins, more
  than 3,600 installs, one evening's publishing window at
  update tempo, had the real hold not intervened. Inside
  the governed path the maximum consequence remains the one
  authorized release; every tampered, re-aimed, or
  credential-only attempt produces audit records only — one
  per attempt on the bare-evaluate and consume routes, two
  (an `approval_rejected` record and a denied decision
  record) on the denied approval-envelope route — and zero
  consequences. Outside the governed path stands the
  incident's real worst case — the backdoor live on
  thousands of sites — which in the real event was
  prevented by WordPress.org's hold, not by anything here;
  this replay does not mitigate it and does not claim to.
  It is the boundary in §5.
- Lighten — minimum benign interpretation: a developer who
  sincerely wants one account login to carry all of their
  plugins' releases wherever the platform distributes them,
  for convenience. The kernel still denies every unapproved
  publish, because a standing publishing convenience,
  however sincere, is not a per-release approval — and the
  incident is what unbounded publishing convenience
  accumulates when the account changes hands. The positive
  control shows the governed path exists: approve the exact
  releases intended.
- Amplify — the failure replicated across every plugin in
  the family at once (as, in the incident, it was: six
  plugins in about two hours); permits are per-intent,
  per-session, and single-use, so replication multiplies
  attempts, never authority. Denial volume produces audit
  growth only.
- Negate — the smallest clean path: the legitimate purpose
  (publishing a reviewed plugin release to its sites) needs
  only per-release permits for the exact artifact and
  version intended. A standing account credential that
  authorizes any artifact under any version label is
  unnecessary.

Stop/continue decision: CONTINUE in the governed kernel path
only.

## 5. Boundary the evidence does not prove

The scenario models publishes presented for consumption by
a caller on the governed path. It proves nothing about
WordPress, WordPress.org, any plugin, any site, or any real
release, and it reproduces no part of any distribution
service. Four boundaries are stated plainly:

1. **The real event was stopped by a different control.**
   WordPress.org's Protect The Shire cooling-off hold and
   Gandalf automated reviewer — a review-and-hold pipeline,
   not an authorization kernel — are what kept the
   backdoored versions from reaching sites. This replay
   models the authorization layer the path lacked; it does
   not evaluate, reproduce, or take credit for the hold,
   and no wording in this record claims Pulpo caught or
   would have caught the real releases. What the two share
   is a position in the path — before distribution — and a
   refusal to treat the publisher's presentation as
   self-authorizing.
2. **Grant resource matching is prefix-based at this
   commit** (Verified, kernel source and step 3's pinned
   behavior). The scenario's plugin-scope claim is
   therefore exact only in the form the run proves: a
   genuinely distinct plugin identity (no shared string
   prefix with the authorized plugin) is denied at evaluate
   by the grant (`agent_resource_not_allowed`) and at
   consume by the permit binding; a prefix-sharing resource
   passes the grant layer and is denied at consume by the
   permit binding alone. The scenario does not establish
   exact-equality plugin scope in the grant layer, and no
   wording in this record claims it does. Whether grant
   matching should be exact-equality is a kernel design
   question (first surfaced by PR #381's review); this
   replay records the behavior and takes no position by
   silently engineering around it.
3. **Non-governed paths.** A distribution path that
   publishes first and checks never — the incident's own
   shape, absent the hold — is governed by nothing here. A
   control not on the execution path governs nothing. The
   gate also governs only the bytes presented to it: a path
   that derives honestly and then distributes different
   bytes afterward (a post-gate swap) is outside this
   model.
4. **Surfacing boundary (issue #375).** A bare `evaluate`
   that returns `require_approval` appends a decision
   record to the canonical audit, where it is complete and
   chain-verified, but the incident channel does NOT derive
   a near-miss record from it; the channel derives
   near-misses from `permit_rejected`, `approval_rejected`,
   denied decisions, and `directive_denial`. The act is
   still stopped — no permit exists to spend — so this is a
   derivation-coverage boundary in the owner-facing
   channel, not an authorization gap. Step 6 pins it: the
   sequence's 3 `require_approval` decisions contribute
   zero of its 16 near-misses. (The different plugin's bare
   evaluate is the other shape: a policy denial, which IS
   derived — 1 of the 3 denied decisions in the pin.)

## 6. Claim classification

- Incident narrative (the six plugins and versions, the
  added module and its behavior, the install count, the
  commit window, CVE-2026-135202 / CVSS 9.8): **Recorded**
  (Wordfence's report, 2026-11-23 — the disclosing
  researcher's primary statement).
- The release hold's effect (backdoored versions never
  released to sites; plugins closed the same evening; no
  live-site exploitation reported): **Recorded** as
  Wordfence's report of WordPress.org's actions, and
  carried in this record as the operative caveat; the
  scenario's claims do not depend on it beyond refusing, on
  its basis, any claim that the backdoor reached a site.
- That the developer's account was compromised:
  **Recorded/reported** — Wordfence: the evidence "strongly
  suggests" compromise; the developer reports it; details
  pending. Not Verified, and the scenario is constructed so
  no claim depends on it.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The prefix-matching behavior of AgentGrant resource
  scope, and the incident-channel surfacing boundary in §5:
  **Verified** (kernel source at the base commit, executable
  probe, and step 3 / step 6's pinned counts).
- The mapping from the incident's pattern to kernel intents
  (a publish names its plugin, version, and artifact digest
  together in the resource identity, the digest derived with
  SHA-256 from the artifact's actual bytes, modeled as a
  release-manifest byte string; the backdoor modeled as the
  incident's own added file and patch line in those bytes;
  an account credential modeled as no authority artifact at
  all): **Inferred** — the harness's modeling choices,
  stated in the module docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and assertion
style mirror the canonical scenario modules merged in PRs
#346–#350, #362–#368, and #374–#382, including their
per-module helper-duplication pattern, and the
reporting-coverage construction of PR #378's step 6 as
amended, PR #379's step 6, and PR #382's steps 6–7 (every
attack variant and every denial route replayed into the
frozen sequence). The caught-before-distribution caveat
framing follows PR #380 (@leadstack).

## 8. Temporal-transfer evidence

Executed 2026-11-23. The applicable historical checkpoint
is this branch's exact base, `a0b3bdd`: the bindings the
scenario exercises (exact-intent binding, single-use
consumption, approval verification, grant plugin scope) all
predate this change, so the checkpoint comparison AGENTS.md
requires was runnable and has been run.

Method: a clean worktree was reconstructed at exactly
`a0b3bdd` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module). The scenario was run there under the canonical
command, then the full suite. Baseline at `a0b3bdd`
without the lesson, executed in the same environment: 1045
OK (skipped=25); the branch adds no kernel code, so any
behavioral difference at the checkpoint would have been a
finding, not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 9 scenario tests pass identically at
  `a0b3bdd` — the account-credential refusal, the
  backdoored-artifact denial at the gate, the re-aimed
  version's consume rejection, the different plugin's scope
  denial and consume rejection, the suffixed resource's
  grant-pass / binding-denial pin, the spent-permit replay
  denials, the forged/mismatched approval denials, the
  positive control distributing exactly once, the step-7
  reconciliation (tampered intent in rejections only, never
  in a consumption), the negative control distributing when
  unguarded, and the incident channel's 0 incidents / 16
  near-misses. Full suite at checkpoint-plus-lesson: 1054
  OK (skipped=25), identical to the worktree head; the
  delta over the 1045 baseline is exactly the 9 scenario
  tests.
- NO EFFECT: the lesson is tests and documentation only;
  it changes no kernel behavior at the checkpoint or at
  the head, and consequential authority is unchanged by
  the replay itself (`authority_effect=none` at both
  states).
- NEGATIVE TRANSFER: none observed. Two boundaries are
  identical at both states and are recorded, not smoothed:
  the §5 bare-evaluate near-miss gap (issue #375), and the
  §5 prefix-matching behavior of the grant layer — both
  are properties of the base, present at `a0b3bdd` exactly
  as at the head; the replay neither introduces nor widens
  either.

The evidence is therefore valid at the checkpoint and at
the worktree head; reuse of the lesson at a later commit
still requires re-evaluation there.

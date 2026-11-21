# Change record — Incident replay: Barracuda machine-speed intrusion — the unretired vendor key (disclosed 2026-11-11)

Base: `origin/main` at `4603a9f` (kernel build item #2, PR #372 —
the first Pulpo-gated merge; Phase 3 closed). Authority: Austin
directed the build on 2026-11-20 ("Go ahead and help and build")
after the standing incident scan surfaced the disclosure.
Test-only change: one scenario module plus this record. No
production code is touched. Merge remains Austin's separate
decision.

## 1. Invariant or failure addressed

Incident (Recorded, from Barracuda's own disclosure, "Forty-four
hours: Anatomy of a machine-speed intrusion," Barracuda blog,
2026-11-11): as part of a previous project, Barracuda provided a
valid cloud access key to a third-party vendor — a company
working in AI — and did not retire the key when the vendor
finished that work. In October the vendor's own development
environment was compromised, and that appears to be where the
attacker found the key. On November 1 at 04:33 UTC the attacker
made its first call with the key and within minutes was reading
stored secrets (AWS access keys, Azure service principal
secrets). Over the next 24 hours it used each secret it found to
reach the next system: cloud accounts to a data analytics system,
to a source-code access token, to Kubernetes clusters; in the
early hours of November 2 it pushed short-lived branches to
trigger a build workflow that printed the build system's secrets
into the job log. Last recorded activity November 2, 23:31 UTC:
about 10 cloud accounts touched in roughly 44 hours. The tooling
and working pattern matched ARTEX, the open-source AI-driven
penetration-testing framework — a match Barracuda notes describes
how the attacker operated, not who it was. The attacker read
secret stores everywhere, hunted cryptocurrency material,
deployed a backdoor container on a Kubernetes cluster, and tried
to create a new administrative cloud identity; that attempt was
blocked. One system it reached stores the credentials Barracuda
XDR uses to collect data from customers' connected systems;
Barracuda found no direct evidence the attacker viewed them,
could not rule it out from the logging, and treated every
credential within reach as potentially compromised.

Failure addressed: **a credential outlived its purpose.** Access
existed; authority for every post-project act did not. The
governing invariants are `STANDING ACCESS != STANDING AUTHORITY`
and `AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`:
under the kernel, the engagement is a directive with a window,
each act requires its own exact-intent permit issued under that
directive, every permit carries a signed expiry enforced at
consume, revocation of the engagement is enforced at consume (not
merely at issuance), and a permit for one account or act spends
on no other — Barracuda's own stated lessons, rendered as kernel
behavior: "Short-lived, narrowly scoped credentials would have
stopped this intrusion at its first step"; "No single credential
should open the next door."

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a test module
only: no production surface is added, narrowed, or widened; no
permit, policy, directive, or state behavior changes. The
module's deliberately unguarded doubles (`_StandingKeyState`,
`_UnguardedConsumeKernel`) exist solely as the negative control,
are test-local, and are never imported by runtime code — the same
pattern as PRs #346 and #362–#368 and the Cairn replay.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
directive activation/revocation path, the governed directive
projection's `evaluate`, `consume`, audit read, and
incident-channel derivation paths, and adds no writer, route,
ledger, executor, or state backend. The incident-channel freeze
is asserted read-only in the scenario itself (audit length
unchanged across the freeze). Audit growth is classified in the
module docstring per AGENTS.md (`NO_PERMIT !=
NO_GOVERNED_EFFECT`): each denied consume or projection denial
appends exactly one audit record — a governed effect (evidence
production), bounded at one record per attempt, append-only,
with `authority_effect=none` and no capability accumulation —
assessed separately from governed external consequences
throughout.

## 4. Exact success and adversarial evidence

Scenario module `tests/test_barracuda_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the one authorized act (read the project
  account's secret store, inside the window, under a permit
  issued through the directive projection and bound to the live
  engagement) executes exactly once; replay of the spent permit
  is denied; the audit chain verifies.
- step 1: the first call with the stolen credential, in two
  parts. In-window — minutes after the legitimate use, the
  engagement still live, the permit's signed expiry still
  ahead: the vendor's spent permit is denied at consume on
  single-use (its rejection record carries the store's
  `directive_status` "active" — the engagement was live; the
  spend itself was the bar), and the raw standing-key string
  presented as a permit is rejected as a fabricated token
  (`permit_signature_invalid`, a rejection that does not
  depend on the clock). Post-project — the same material
  presented again past the engagement's expiry and past the
  permit's signed expiry: the authentic token is refused at
  the kernel layer with `permit_expired`, the store never
  consulted (no `directive_status` in the record), and the
  raw key is rejected as fabricated again. What the vendor
  held is not a standing capability, so there is nothing
  standing to steal — in the window or after it. Step 2
  exercises each expiry layer separately.
- step 2: expiry at every layer — an unspent permit presented at
  its signed expiry is refused at the kernel layer
  (`permit_expired`, store never consulted); a permit issued
  late in the window whose token expiry runs past the window's
  end is refused at the store once the engagement itself has
  ended (`directive_inactive`); and with the window closed the
  projection mints nothing (`directive_inactive` denial,
  recorded).
- step 3: revocation at consume — the owner revokes the
  engagement directive mid-window; the still-unexpired,
  still-unspent bound permit is then refused at consume by the
  store's live directive-status check (`directive_revoked` in
  the rejection payload), twice; new issuance is denied with
  the same reason, recorded as a `directive_denial`. Retirement
  is a governed act with consume-time effect, not a note in a
  runbook.
- step 4: lateral movement — inside the window, credential in
  hand, the incident's chain (another account's secret store,
  the analytics system, the source-code token) is denied on
  every route: the projection refuses to mint for out-of-scope
  intents (`directive_resource_not_allowed`,
  `directive_action_not_allowed`, each recorded), and the
  project permit does not spend on them
  (`permit_intent_mismatch`). The permit still spends afterward
  on its exact intent: scope denial is not lockout.
- step 5: the credential store, the admin identity, the
  backdoor — the XDR credential store (reached in the real
  intrusion) is an ungranted resource like any other; the
  administrative-identity creation (the one act the real
  platform blocked) is denied by scope before any platform
  question arises; the Kubernetes workload deployment is denied
  likewise; all three on all three routes (projection, project
  permit, raw key), with zero governed external consequences.
- step 6: the incident channel sees the campaign — freezing a
  report over the full attempt sequence yields zero incidents
  and exactly the near-miss records the channel's derivation
  produces from the audit: 13 `permit_rejected`, 7
  `directive_denial`, 0 `approval_rejected`, 0 denied decisions
  — 20 near-misses, each classified Recorded under a valid audit
  chain; the freeze appends nothing. On the routes this scenario
  exercises (consume and the directive projection), derivation
  coverage is complete: every attempt surfaces.
- volume: 44 post-retirement attempts (one per recorded hour of
  the campaign) rotating the spent permit, the unspent permit,
  and the raw key across the project and attack intents, after
  revocation and past every expiry — zero governed external
  consequences, exactly one audit record per denied attempt,
  chain verifies.
- negative control: the identical timeline (activate, issue,
  revoke, advance past every bound) run with consume unguarded
  at both layers — a kernel double skipping token authentication,
  signed-expiry enforcement, and intent binding, over a state
  double whose consume asks only "issued and unspent" — EXECUTES
  the post-retirement spend. That is the incident. The denials
  above therefore come from the real consume path's expiry and
  revocation layers, not from a harness that denies by
  construction.

Full suite at the worktree head: **1018 tests, OK
(skipped=13)** (executed 2026-11-20 at head `645c9da` with
the step-1 correction recorded in §8 applied; the branch
head sits on a main that has absorbed the Dragos and Cairn
replays since the original base — at the §8 checkpoint,
`4603a9f` plus this module alone, the suite is 1000 OK
(skipped=13) against the recorded 991 baseline, the delta
exactly the 9 scenario tests).

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — no control depends on the credential holder's
  cooperativeness or on anyone remembering anything. The
  incident's failure was a retirement nobody performed; under
  the kernel, expiry is stamped into the signed token at
  issuance and revocation is a governed act checked at consume,
  so forgetting is not a failure mode the path offers. The
  holder-side flip is the incident itself: whoever holds the
  vendor's material gains nothing from the engagement having
  once been legitimate — past legitimacy spends zero times
  after the first use, the expiry, or the revocation.
- Reverse — the intrusion chain required every hop to unlock
  the next: key to secrets to analytics to source token to
  clusters to credential store. The earliest unreachable point
  is the first call with the stolen material (step 1): inside
  the window the spent permit already spends zero times, and
  past the window its signed expiry bars it at the kernel
  layer. And the chain does not collapse to one control: even
  inside the window each hop is a distinct intent requiring
  its own permit (step 4), so a live permit for hop one spends
  on no later hop.
- Invert — outcome is not legitimacy: a report claiming "the
  vendor accessed the project account" is supportable only for
  the one consumed act; every other act in the sequence stands
  in the audit as a recorded denial, so post-hoc claims about
  what the credential "must have" done are checkable against
  the record rather than argued from reachability (step 6).
- Inside-Out — the governor cannot originate the authority it
  enforces: permits arrive only through the projection under an
  active directive, and the directive is activated and revoked
  only through verified authority envelopes consumed as
  one-use permits by the operator; the vendor principal cannot
  activate, extend, or un-revoke its own engagement. The test
  verifiers are test-only; the orchestrator surface used for
  the incident report is read-only and its freeze is asserted
  to append nothing (step 6).
- Darken — worst credible bounded case: the attacker runs the
  full campaign at machine tempo holding everything the vendor
  ever held. At the recorded 44-hour scale the volume test
  shows zero consequences and one audit record per attempt; the
  per-attempt bound is linear by construction, so a longer
  campaign changes the record's size, not its completeness —
  stated as construction, not re-run at larger scale. Maximum
  consequence inside the governed path remains the one
  authorized project read.
- Lighten — minimum benign interpretation: a legitimate vendor
  who simply kept working past the project end in good faith.
  The kernel still denies every post-window and
  post-revocation act, because continued need is not continued
  authority. That friction is the replay's point, and the
  positive control shows the governed path exists: renew the
  engagement and take per-act permits inside it.
- Amplify — many holders of the same stolen material aggregate
  nothing: permits are per-intent and single-use; the spent
  permit replays for no one (step 1); the unspent one dies at
  its expiry whoever holds it (step 2); denial volume produces
  audit growth only, never capability.
- Negate — the smallest clean path: the legitimate purpose (a
  vendor performing scoped project work) needs only an
  engagement directive for the exact scope and per-act permits
  inside its window. The standing key, ambient cross-account
  reach, and post-project validity are all unnecessary.

Stop/continue decision: CONTINUE in the governed kernel path
only.

## 5. Boundary the evidence does not prove

The scenario models acts presented for consumption by a holder
on the governed path. It proves nothing about the actual key,
the vendor's development environment, any cloud control plane,
or any part of the intrusion's tooling, and it reproduces none
of it. It proves nothing about non-governed paths: the real key
existed entirely outside any kernel, and a credential that is
never re-issued as governed permits is governed by nothing
here — a control not on the execution path governs nothing.
What the replay shows is the counterfactual the disclosing post
itself states: what changes when the access a standing key
stands for is instead issued as short-lived, narrowly scoped,
per-act permits under a retirable engagement.

Surfacing, stated plainly: on the routes this scenario exercises
— `consume` and the directive projection — no surfacing gap was
observed. Both routes record exactly one audit record per denied
attempt, the incident channel derives near-misses from both
record classes, and step 6 pins the derived counts against the
audit with no remainder (Verified at this commit). The
bare-`evaluate` near-miss boundary recorded by the Cairn replay
(issue #375) is a property of a route this scenario does not
exercise — no attempt here is a bare evaluate — so this replay
neither reproduces it, closes it, nor widens it; it is named so
the complete coverage claimed here is not read as a claim about
that route.

## 6. Claim classification

- Incident narrative: **Recorded** (Barracuda, "Forty-four
  hours: Anatomy of a machine-speed intrusion," Barracuda blog,
  2026-11-11 — the disclosing source; this record follows the
  primary source's account, including that the key was
  apparently found in the vendor's compromised development
  environment, rather than any secondary summary).
- Kernel behavior asserted by the scenario tests: **Verified**
  (executable evidence at the worktree head commit).
- Incident-channel coverage on the exercised routes:
  **Verified** (step 6's pinned counts against the audit at the
  base commit).
- The mapping from the incident's pattern to kernel constructs
  (the engagement as a directive; the key's legitimate use as
  per-act permits under it; retirement as directive revocation;
  each lateral hop as its own intent; one volume attempt per
  recorded campaign hour): **Inferred** — the harness's modeling
  choices, stated in the module docstring.
- Any claim that this prevents the incident class in a deployed
  system: **Proposed** — not made by this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy control
path was copied. Structure, helpers, and assertion style mirror
the canonical scenario modules merged in PRs #346–#350 and
#362–#368 and the Cairn replay (PR #374), including their
per-module helper-duplication pattern.

## 8. Temporal-transfer evidence

Review disposition (Codex P2 on this PR, 2026-11-20): Codex
observed that step 1's original attempt timestamps (T0 + 300)
fall inside the project window — the engagement directive
runs to T0 + 100_000 and the permit's signed expiry to
T0 + 20_100 — so the step's authentic-token denial evidenced
in-window single-use replay protection, not a first
post-project attempt, and the raw-key rejection
(`permit_signature_invalid`) is timing-independent.
Verified accurate against the module and the kernel's
consume layering. Step 1 is restructured accordingly: the
in-window attempt is labeled as exactly that, with its
rejection record's `directive_status` "active" asserted as
the proof of what barred it, and the same stolen material is
presented again past the window's end and past the permit's
signed expiry, refused there at the kernel layer with
`permit_expired`; step 2 continues to exercise each expiry
layer separately rather than step 1 duplicating them. The
checkpoint comparison below was re-run with the corrected
module; the results are unchanged.

Executed 2026-11-20, before this record was finalized — the
checkpoint comparison AGENTS.md requires, run proactively
rather than on review — and re-run the same day with the
corrected step 1 described above. The record names the exact
base, `4603a9f`, and every binding the scenario exercises
(signed permit expiry, directive binding and revocation at
consume, exact-intent binding, single-use consumption,
projection denial recording) predates this change, so the
comparison was runnable and has been run.

Method: a clean worktree was reconstructed at exactly
`4603a9f` (no tree rewriting; `git status` verified the only
delta from the checkpoint was the copied scenario module). The
scenario was run there under the canonical command, then the
full suite. Baseline at `4603a9f` without the lesson is the
recorded 991 OK (skipped=13); the branch adds no kernel code,
so any behavioral difference at the checkpoint would have been
a finding, not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 9 scenario tests pass identically at
  `4603a9f` — the positive control executing exactly once, the
  stolen-material denials of step 1 (the in-window replay
  refused on single-use with the engagement recorded active;
  the same material refused again past the window on its
  signed expiry), expiry enforced at the kernel layer, the
  store layer, and the projection (step 2), revocation
  enforced at consume (step 3), lateral movement and the
  crown-jewel acts denied on every route (steps 4–5), the
  incident channel's 0 incidents / 20 near-misses with complete
  coverage on the exercised routes (step 6), the 44-attempt
  volume run with a complete verifying audit, and the negative
  control executing when unguarded. Full suite at
  checkpoint-plus-lesson: 1000 OK (skipped=13), identical to
  the worktree head at the time of the original run; the delta
  over the 991 baseline is exactly the 9 scenario tests.
- NO EFFECT: the lesson is tests and documentation only; it
  changes no kernel behavior at the checkpoint or at the head,
  and consequential authority is unchanged by the replay itself
  (`authority_effect=none` at both states).
- NEGATIVE TRANSFER: none observed. One scoping note, recorded
  rather than smoothed: this scenario's surfacing assertions
  cover the consume and projection routes only, at both states;
  the bare-`evaluate` boundary from the Cairn replay (issue
  #375) is not exercised by this scenario at either state, and
  no claim about it transfers from this record — each replay's
  surfacing statement stands on its own routes.

The evidence is therefore valid at the checkpoint and at the
worktree head; reuse of the lesson at a later commit still
requires re-evaluation there.

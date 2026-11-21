# Change record — Incident replay: Dragos / HD Moore AI inference canary investigation (disclosed 2026-11-20)

Base: `origin/main` at `4603a9f` (kernel build item #2, PR #372 —
the first Pulpo-gated merge; Phase 3 closed). Authority: Austin
directed the build on 2026-11-20 ("Go ahead and help and build")
after the standing incident scan surfaced the disclosure the day
it was published. Test-only change: one scenario module plus this
record. No production code is touched. Merge is Austin's separate
decision; nothing in this change merges itself.

## 1. Invariant or failure addressed

Incident (Recorded, from Dragos's disclosure, "AI Supply Chain
Security: What Canary Tokens Found," HD Moore, Dragos blog,
2026-11-20): over five months from July through November 2026
the researchers sent approximately two million prompts containing
unique canary credentials and URLs to widely used AI inference
services, then watched where the secrets surfaced. At least three
providers were compromised: in the largest breach a couple
hundred of the seeded AWS keys — each sent in exactly one request
to one provider, all within a few short windows in late October —
were stolen, some from requests the provider rejected before a
model ever ran, telling the researchers the attacker was copying
requests at the provider's front door. The thieves tested each
key for liveness within hours, listed S3 buckets and searched
Secrets Manager and Parameter Store, then tried to persist —
enabling Bedrock models, creating Bedrock API keys, adding their
own IAM users. The bait keys were used for tens of thousands of
AWS API calls; on November 1 the same attacker added ARTEX, an
LLM-driven penetration-testing framework, which made a handful of
calls confirming keys already held were still live. Marketplace
resellers needed no exploit: standard logging let them view and
retain customer prompts, and individuals used what they found —
opening secret URLs, trying prompt passwords as root over SSH.
Privacy settings were not honored: one Chinese AI lab's systems
fetched secret URLs from more than half the prompts sent to its
models, including roughly two-thirds of the requests marked Zero
Data Retention, and twenty-four days after one ZDR-flagged prompt
was sent to a U.S.-based provider, its secret link was posted
into a Feishu chat channel from a stored copy of the full prompt.

Failure addressed: **possession is not a permit.** Every
consequential act in the incident was performed with a genuine
credential by someone who legitimately or illegitimately *held*
it — the key was valid, the password was correct, the URL was
real — and none of that possession was authority for the act.
The governing invariants are `POSSESSION_OF_CREDENTIAL !=
AUTHORIZATION_FOR_ACT` and `AVAILABLE_CAPABILITY !=
AUTHORIZED_CAPABILITY`: under the kernel, each act requires its
own exact-intent permit issued against a verified per-act
approval; a secret that arrived through a trusted channel mints
nothing, a permit for one act spends on no other, and a privacy
flag — a promise about data — is not a mechanism over acts.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a test module
only: no production surface is added, narrowed, or widened; no
permit, policy, or state behavior changes. The module's
deliberately unguarded doubles (`_IntentBlindState`,
`_UnguardedConsumeKernel`) exist solely as the negative control,
are test-local, and are never imported by runtime code — the same
pattern as PRs #346 and #362–#368 and the Cairn replay.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing `evaluate`,
`evaluate_with_approval`, `consume`, audit read, and
incident-channel derivation paths, and adds no writer, route,
ledger, executor, or state backend. The incident-channel freeze
is asserted read-only in the scenario itself (audit length
unchanged across the freeze). Audit growth is classified in the
module docstring per AGENTS.md (`NO_PERMIT !=
NO_GOVERNED_EFFECT`): each denied attempt appends exactly one
audit record — a governed effect (evidence production), bounded
at one record per attempt, append-only, with
`authority_effect=none` and no capability accumulation — assessed
separately from governed external consequences throughout.

## 4. Exact success and adversarial evidence

Scenario module `tests/test_dragos_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the one authorized act (serve one inference
  request, the holder's actual role in the chain) executes
  exactly once under a verified approval envelope; replay of the
  spent permit is denied; the audit chain verifies.
- step 1: the canary secret is not a permit — `evaluate` of the
  stolen key's liveness test returns `require_approval` with no
  permit minted, and the stolen credential string itself,
  presented as a permit token, is rejected at consume
  (`permit_rejected` bound to the liveness test's intent hash).
- step 2: the liveness test presented under the serve permit is
  denied at consume; the denial consumes nothing and the genuine
  permit spends afterward on its exact intent.
- step 3: the data-hunting calls (list S3 buckets, search
  Secrets Manager) are denied on every route — no approval at
  evaluate; serve permit and canary token both rejected at
  consume, four rejections naming exactly the two intents.
- step 4: the persistence call (create an IAM user) is denied on
  every route; the serve permit survives the denied persistence
  attempts and still spends on its own intent (authority to serve
  a request was never authority over the account, in either
  direction).
- step 5: an approval envelope for the IAM act signed with the
  holder's own key is denied (`approval_signature_invalid`), and
  the genuine serve envelope presented for the IAM intent is
  denied (`approval_intent_mismatch`); the genuine pair still
  admits afterward.
- step 6: the canary sees the campaign — freezing a report over
  the full attempt sequence yields zero incidents and exactly
  the near-miss records the channel's derivation produces from
  the audit: 12 `permit_rejected`, 1 `approval_rejected`, 1
  denied `decision`, each classified Recorded under a valid
  audit chain; the freeze appends nothing. Every rejected
  consume's intent hash ties the attempt back to exactly the six
  seeded acts — the tie-back the researchers designed their
  canaries for. The step also pins the surfacing boundary stated
  in §5: the sequence's 6 `require_approval` decisions are
  present in the audit and contribute zero near-miss records.
- volume: 10,000 unauthorized attempts (the low end of the
  disclosure's recorded "tens of thousands of AWS API calls")
  across the six attack intents and three routes — zero governed
  external consequences, exactly one audit record per denied
  attempt, chain verifies.
- negative control: with consume unguarded at both layers
  (kernel double + intent-blind state double), the stolen key's
  liveness test EXECUTES under the serve permit — the denials
  come from the binding layers, not from a harness that denies
  by construction.

Full suite at the worktree head: **1000 tests, OK
(skipped=13)** — the recorded baseline at the base commit is
991 OK (skipped=13); the delta is exactly the 9 scenario tests.

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — no control depends on the channel's trustworthiness or
  the holder's self-description: a prompt marked ZDR and one
  unmarked are indistinguishable at the kernel, and a retention
  promise mints nothing; authority arrives only as verified
  per-act approvals. The incident-side flip is the finding
  itself: the privacy flag was the marketed control, and it
  governed nothing because it was never on the execution path
  of any act performed with the data.
- Reverse — the recorded sequence is a chain with a direction:
  key, then liveness, then data, then persistence. The earliest
  unreachable point is the first use (denied at evaluate and at
  consume, step 1), and the chain does not collapse to one
  control: even the legitimately permitted serve cannot be
  spent on the liveness test (step 2), the data hunt (step 3),
  or persistence (step 4) — each later stage needs its own
  approval, which does not exist.
- Invert — outcome is not legitimacy: in the real incident the
  tens of thousands of calls "succeeded" because the platform
  honored valid keys; success at an API is evidence of
  possession, never of authority. Under the kernel the governed
  record supports credit only for consumed acts — exactly one,
  the serve — so a claim that the holder "was authorized" is
  unsupportable against the audit and visible as such in the
  incident channel (step 6).
- Inside-Out — the governor cannot originate the authority it
  enforces: the holder's own-key envelope is denied (step 5a);
  the test verifiers are test-only; the orchestrator surface
  used for the incident report is read-only and its freeze is
  asserted to append nothing (step 6).
- Darken — worst credible bounded case, run at the recorded
  scale: the holder fires the full bait-key tempo against the
  governed path. The volume test runs 10,000 attempts across
  all six act classes and three routes: zero consequences, one
  audit record per attempt, chain verifies; the per-attempt
  bound is linear by construction, so the upper end of "tens of
  thousands" changes the record's size, not its completeness.
  Maximum consequence inside the governed path remains the one
  authorized serve. The incident's own darker fact is recorded,
  not modeled: the bait prompts were processed alongside real
  customer requests, which the disclosure states were almost
  certainly copied too — the canary accounts were empty by
  design; real accounts would not have been.
- Lighten — minimum benign interpretation: a reseller whose
  prompt logging is ordinary operations, a provider whose ZDR
  failure is a bug rather than malice, a lab whose scraper is
  an over-eager crawler. The kernel still denies every use,
  because a benign reason to *hold* data is not authority to
  *use* the secrets inside it — and the positive control shows
  the governed path for the holder's actual job exists: approve
  the exact acts intended.
- Amplify — two million prompts aggregate nothing: permits are
  per-intent, per-session, and single-use; replay of the one
  genuine permit fails (positive control); 10,000 denied
  attempts produce audit growth only, never capability. In the
  real incident one adversary compromised two providers at once
  and pooled the take; under the kernel, secrets pooled from
  any number of channels still sum to zero permits.
- Negate — the smallest clean path: the holder's legitimate
  purpose (serve the request; retain logs under a real policy)
  needs only the per-act permit for the act intended. The
  prompt's contents, the customer's credentials, and the ZDR
  flag are all unnecessary to it — the flag especially: a
  promise about data is not a mechanism over acts, and the
  governed path never asks for one.

Stop/continue decision: CONTINUE in the governed kernel path
only.

## 5. Boundary the evidence does not prove

The scenario models acts presented for consumption by a holder
on the governed path. It proves nothing about any inference
provider, router, marketplace, or cloud API, reproduces no part
of the incident's tooling, and uses no real credential material —
every "secret" in the module is a string in the test file. It
proves nothing about non-governed paths: the real uses were raw
credentials presented directly to cloud APIs, SSH logins, and
browsers, with no kernel anywhere on those paths, and a control
not on the execution path governs nothing.

One detection asymmetry, stated plainly because the incident's
headline is detection: the campaign was *seen* because the
secrets were bait in empty, fully logged accounts the
researchers owned, each canary existing in exactly one place so
any use tied back to its prompt. Real customer credentials
copied in the same windows would be used against real accounts,
where the victim's observation is the platform's ordinary logs,
not a purpose-built canary service. This replay models the
authorization question and, in step 6, the reconciliation
tie-back over governed attempts; it does not model detection
economics for real secrets, and it claims no detection result.

One surfacing boundary, the same one the Cairn replay recorded
and filed as issue #375 (Verified at this commit, by executable
probe, by the channel's derivation source, and by step 6's
pinned counts): a bare `evaluate` that returns
`require_approval` — the kernel declining to mint a permit
without approval — appends a decision record to the canonical
audit, where it is complete and chain-verified, but the incident
channel does NOT derive a near-miss record from it; the channel
derives near-misses from `permit_rejected`, `approval_rejected`,
denied decisions, and `directive_denial`. The act is still
stopped — no permit exists to spend — so this is a
derivation-coverage boundary in the owner-facing channel, not
an authorization gap. This replay observed no new gap: the
boundary appears here exactly as at the base, neither introduced
nor widened, and the replay records it rather than engineering
around it.

## 6. Claim classification

- Incident narrative: **Recorded** (Dragos blog, HD Moore —
  the disclosing researchers; figures follow the primary
  source: approximately two million prompts, a couple hundred
  keys in the largest breach, tens of thousands of bait-key API
  calls, the more-than-half and roughly-two-thirds ZDR scrape
  figures, the twenty-four-day Feishu interval).
- Kernel behavior asserted by the scenario tests: **Verified**
  (executable evidence at the worktree head commit).
- The incident-channel surfacing boundary in §5: **Verified**
  (executable probe plus the channel's derivation source at the
  base commit, pinned by step 6); previously filed as issue
  #375 by the Cairn replay.
- The mapping from the incident's pattern to kernel intents
  (the three holder classes collapsed into one principal because
  the kernel question is identical for each; cloud acts named
  as exact-resource `api_call` intents; the URL fetch and the
  SSH login as their own action classes; serving one inference
  request as the holder's one legitimate act): **Inferred** —
  the harness's modeling choices, stated in the module
  docstring.
- Any claim that this prevents the incident class in a deployed
  system: **Proposed** — not made by this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy control
path was copied. Structure, helpers, and assertion style mirror
the canonical scenario modules merged in PRs #346–#350 and
#362–#368 and the Cairn incident replay.

## 8. Temporal-transfer evidence

Executed 2026-11-20, per the AGENTS.md temporal-replay
requirement, before the pull request was opened. The applicable
historical checkpoint is the exact base this change names,
`4603a9f`: the bindings the scenario exercises (exact-intent
binding, single-use consumption, approval verification) all
predate this change, so the checkpoint comparison was runnable
and has been run.

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
  `4603a9f` — the canary-secret refusal, the liveness, data-hunt,
  and persistence denials on every route, forged/mismatched
  approval denials, the positive control executing exactly once,
  the negative control executing when unguarded, the
  10,000-attempt volume run with a complete verifying audit,
  and the incident channel's 0 incidents / 14 near-misses. Full
  suite at checkpoint-plus-lesson: 1000 OK (skipped=13),
  identical to the worktree head; the delta over the 991
  baseline is exactly the 9 scenario tests.
- NO EFFECT: the lesson is tests and documentation only; it
  changes no kernel behavior at the checkpoint or at the head,
  and consequential authority is unchanged by the replay itself
  (`authority_effect=none` at both states).
- NEGATIVE TRANSFER: none observed. One boundary is identical
  at both states and is recorded, not smoothed: the §5
  bare-evaluate near-miss gap (issue #375) is a property of the
  base-era incident projection, present at `4603a9f` exactly as
  at the head — the replay neither introduces nor widens it.

The evidence is therefore valid at the checkpoint and at the
worktree head; reuse of the lesson at a later commit still
requires re-evaluation there.

# Change record — Incident replay: PolinRider CI force-push wave — loader force-pushed into open PRs, executed in CircuitVerse's release-build CI (force-pushes 2026-10-19; Corgea update 2026-11-26)

Base: `origin/main` at `d7b7506` (incident replay:
OpenSSH SSHole CVE-2026-123158, PR #393). Authority:
Austin approved this build on 2026-11-26. Test-only
change: one scenario module plus this record. No
production code is touched; no kernel changes were
required.

## Relationship to PR #390 (explicit, per the build brief)

PR #390 (open, branch `replay/polinrider-incident`)
replays PolinRider's EARLIER phase: the Python loader
planted across 375 GitHub repositories, executed at
import time through a trusted import channel (`utils`
packages, a root `conftest.py`), with forged "removal"
commits. Its scenario module is not on `main`.

This change replays the NEW phase only, and is not a
duplicate of #390:

- Delivery: a force-push rewriting the head of pull
  requests still open at OTHER projects (AsyncAPI,
  CircuitVerse, Open Food Facts) — not files planted in
  repositories a victim clones.
- Execution path: a project's desktop release-build CI
  executing the PR head's build scripts — not a Python
  import on a developer workstation.
- Consequence: 40 published release installers built
  after the loader ran — not a payload execution and an
  interactive shell on a workstation.
- Mechanism exercised at a new boundary: exact-intent
  binding for BUILD and PUBLISH acts, where the intent
  names the exact head tree — so a force-push after
  approval makes the presented act ≠ the approved act.
  #390 exercised binding at the import/execution
  boundary; it contained no build, release, publication,
  or head-substitution act.

Where the two share machinery (the kernel's exact-intent
binding, the count-based test-level reconciliation
pattern, the incident channel), this module re-derives
its own sequence and counts at this base; nothing is
copied from #390's branch, which is not an ancestor of
this one.

## 1. Invariant or failure addressed

Incident (Recorded-per-Corgea, from Corgea's research
note "PolinRider expands from npm into Go, Packagist,
and Chrome extension supply-chain poisoning," update of
2026-11-26, reporting the maintainers' and
StepSecurity's accounts; not independently re-derived
here): the GitHub account `Eternity0207` opened 217
pull requests across open-source projects, 145 of them
merged. On 2026-10-19 it force-pushed rewritten commits
carrying the campaign's JavaScript loader (`api.js`,
wired in via a `node api.js && ` prefix on `package.json`
build/dev scripts; at CircuitVerse also a folder-open VS
Code task) into still-open pull requests: two at
AsyncAPI Generator, ten at CircuitVerse `cv-frontend-vue`,
four at Open Food Facts `openfoodfacts-explorer`. What
happened in CI depended on fork settings: AsyncAPI
requires maintainer approval for fork PR workflows, so
nothing ran there; CircuitVerse's PR workflows,
including the desktop release build, ran without
approval, and a CircuitVerse maintainer confirmed the
loader ran in the desktop build CI; the workflow's
artifact pages offered 40 Windows, Linux and macOS
installers built after it ran until the team deleted
them on 2026-11-25. Open Food Facts' CI ran `pnpm build`
on each poisoned commit (all four runs failed) and its
maintainers rotated a secret. GitHub gives fork
`pull_request` workflows no repository secrets and a
read-only `GITHUB_TOKEN`, and no project has reported
stolen secrets. By 2026-11-25 GitHub had suspended the
account and removed its PRs; on 2026-11-26 CircuitVerse
merged a change so fork PRs can no longer publish builds.

Failures addressed:

1. **Trusted-path CI execution.** Code executed in a
   release build because it arrived through a trusted
   channel — an open PR from an account with previously
   merged PRs — not because the specific content was
   authorized. `TRUSTED_PR_CHANNEL !=
   AUTHORIZATION_FOR_THE_BUILD`.
2. **Approval does not survive substitution.** A
   force-push after review changes the act itself: the
   tree that was reviewed and the tree that was built
   were different trees under the same pull request, and
   nothing compared them. Under the kernel, a build or
   publication act is authorized for the exact approved
   head tree, carried in the intent's hashed resource
   identity; the substituted tree is a different intent,
   and presenting the genuine approval or permit for it
   fails closed — `approval_intent_mismatch` at the
   envelope boundary, `permit_rejected` at consume.

The governing invariants are the fail-closed rule of
AGENTS.md and the exact-intent binding itself: approval
must bind the exact intent, and unknown, malformed,
untrusted, expired, replayed, or unavailable authority
fails closed through the canonical kernel.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's `UngovernedReleaseCI`
model exists solely as the negative control, is
test-local, and is never imported by runtime code — the
same pattern as the doubles in PRs #346–#393.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `ReleaseLedger` is a test harness: it
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
per route: a bare `evaluate` returning
`require_approval` appends one decision record; a
`consume` rejection appends one `permit_rejected`
record; a denied approval-envelope evaluation appends
two records — an `approval_rejected` record and a
denied decision record. Growth stays bounded per
attempt (at most two records), which is the invariant
the scenario pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_polinrider_ci_force_push_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the two authorized acts — building
  the release from the exact reviewed head tree, and
  publishing that build's artifact set — each execute
  exactly once under its own verified approval envelope;
  both spent permits replay for nothing; the claimed
  release record listing exactly the two consumed acts
  (with the two replays disclosed as attempts) reconciles
  count-for-count against the audit; the audit chain
  verifies.
- step 1 (the force-push substitution): the genuine
  approval envelope for the reviewed build, presented
  for the substituted build, is denied
  (`approval_intent_mismatch`) — the approval bound the
  tree it was granted against, and the tree changed; the
  genuine build permit consumed against the substituted
  intent is rejected at consume (`permit_rejected` bound
  to the substituted intent's hash); nothing is built
  and no artifacts exist; the same permit still spends
  on the exact approved build afterward.
- step 2: the loader's execution is denied on every
  route — bare `evaluate` returns `require_approval`;
  the trusted channel itself (the force-push event
  string) presented as a permit is rejected at consume;
  the genuine build permit re-aimed at the loader intent
  is rejected at consume; the permit still spends on the
  approved build afterward. Code arriving via a trusted
  channel is not thereby authorized to execute in a
  release build; the governed path executes only what
  the approved intent contains.
- step 3: publication of the poisoned artifact set is
  denied under both genuine permits (the build permit
  covers no publication; the publication permit covers
  only the approved build's set) and has no approval of
  its own; the governed release then completes with only
  the approved artifact set.
- step 4: an approval envelope for the substituted
  build signed with an unauthorized key is denied
  (`approval_signature_invalid`) — control of the PR
  branch does not confer the maintainer's approval
  authority; the genuine pair still admits afterward.
- step 5: the spent build permit re-presents for
  nothing — not for the same approved build, and not
  for the substituted build.
- step 6: reconciliation exposes the poisoned release
  claim. The governed record holds the loader attempt
  (rejected at consume), the substituted-build attempt
  (declined at evaluate), and the two legitimate acts
  (consumed). The claimed release record — the two
  legitimate acts PLUS the poisoned publication as a
  third consequence, and no attempts — fails in both
  directions: both real attempts are
  `undisclosed_attempts`, and the poisoned publication
  is an `unbacked_consequence`, an act that never passed
  the kernel. An honest record reconciles exactly.
  Reconciliation compares occurrence counts (multisets),
  verifies the audit chain first, and fails closed on an
  invalid chain.
- step 7: the incident channel sees the wave — freezing
  a report over the full attempt sequence of steps 1–5
  yields zero incidents and exactly the near-miss
  records the channel's derivation produces from the
  audit: 6 `permit_rejected`, 2 `approval_rejected`, 2
  denied `decision` records, and 1 `require_approval`
  `decision` record (11 near-misses in total), each
  classified Recorded under a valid audit chain; the
  freeze appends nothing. The step also pins the
  surfacing boundary as amended by §10: the sequence's
  1 `require_approval` decision is present in the audit
  and contributes one near-miss record.
- negative control: an ungoverned CI model that builds
  whatever the PR head currently contains behaves
  correctly before the force-push (clean tree in, clean
  artifact set out, no loader execution) and then, after
  the force-push rewrites the head's build script to
  carry the `node api.js && ` hook, runs the substituted
  loader inside the release build and publishes 40
  poisoned installers — the incident's count and shape,
  reproduced at the exact layer it happened: the missing
  comparison between what was reviewed and what was
  built. The identical substitution against the governed
  path is denied (`approval_intent_mismatch`). The
  denials above therefore come from the real binding,
  not from a harness that denies by construction.

Full suite at the worktree head: **1148 tests, OK
(skipped=13)** in this environment — the recorded local
baseline at the base commit `d7b7506`, executed in a
clean worktree of this branch before the change, is
1139 OK (skipped=13); the delta is exactly the 9
scenario tests. (Environment note: skipped and total
counts are this environment's; CI records its own
environment's counts.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — no control depends on how the content arrived:
  a maintainer's own PR head and an attacker's
  force-pushed head are indistinguishable as channel
  artifacts, and neither channel mints anything;
  authority arrives only as verified per-act approvals
  bound to an exact tree. The incident's own flip is
  that the most trusted input a release build has — its
  own PR's head — became the delivery vehicle.
- Reverse — each act requires a consumed permit; the
  permit requires a verified approval; the approval
  binds the exact intent hash, tree identity included.
  The earliest unreachable point is the substituted
  build itself, and the chain does not collapse to one
  control: the substitution is stopped at the envelope
  boundary (step 1a) and independently at consume
  (step 1b), the loader under the genuine permit
  (step 2), the poisoned publication under either
  genuine permit (step 3), the forged envelope
  (step 4), and the spent-permit replay (step 5).
- Invert — outcome is not legitimacy: the incident's 40
  installers were "the project's release" by outcome
  and wholly illegitimate; the governed record supports
  credit only for consumed acts under verified approvals
  (exactly two: the approved build and its publication),
  so any claim that the poisoned publication was
  authorized is unsupportable against the audit, visible
  as such in reconciliation (step 6) and in the incident
  channel (step 7).
- Inside-Out — the governor cannot originate the
  authority it enforces: an envelope signed with an
  unauthorized key is denied (step 4); a PR, a
  force-push event, or a workflow trigger cannot produce
  an approval envelope or ceremony evidence at all
  (step 2's channel token); the test verifier and the
  ungoverned-CI model are test-only; the orchestrator
  surface used for the incident report is read-only and
  its freeze is asserted to append nothing (step 7);
  reconciliation verifies the audit chain before
  deriving anything from it (step 6).
- Darken — worst credible bounded case: one
  force-pushed account touched 16 open PRs across three
  projects in this wave alone, and the campaign's merged
  count (145) shows the channel trust was broad; a
  single success in a release build poisons every
  artifact that build publishes, under the project's own
  name, to every user who installs it. Inside the
  governed path the maximum consequence per approval
  remains the one authorized act; every unauthorized
  attempt produces audit records only — one per attempt
  on the bare-evaluate and consume routes, two on the
  denied approval-envelope route — and zero consequences.
  Outside the governed path stands the incident's real
  worst case, and this replay does not mitigate it; it
  is the boundary in §5.
- Lighten — minimum benign interpretation: a maintainer
  who sincerely wants fork PRs to "just build," for
  contributor velocity — AsyncAPI's approval gate and
  CircuitVerse's post-incident change show the ecosystem
  itself treating ungated fork builds as the defect.
  The kernel still denies every unapproved substituted
  act, because channel convenience, however sincere, is
  not a per-act approval bound to an exact tree — and
  the positive control shows the governed path exists:
  approve the exact tree intended, then build it.
- Amplify — the wave replicated across every project
  that left fork builds ungated; approvals are per-tree,
  per-session, and permits single-use, so replication
  multiplies attempts, never authority. A force-push can
  be repeated after every review; each repetition is a
  new intent with no approval, not a renewal of the old
  one. Denial volume produces audit growth only, bounded
  per attempt.
- Negate — the smallest clean path: the legitimate
  purpose (building and publishing a reviewed PR's
  release) needs only per-act permits for the exact
  trees intended. A mutable head pointer treated as the
  build's identity, and a channel trigger treated as
  authority, are both unnecessary — pin the tree in the
  intent, and the force-push has nothing to substitute.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models acts presented for consumption by a
caller on the governed path. It proves nothing about
the real projects, the real account, the real loader,
GitHub Actions, or any real release pipeline, and it
reproduces no part of the wave. Four boundaries are
stated plainly:

1. **Non-governed paths.** A CI workflow that executes
   whatever a PR head currently contains and checks
   never — the incident's own shape — is governed by
   nothing here. A control not on the execution path
   governs nothing. In particular, nothing in this
   replay scans for, detects, or removes the loader, and
   nothing here implements a real CI gate (such as
   requiring approval for fork workflows, or GitHub's
   "require approval of the most recent reviewable
   push" setting, which Corgea's note recommends); it
   governs whether the build, execution, and publication
   acts may be consumed through the kernel.
2. **The delivery mechanism is out of scope.** How the
   account gained its standing (145 merged PRs) and
   whether any given project's review actually examined
   the pre-force-push trees are Recorded-per-Corgea at
   best and partly Unknown; the harness models the
   approval as granted against the reviewed tree because
   that is the weakest assumption under which the
   incident still happens — even a perfectly reviewed
   tree does not authorize its substitute.
3. **Secrets are not the claim.** No project reported
   stolen secrets, and fork-PR token limits are part of
   why (Recorded-per-Corgea). This replay claims nothing
   about credential exposure: the governed failure it
   exercises is execution and publication without
   authorization, which needed no secrets at all.
4. **Surfacing boundary (issue #375).** A bare
   `evaluate` that returns `require_approval` appends a
   decision record to the canonical audit, where it is
   complete and chain-verified, but the incident channel
   does NOT derive a near-miss record from it; the
   channel derives near-misses from `permit_rejected`,
   `approval_rejected`, denied decisions, and
   `directive_denial`. The act is still stopped — no
   permit exists to spend — so this is a
   derivation-coverage boundary in the owner-facing
   channel, not an authorization gap. Step 7 pins it:
   the sequence's 1 `require_approval` decision
   contributes zero of its 10 near-misses.

## 6. Claim classification

- Incident narrative (217 PRs opened / 145 merged; the
  2026-10-19 force-pushes — AsyncAPI 2, CircuitVerse 10,
  Open Food Facts 4; the loader's execution in
  CircuitVerse's desktop build CI; 40 installers
  published and deleted 2026-11-25; no secrets reported
  stolen; account suspended; CircuitVerse's 2026-11-26
  fork-publication fix): **Recorded** — per Corgea's
  2026-11-26 update, reporting maintainer and
  StepSecurity accounts; not independently re-derived
  here.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 7).
- The mapping from the incident's pattern to kernel
  artifacts (the reviewed vs. force-pushed head trees
  modeled as distinct resource identities inside the
  hashed intent; the loader modeled as a
  process-execution intent; publication modeled as its
  own act distinct from the build; the 40-installer
  figure carried as the negative control model's output
  count): **Inferred** — the harness's modeling choices,
  stated in the module docstring. Tree labels, session
  naming, and artifact names are harness constructions,
  not recovered incident artifacts.
- Any claim that this prevents the incident class in a
  deployed CI system: **Proposed** — not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346–#350, #362–#368, #374–#382, #386,
and #391–#393, including their per-module
helper-duplication pattern, the reporting-coverage
construction of PR #378's step 6 as amended, and — for
step 6's reconcile-a-claimed-history construction — the
count-based (multiset) reconciliation pattern of the
filename-deception scenario as corrected in PR #390's
fix pass. PR #390's branch is not an ancestor of this
branch and no code was taken from it; the pattern is
the canonical one on `main`.

## 8. Temporal-transfer evidence

Executed 2026-11-26. The applicable historical
checkpoint is this branch's exact base, `d7b7506`: the
bindings the scenario exercises (exact-intent binding
including the resource identity, single-use consumption,
approval verification, incident-channel derivation,
audit-chain verification) all predate this change, so
the checkpoint comparison AGENTS.md requires was
runnable and has been run.

Method: a clean worktree was reconstructed at exactly
`d7b7506` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module). The scenario was run there under the canonical
command. Baseline at `d7b7506` without the lesson in
this environment is 1139 OK (skipped=13); the branch
adds no kernel code, so any behavioral difference at
the checkpoint would have been a finding, not an
expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 9 scenario tests pass identically at
  `d7b7506` — the positive control building and
  publishing exactly once with its artifact set
  reconciling, the force-push substitution denied at
  both boundaries, the loader denied on every route, the
  poisoned publication denied, the forged approval
  denied, the spent-permit replays denied, reconciliation
  exposing the poisoned release claim, the incident
  channel's 0 incidents / 10 near-misses, and the
  negative control publishing 40 poisoned artifacts
  under the ungoverned CI model.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not
  smoothed: the §5 bare-evaluate near-miss gap (issue
  #375) is a property of the base-era incident
  projection, present at `d7b7506` exactly as at the
  head — the replay neither introduces nor widens it.

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.

## 9. Fix pass — Codex P2: bind publication to the artifacts produced by the build (2026-11-26)

Authorized by Austin on 2026-11-26. Scenario/test layer
only: no kernel or other production code is touched,
no merge, and the review thread is left open.

1. **Invariant or failure addressed.** The Codex review
   thread on PR #408 (P2, first comment id 4710044079,
   unresolved) found that `ReleaseLedger.execute()` —
   this scenario's publication boundary — consumed a
   publication permit and recorded a publication effect
   from the intent's action and resource alone, without
   accepting or checking the artifacts the governed
   build produced. The exact publication intent could
   therefore be consumed before the build intent (with
   the ledger's artifact set still empty), or after
   outputs were substituted, and still return success;
   step 3's poisoned-publication denial rested on the
   poisoned set being a *different intent*, not on any
   build-to-artifact binding at the publication
   boundary. **Verified** at the pre-fix head `d0bc526`
   by reading the thread and the source: `execute()`
   took only `(kernel, permit, intent)` and, for a
   build, populated `artifacts` itself after consume;
   publication accepted no artifact input at all.
2. **Authority gained, narrowed, or left unchanged.**
   Unchanged. `authority_effect=none`. The correction
   narrows only the test harness's publication path:
   publication of the exact publication intent now
   additionally requires build evidence, checked before
   the permit is consumed. No permit, policy, or kernel
   behavior changes.
3. **Canonical state mutations introduced or exposed.**
   None. The ledger remains a test harness holding no
   canonical state. The new check runs before
   `kernel.consume`, so a refused publication appends
   no audit record, consumes no permit, and records no
   effect — the refusal is observable exactly as the
   absence of all three, and the unspent permit is
   shown still spending on the honest publication in
   both regressions.
4. **Exact success and adversarial evidence.** The
   ledger now records, at the moment its governed build
   executes, `BuildEvidence` — the observed artifact
   digest (SHA-256 of the exact artifact set), the
   artifact set itself, and its provenance (the exact
   build resource, i.e. the reviewed head tree).
   Publication requires presented evidence that (a)
   exists, (b) equals the evidence this ledger itself
   observed from its own governed build execution,
   (c) carries the approved build's provenance, and
   (d) has a digest matching the artifact set presented
   with it. Two regressions were added (scenario count
   9 → 11):
   - step 3b: publication with no build evidence, and
     publication with caller-fabricated evidence naming
     the approved artifacts and their correct digest
     but never observed from a governed build, are both
     refused before consume (zero `permit_consumed`,
     zero `permit_rejected`, no effect); the same
     permit then publishes honestly once the governed
     build has run.
   - step 3c: publication after a governed build with
     substituted output is refused before consume in
     both forms — the poisoned artifact set with its
     own self-consistent digest, and the poisoned set
     carrying the observed build's digest (digest /
     artifact-set mismatch); the same permit then
     publishes honestly with the observed evidence.
   The honest end-to-end path (authorized source
   revision → governed build → observed artifact
   digest → exact publication authorization →
   publication) passes in the positive control and in
   steps 3, 3b, 3c, 6, and 7, whose publication calls
   now present the ledger's observed build evidence.
   Counts in this environment (canonical `unittest`
   runner; the local venv carries no `pytest` module):
   baseline at `d0bc526` before the fix — scenario 9/9,
   full suite 1171 OK (skipped=13); after the fix —
   scenario 11/11, full suite 1173 OK (skipped=13),
   the delta being exactly the two new regressions.
5. **Boundary the evidence does not prove.** The
   binding is proven at this scenario's ledger
   boundary, for a caller that routes publication
   through it. A caller that bypasses the ledger and
   calls `kernel.consume` directly (as step 7's raw
   consume probes deliberately do, at the kernel layer)
   is governed by the kernel's exact-intent binding
   alone; nothing here adds a kernel-level
   artifact-binding, and no real CI or release pipeline
   is governed by this harness (the §5 boundaries stand).
6. **Claim classification.** The Codex finding and its
   reproduction at `d0bc526`: **Verified** (thread text
   plus source reading). The correction's behavior:
   **Verified** (executable evidence, counts above).
   That digest-plus-provenance evidence is the right
   model of a real build's attested output: **Inferred**
   — a harness modeling choice, stated here.
7. **Legacy behavior source.** None; no legacy control
   path was copied.
8. **Temporal-transfer evidence.** No new reusable
   lesson is claimed beyond this scenario's boundary;
   the §8 checkpoint comparison for the original replay
   stands, and the fix-pass regressions were executed
   at the branch head stated in §9.4. Reuse at a later
   commit requires re-evaluation there.

## 10. Addendum — #413 near-miss derivation pin refresh (2026-11-27)

Cause (Recorded): PR #413, merged 2026-11-26 as
`b1cea2f` ("Fix #375: derive near-miss from
bare-evaluate require_approval decisions"), changed
the incident channel's near-miss derivation so a
bare `evaluate` returning `require_approval` now
derives one near-miss record. This branch was built
before #413 and pinned the old derivation in step
7; after the branch merged `main` containing #413,
CI failed on exactly that pin (expected 10, got
11). This is an expectation shift, not a behavior
change in this scenario: every allow/deny assertion
is unchanged and passes as before. (This addendum
is numbered §10 because §9 above is the Codex
fix pass.)

Correction (test pins and this record only; no
kernel or production code touched,
`authority_effect=none`): step 7's pinned total
moves 10 → 11; the accounting sum and the
`decision` source-detail count now include the
sequence's 1 `require_approval` decision, which
contributes one near-miss record; §4's step 7
counts are updated the same way. §5.4's
surfacing-boundary statement and §8's checkpoint
counts remain accurate for the pre-#413 base they
describe and are superseded for the current head
by this addendum: the #375 derivation gap they
record is closed on `main` by #413.

Evidence (Verified — executed in this environment
with the repo venv interpreter): before the fix,
the scenario module failed on the single assertion
above (11 tests, FAILED (failures=1), `10 != 11`
at step 7); after the fix, the scenario module
passes 11/11 and the full suite passes: 1186
tests, OK (skipped=13).

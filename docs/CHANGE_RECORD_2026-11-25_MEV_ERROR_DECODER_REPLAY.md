# Change record — Incident replay: web3-mev-error-decoder npm supply-chain attack (GHSA-hvqj-jrfw-r9mh; package published 2026-11-09, advisory published 2026-11-25)

Base: `origin/main` at `d7b7506` (incident replay:
OpenSSH SSHole CVE-2026-123158, PR #393).
Authority: Austin Irvan, owner of Ironnember/Pulpo1.0,
authorized this build in plain words in the main chat
on Nov 25, 2026 (~15:34 MST): "Go and build on number
2" — the replay-build go-ahead for this incident.
Test-only change: one scenario module plus this
record. No production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from the Endor Labs write-up of
the incident, converged with the GitHub advisory
GHSA-hvqj-jrfw-r9mh / MAL-2026-20610, CWE-506):
the npm package `web3-mev-error-decoder@0.1.0` was
published on 2026-11-09 13:35 UTC. Its own tarball was
clean — no install hook, no malicious code (the Endor
Labs review of a tarball copy whose SHA-1/SHA-512
match the pre-takedown registry metadata; tarball
SHA-256
`05d193d87e03221b68cac57c7048c45c82cb55a43e9c56f600ca973add67c8ed`).
Its only consequential content was one dependency
declaration,
`"multicall-error-decoder": "github:outgoingyang/multicall-error-decoder"`.
A `github:` specifier tells npm to fetch a GitHub
repository instead of a registry tarball; the fetched
repository's `package.json` carried the install hook
`node dist/error-decoder/handlers.js`. Kitsunox
recorded that repository at commit `240aa9b685e2`
(2026-11-12): the hook was a downloader that
decrypted its strings with AES at runtime
(`crypto.createDecipheriv('aes-256-cbc', ...)`),
then, on Windows, downloaded an archive and launched
the executable inside it (detached, outliving the
install), and on macOS piped a remote script into
the shell. Linux behavior is not described in the
sources. Two days before the malicious package, on
2026-11-07, the attacker had published a clean
package named `multicall-error-decoder@0.1.0` to the
npm registry (tarball SHA-256
`62405e794b8cb35d52589f783ffda8eb758e04263ab5aa6eef803a8a348457d9`)
— real, working, hook-free code under exactly the
dependency's name, so name-based review and
registry-only scanning found a legitimate library;
the harmful code never appeared on npm at all.
Kitsunox at first raised a single MEDIUM finding on
the non-registry specifier. GitHub published
GHSA-hvqj-jrfw-r9mh on 2026-11-25 at 16:13 UTC and
npm replaced the package with a security holder one
minute later: an exposure window of about 16 days.
The GitHub account, repository, and commit have
since been deleted, so the second-stage payload was
never recovered. No victims are confirmed in the
sources. Download figures are not a victim count:
the reported npm downloads API shows 9,735,029
downloads on a single day (2026-11-11) against
roughly 60 to 4,089 on other days — read by Endor
Labs as count inflation, with mirrors and scanners
inflating even the smaller figures; deps.dev reports
no registry dependents.

Failure addressed: **a package name is not an
authorization to execute.** This is a Class 1
(supply-chain / trusted-path execution) failure:
code executed at install time because the package
channel was trusted, on the strength of a manifest
declaration alone, with no per-action authorization
by a named accountable human and no binding to the
artifact that actually ran — the artifact reviewed
(the registry decoy; the clean top-level tarball)
was not the artifact executed (the GitHub copy at
the same name). The governing invariants are the
fail-closed rule of AGENTS.md (unknown, malformed,
untrusted, expired, replayed, or unavailable
authority fails closed through the canonical kernel)
and the exact-intent binding itself: under the
kernel, install-time execution of fetched code is a
consequential action requiring a permit issued only
after a verified approval bound to the exact
artifact — name, version, source, and hash, all
carried in the intent's resource string so the
intent hash binds the identity as stated. That
four-field identity is exact and complete for the
reviewed registry artifact, whose hashes are real
SHA-256s. The GitHub payload's recorded identity is
narrower: name, the `github:` source, and the
abbreviated commit `240aa9b685e2` observed on
2026-11-12, with its content hash **Unknown** (never
recovered; the repository is deleted). A `github:`
redirect changes the source; a same-name substitution
changes the hash; either makes a different intent
whose approval does not exist, so execution is
refused and the refusal is recorded. The evidence
below attributes each limb accordingly: the hash
limb is proven only by the registry hash-substitution
test (step 3), and the Git-redirect test (step 2)
proves the source limb only.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds
a test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately
ungoverned double (`NameOnlyInstaller`) exists
solely as the negative control, is test-local, and
is never imported by runtime code — the same pattern
as PRs #346 and #362–#393.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`,
audit read, and incident-channel derivation paths,
and adds no writer, route, ledger, executor, or
state backend. The scenario's `InstallExecutor` is a
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
`tests/test_web3_mev_error_decoder_incident_scenario.py`
(8 tests, all passing at the worktree head):

- positive control: the one authorized act
  (install-time execution of the exact reviewed
  registry artifact) executes exactly once under a
  genuine, well-formed verified approval envelope;
  replay of the spent permit is denied; the audit
  chain verifies.
- step 1: with no approval at all, `evaluate` of
  the GitHub payload artifact returns
  `require_approval` with no permit minted, and
  nothing executes. A manifest declaration is not
  an approval.
- step 2: the genuine approval for the reviewed
  registry artifact, presented for the GitHub
  artifact at the same name (the `github:` redirect
  — same name, different source and content), is
  denied (`approval_intent_mismatch`); the genuine
  pair still admits afterward. This is the
  source-limb test: the denial turns on the changed
  source (the Git identity's hash field is
  **Unknown**, not a digest), so it proves nothing
  about a hash for the Git payload.
- step 3: the genuine approval presented for an
  artifact at the same name, version, and source
  with a substituted hash is denied
  (`approval_intent_mismatch`) — the same-name decoy
  in its hash form; a name-based check would pass
  it, the exact binding does not. This is the
  hash-limb test — the only hash-limb evidence in
  the scenario, both registry hashes being real
  SHA-256s.
- step 4: an approval envelope for the GitHub
  artifact signed with an unauthorized (attacker)
  key is denied (`approval_signature_invalid`).
  Whoever controls the package cannot mint the
  installer's authority.
- step 5: multiplicity — the spent permit
  re-presented for the same artifact executes
  nothing and consumes nothing a second time;
  reconciliation is per-item counted (`Counter` /
  multiset), never set-based: an exact claim
  reconciles, a claim listing the same consumed
  artifact twice is a phantom of count exactly 1,
  and an empty claim under-reports by exactly 1.
  A set-based check would collapse the duplicate
  and report a match.
- step 6: the incident channel sees the attempts —
  freezing a report over the full attempt sequence
  exercisable on one kernel (the no-approval
  evaluation, the redirect mismatch, the forged
  envelope, the payload name presented as a permit,
  the one legitimate execution, and the spent-permit
  replay) yields zero incidents and exactly the
  near-miss records the channel's derivation
  produces from the audit: 2 `permit_rejected`, 2
  `approval_rejected`, and 2 denied `decision`
  records, plus 1 `require_approval` `decision`
  record (7 near-misses in total), each classified
  Recorded under a valid audit chain; the freeze
  appends nothing. The step also pins the surfacing
  boundary stated in §5: the sequence's 1
  `require_approval` decision is present in the
  audit and contributes one near-miss record since
  the issue #375 fix (PR #413; §9). The
  counts are from the executed run at this head, not
  estimates.
- negative control: with the governed boundary
  swapped for the incident's own rule — a
  test-local installer that authorizes install-time
  execution by package name alone, as registry-only
  scanning effectively does — the GitHub payload
  artifact EXECUTES, and so does the
  hash-substituted artifact, while an unrelated name
  does not pass. The double's defect is precision,
  exactly the decoy's design target: it cannot tell
  the reviewed artifact from any other artifact at
  the same name. The denials in the steps above
  therefore come from the exact binding over the
  stated identity — the source limb for the GitHub
  route, the hash limb for the registry substitution
  — not from a harness that denies by construction.

Full suite at the worktree head: **1147 tests, OK
(skipped=25)** in this environment — the recorded
local baseline at the base commit `d7b7506` is 1139
OK (skipped=25); the delta is exactly the 8 scenario
tests. (The skipped=25 figure is this environment's
count; CI records its own environment's skipped
count with the same test total modulo
environment-specific discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — the incident is itself a flip: the artifact
  inspected was clean and the artifact executed was
  never inspected, the two swapped by a source
  redirect under one name. On the governed path the
  flip has nowhere to live: source and hash are
  inside the bound identity (the source in step 2,
  the hash in step 3), so swapping either swaps the
  intent and voids the approval.
- Reverse — the consequence requires a consumed
  permit; the permit requires a verified approval;
  the approval binds the exact artifact identity.
  The chain does not collapse to one control: the
  no-approval route (step 1), the redirect (step 2),
  the hash substitution (step 3), and the forged key
  (step 4) are each stopped at a distinct check, and
  the spent permit cannot be replayed (positive
  control, steps 5–6).
- Invert — outcome is not legitimacy: the incident's
  installs "succeeded" by outcome and were wholly
  unauthorized; the governed record supports credit
  only for consumed acts under verified approvals
  bound to the exact artifact, so any claim that a
  name-matched install was authorized is
  unsupportable against the audit and visible as
  such in the incident channel (step 6).
- Inside-Out — the governor cannot originate the
  authority it enforces: a package, a manifest, or a
  registry listing cannot produce an approval
  envelope or ceremony evidence at all; the test
  doubles are test-only; the orchestrator surface
  used for the incident report is read-only and its
  freeze is asserted to append nothing (step 6).
- Darken — worst credible bounded case: the package
  targeted Web3/MEV developer machines, which often
  hold hot-wallet keys, seed phrases, deployer keys,
  and RPC credentials, and stage 1 already gave the
  attacker arbitrary code execution on install
  (stage 2 unknown). Inside the governed path the
  maximum consequence per approval remains the one
  authorized act on the one exact artifact; every
  unauthorized attempt produces audit records only
  — one per attempt on the bare-evaluate and consume
  routes, two on the denied approval-envelope route
  — and zero consequences. Outside the governed path
  stands the incident's real worst case — an
  installer that runs hooks on a declaration — and
  this replay does not mitigate it; it is the
  boundary in §5.
- Lighten — minimum benign interpretation:
  `github:` dependencies and install hooks are
  legitimate, ordinary mechanisms, and the decoy
  package is genuinely clean code. Nothing in the
  governed path bans either: the positive control
  shows install-time execution proceeding normally
  when a named accountable human has approved the
  exact artifact. What is refused is only execution
  that no one approved, of an artifact no one
  reviewed.
- Amplify — the attack replicated across every
  install of a trending package at once; approvals
  are per-artifact and permits single-use, so
  replication multiplies attempts, never authority.
  Denial volume produces audit growth only, bounded
  per attempt, and duplicate presentations never
  double-count or double-authorize (step 5).
- Negate — the smallest clean path: install-time
  execution must be authorized against the exact
  artifact that will run — name, version, source,
  and hash — by a named accountable human. (That is
  the standard; for the incident's Git payload the
  full identity is unrecoverable — its hash is
  **Unknown** — which is itself the point: nothing
  bound it because nothing about it was ever pinned.)
  A name, and a registry listing under that name, are
  both unnecessary as authority on the execution
  path — remove name-as-authority and the incident
  does not happen.

Stop/continue decision: CONTINUE in the governed
kernel path only.

## 5. Boundary the evidence does not prove

The scenario models approval artifacts presented for
install-time execution at a governed kernel
boundary. It proves nothing about npm, any registry,
scanner, or installer, and it reproduces no part of
the malicious package, the install hook, or any
payload — the stage-1 behavior is described from the
sources, not reproduced, and the stage-2 payload was
never recovered, so its behavior is **Unknown** and
is not modeled at all. It proves nothing about
non-governed paths: an installer that executes hooks
on the strength of a manifest declaration is
governed by nothing here — a control not on the
execution path governs nothing. It also does not
speak to compromise after a hook runs (credential
theft, persistence, fund loss): it governs the
execution before it starts, not the compromise
afterward. Download counts in the sources are
inflated by mirrors, scanners, and an apparent
count-inflation spike and are not presented anywhere
in this change as a victim count; no victims are
confirmed in the sources. Whether any given
production installer binds execution to exact
artifact identity is an audit question for that
installer; this scenario pins only that the
canonical kernel's exact-intent binding gives a
source redirect and a same-name substitution
nothing to travel on.

One identity boundary, stated as plainly: the Git
payload's identity in this scenario is the recorded
one — name, the `github:` source, and the
abbreviated commit `240aa9b685e2` observed on
2026-11-12 — and its content hash is **Unknown**.
The repository, account, and commit were deleted
before any digest was recovered, and the sources
record no archive copy, so no full revision or
digest can be stated and none is attempted. The
scenario therefore proves the source limb for the
Git route (a genuine approval for the registry
artifact does not transfer to a differently-sourced
intent at the same name) and proves the hash limb
only for registry artifacts, where both hashes are
real SHA-256s. It does not prove an exact-identity
binding for the Git payload, and the recorded commit
does not cover other revisions the dependency's
default-branch resolution may have fetched during
the ~16-day exposure window.

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

- Incident narrative: **Recorded** (the Endor Labs
  write-up of the incident, converged with GHSA-
  hvqj-jrfw-r9mh / MAL-2026-20610: the package and
  decoy publication dates and identities, the
  `github:` dependency declaration, the install
  hook, the advisory and security-holder dates, and
  the ~16-day exposure window).
- Stage-1 hook behavior (AES-decrypted strings;
  Windows archive download and executable launch;
  macOS remote script piped to shell): **Recorded**,
  as recorded by Kitsunox at commit `240aa9b685e2`
  and reported by Endor Labs; the repository is
  deleted and the code was not independently
  re-derived here. Linux behavior: **Unknown** (not
  described in the sources).
- Stage-2 payload behavior: **Unknown** — never
  recovered or analyzed.
- The Git payload's content hash and full commit
  SHA: **Unknown** — never recovered; the repository
  was deleted and the sources record no archive
  copy. The scenario's Git identity is the recorded
  abbreviated commit only, and no hash claim is made
  for it.
- Victims: none confirmed in the sources
  (**Recorded** as an absence, not a proof of none).
  Download figures: **Recorded** as reported, and
  explicitly not a victim count (inflated by
  mirrors/scanners and an apparent inflation spike).
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree
  head commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 6).
- The mapping from the incident's pattern to kernel
  artifacts (install-time hook execution modeled as
  the consequential act; artifact identity carried
  in the intent's resource string — name, version,
  source, and hash for the registry artifacts; name,
  source, and the recorded abbreviated commit for
  the GitHub copy, its hash **Unknown**; the
  registry decoy modeled as the approved artifact
  and the GitHub copy as a distinct intent at the
  same name): **Inferred** — the harness's modeling
  choices, stated in the module docstring.
- Any claim that this prevents the incident class
  in a deployed system: **Proposed** — not made by
  this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no
legacy control path was copied. Structure, helpers,
and assertion style mirror the canonical scenario
modules merged in PRs #346–#350, #362–#368,
#374–#382, #386, and #393, including their
per-module helper-duplication pattern, the
reporting-coverage construction of PR #378's step 6
as amended, and the negative-control double
construction of PR #386 and #393. The per-item
(`Counter`) reconciliation follows the multiplicity
discipline of the merged replay suite.

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
environment is 1139 OK (skipped=25); the branch adds
no kernel code, so any behavioral difference at the
checkpoint would have been a finding, not an
expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 8 scenario tests pass identically
  at `d7b7506` — the positive control executing
  exactly once, the no-approval denial, the
  `github:`-redirect binding failure, the same-name
  hash-substitution binding failure, the forged-
  approval denial, the multiplicity probe (duplicate
  presentation neither double-executes nor
  double-counts), the incident channel's 0 incidents
  / 6 near-misses, and the negative control executing
  under the name-only installer double. Full suite
  at checkpoint-plus-lesson: 1147 OK (skipped=25),
  identical to the worktree head; the delta over the
  1139 baseline is exactly the 8 scenario tests.
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

## Sources

- Endor Labs, "web3-mev-error-decoder: a clean npm
  package that installs malicious payload from
  GitHub" (2026-11-25):
  https://www.endorlabs.com/learn/web3-mev-error-decoder-a-clean-npm-package-that-installs-malicious-payload-from-github
- GitHub Advisory GHSA-hvqj-jrfw-r9mh /
  MAL-2026-20610 (published 2026-11-25).

## 9. Addendum — #413 near-miss derivation pin refresh (2026-11-27)

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

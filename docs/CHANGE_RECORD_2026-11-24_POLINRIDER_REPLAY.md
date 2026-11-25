# Change record — Incident replay: Polinrider GitHub-repo Python loader wave (publicized 2026-11-24)

Base: `origin/main` at `5297d1c` (incident replay:
ConnectWise ScreenConnect CVE-2026-84869 technician
exploitation, PR #386).
Authority: Austin approved this build on 2026-11-24 ("Build
the replay PR"), after the incident-scan surfaced the
candidate the same morning. Test-only change: one scenario
module plus this record. No production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from SafeDep's analysis, "Polinrider:
Python Loader Delivered via Ethereum Calldata," 2026-11-24;
first reported the same day by Jay Maier in issue #96 of
meSingh/polinrider-scanner): a 58-line Python loader was
planted across 375 GitHub repositories and accounts, hidden
in `utils` packages or in a root `conftest.py` — files that
Python tooling imports automatically. On import, the loader
reads the newest self-sent transaction from the Ethereum
wallet `0x3b1574417524c11a7403c4b232CAcBb320CceBC6`,
hex-decodes the transaction's input data as JavaScript, and
executes it via Node.js (build 4, marker `A9-10502`). The
JavaScript pulls a command-and-control server at
95.135.181.84 and spawns an interactive `node -i` shell.
The planting commits were forged, including fake "removal"
commits — history rewritten to claim the loader was gone.

Failure addressed: **trusted-path execution — code ran
because the channel it arrived through was trusted, not
because the specific act was authorized.** A `conftest.py`
import is a loading mechanism, not an approval:
`TRUSTED_IMPORT_CHANNEL != AUTHORIZATION_FOR_THE_ACT`, and
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`.
Nothing in the incident path asked whether *this*
execution — of *this* remotely fetched payload, on *this*
machine — was authorized by anyone; the import itself was
treated as the authority. The governing mechanism is the
exact-intent binding itself: under the kernel, each
consequential act requires its own permit bound to the
exact intent — principal, action, resource, cost, session —
rechecked at consume and spent on use, so a build-step
approval is not a payload approval even when both acts
share the same verb (executing a process via Node), and a
file having been loaded mints nothing. The second failure
is pointed at the record: the forged commits made
repository state (history) claim acts happened and were
undone with no provenance behind either claim. Step 6
models the governed answer: reconciliation of the claimed
history against the canonical audit, in both directions —
state is evidence, state is not provenance, and provenance
is not authority.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a test
module only: no production surface is added, narrowed, or
widened; no permit, policy, or state behavior changes. The
module's deliberately unguarded doubles (`_IntentBlindState`,
`_UnguardedConsumeKernel`) exist solely as the negative
control, are test-local, and are never imported by runtime
code — the same pattern as PRs #346 and #362–#386.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, incident-channel derivation, and test-level
reconciliation paths, and adds no writer, route, ledger,
executor, or state backend. The reconciliation in step 6
is test-level, implemented against the public
`kernel.audit` read path (as in the filename-deception and
Mythos scenarios): the shipped reconcilers reconcile
filesystem effects and custody-domain outcomes, not a
claimed history against the kernel audit trail. The
incident-channel freeze is asserted read-only in the
scenario itself (audit length unchanged across the freeze).
Audit growth is classified in the module docstring per
AGENTS.md (`NO_PERMIT != NO_GOVERNED_EFFECT`): each denied
attempt appends audit records — a governed effect (evidence
production), append-only, with `authority_effect=none` and
no capability accumulation — assessed separately from
governed external consequences throughout. The count is per
route, not uniformly one: a bare `evaluate` returning
`require_approval` appends one decision record; a `consume`
rejection appends one `permit_rejected` record; a denied
approval-envelope evaluation appends two records — an
`approval_rejected` record and a denied decision record.
Growth stays bounded per attempt (at most two records),
which is the invariant the scenario pins.

Scope note, stated plainly: this scenario's policy carries
no AgentGrant, so no claim in this record rests on the
grant layer (whose resource matching is prefix-based at
this commit — the open item first surfaced by PR #381's
review and pinned by PRs #381/#382). The denials here rest
on the approval requirement and the exact-intent permit
binding at consume, exactly as the executed run proves and
no further.

## 4. Exact success and adversarial evidence

Scenario module `tests/test_polinrider_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the one authorized act (the project's
  pinned Node build-check step) executes exactly once under
  a verified approval envelope; replay of the spent permit
  is denied; the audit chain verifies.
- step 1: the payload execution is denied on every route —
  `evaluate` returns `require_approval` with no permit
  minted, and the import channel itself, presented as a
  permit (the loader's marker string), is rejected at
  consume (`permit_rejected` bound to the payload intent's
  hash). A channel is not a permit, and reach is not
  authority.
- step 2: executing the decoded payload and spawning the
  interactive shell against the command server, both under
  the genuine build permit, are rejected at consume (2
  `permit_rejected`, bound to the two distinct intent
  hashes); the permit still spends afterward on the exact
  build step it was issued for. The denial was scope, not
  lockout.
- step 3: the permitted build step re-presented with the
  payload appended to its resource identity is rejected at
  consume under the genuine permit; the exact approved
  build step still spends afterward. The widened build is
  the incident's core claim — that the channel's trust in
  the build covered whatever the import delivered with it.
- step 4: the spent permit replays for nothing —
  re-presented for the same build step and for the payload
  execution after consumption, both are rejected
  (2 `permit_rejected` against 1 `permit_consumed`). An
  import that fires twice authorizes nothing the second
  time.
- step 5: an approval envelope for the payload execution
  signed with an unauthorized key is denied
  (`approval_signature_invalid`), and the genuine build
  envelope presented for the payload intent is denied
  (`approval_intent_mismatch`); the genuine pair still
  admits afterward.
- step 6: reconciliation exposes the forged history. The
  governed record holds the payload attempt (rejected at
  consume), the shell attempt (declined at evaluate), and
  the one legitimate build (consumed). The forged claim —
  consequences: the build plus a "removal" of the loader;
  attempts: none — fails reconciliation in both directions:
  the two real attempts are `undisclosed_attempts`, and the
  claimed removal is an `unbacked_consequence`, an act that
  never passed the kernel and has no provenance behind it.
  An honest history (the build as the only consequence,
  both attempts disclosed, no invented removal) reconciles
  exactly. Reconciliation verifies the audit chain first
  and fails closed on an invalid chain.
- step 7: the incident channel sees the wave — freezing a
  report over the full attempt sequence of steps 1–5
  (every attack act on every route: the three attack
  intents — payload, shell, widened build — each on bare
  evaluate, the channel token, and the genuine permit;
  both approval-envelope attempts; and both spent-permit
  replays) yields zero incidents and exactly the near-miss
  records the channel's derivation produces from the audit:
  8 `permit_rejected` (6 wave-route rejections plus the 2
  spent-permit replays), 2 `approval_rejected`, and 2
  denied `decision` records (the two step-5 envelope
  denials) — 12 near-misses in total, each classified
  Recorded under a valid audit chain; the freeze appends
  nothing. The step also pins the surfacing boundary
  stated in §5: the sequence's 3 `require_approval`
  decisions are present in the audit and contribute zero
  near-miss records. One honest scoping: step 6's
  reconciliation sequence runs on its own kernel (its own
  audit trail by construction) and is pinned there.
- negative control: the identical presentation as step 2's
  route (build permit, payload intent) with consume
  unguarded at both layers (kernel double + intent-blind
  state double) EXECUTES. That is the incident's own
  shape — an import path that executes whatever it loads,
  because the channel was trusted. The denials come from
  the real consume path's binding, not from a harness that
  denies by construction.

Full suite at the worktree head: **1098 tests, OK
(skipped=25)** — the recorded baseline at the base commit
`5297d1c`, executed in a clean worktree, is 1089 OK
(skipped=25); the delta is exactly the 9 scenario tests.

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — no control depends on how the code arrived: a
  maintainer's own pinned build script and an attacker's
  planted loader are indistinguishable as channel
  artifacts, and neither channel mints anything; authority
  arrives only as verified per-act approvals. The
  incident's own flip is that the file type Python trusts
  most (the test harness's own `conftest.py`) became the
  delivery vehicle.
- Reverse — each act requires a consumed permit bound to
  the exact intent; the earliest unreachable point is the
  first fetched-payload execution (denied at evaluate and
  at consume), and the chain does not collapse to one
  control: the genuine permit cannot be re-aimed at the
  payload or the shell (step 2), re-scoped to carry the
  payload under the build's identity (step 3), or replayed
  after use (step 4).
- Invert — outcome is not legitimacy: a test suite passing
  after the import would be "success" by outcome even with
  the loader resident, but the governed record supports
  credit only for consumed acts (exactly one: the approved
  build step), so any claim that the payload execution or
  the removal was authorized is unsupportable against the
  audit, visible as such in the incident channel (step 7)
  and in reconciliation (step 6).
- Inside-Out — the governor cannot originate the authority
  it enforces: an envelope signed with an unauthorized key
  is denied (step 5a); a channel, a file, or a marker
  string cannot produce an approval envelope or ceremony
  evidence at all; the test verifiers are test-only; the
  orchestrator surface used for the incident report is
  read-only and its freeze is asserted to append nothing
  (step 7); reconciliation verifies the audit chain before
  deriving anything from it (step 6).
- Darken — worst credible bounded case: the wave planted
  one loader shape across 375 repositories, so a single
  import-time trust decision replicated to every machine
  that cloned and tested any of them. Inside the governed
  path the maximum consequence remains the one authorized
  build step; every loader attempt produces audit records
  only — one per attempt on the bare-evaluate and consume
  routes, two (an `approval_rejected` record and a denied
  decision record) on the denied approval-envelope route —
  and zero consequences. Outside the governed path stands
  the incident's real worst case, and this replay does not
  mitigate it; it is the boundary in §5.
- Lighten — minimum benign interpretation: a maintainer
  who sincerely wants the project's tooling to "just run"
  whatever a checkout contains, for speed. The kernel
  still denies every unapproved fetched-payload act,
  because channel convenience, however sincere, is not a
  per-act approval — and silent loading plus silent
  execution is what unbounded channel trust accumulates.
  The positive control shows the governed path exists:
  approve the exact acts intended.
- Amplify — the failure replicated across every repository
  a developer clones in a week; permits are per-intent,
  per-session, and single-use, so replication multiplies
  attempts, never authority. Denial volume produces audit
  growth only, and the forged-history variant multiplies
  claims, which reconciliation checks against one canonical
  audit rather than against the claims' own consistency.
- Negate — the smallest clean path: the legitimate purpose
  (running the project's pinned build check) needs only
  per-act permits for the exact acts intended. An import
  channel treated as authority, and a rewritten history
  treated as provenance, are both unnecessary.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models acts presented for consumption by a
caller on the governed path. It proves nothing about the
real repositories, the real operator, the real loader, or
any real import path, and it reproduces no part of the
wave. Four boundaries are stated plainly:

1. **Non-governed paths.** An import path that executes
   what it loads and checks never — the incident's own
   shape — is governed by nothing here. A control not on
   the execution path governs nothing. In particular,
   nothing in this replay scans, detects, or removes a
   planted loader; it governs whether the loader's
   consequential acts may be consumed through the kernel.
2. **The delivery mechanism is out of scope.** How the
   loader was planted across 375 repositories (account
   compromise, social engineering, or otherwise) is
   Unknown in the source and unmodeled here. A permit
   governs whether the fetched-payload act may be
   attempted through the kernel; it does not harden any
   real repository, account, or CI runner.
3. **Surfacing boundary (issue #375).** A bare `evaluate`
   that returns `require_approval` appends a decision
   record to the canonical audit, where it is complete and
   chain-verified, but the incident channel does NOT
   derive a near-miss record from it; the channel derives
   near-misses from `permit_rejected`, `approval_rejected`,
   denied decisions, and `directive_denial`. The act is
   still stopped — no permit exists to spend — so this is
   a derivation-coverage boundary in the owner-facing
   channel, not an authorization gap. Step 7 pins it: the
   sequence's 3 `require_approval` decisions contribute
   zero of its 12 near-misses.
4. **No grant-layer claim.** As stated in §3, this
   scenario's policy carries no AgentGrant; nothing here
   establishes or relies on grant resource scope, and the
   prefix-matching behavior of that layer is neither
   exercised nor hidden — it is simply not this replay's
   subject.

## 6. Claim classification

- Incident narrative: **Recorded** (SafeDep's analysis,
  2026-11-24 — the disclosing researcher's statement;
  corroborated as to the wave's existence by the public
  scanner issue it cites; no confirmed victim count
  exists, so impact specifics remain Recorded).
- The operator behind the wallet and the planting vector:
  **Unknown** — not established in the source.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (kernel source at the base commit,
  executable probe, and step 7's pinned counts).
- The mapping from the incident's pattern to kernel
  intents (the loader's consequential acts modeled as
  process-execution and shell intents against named
  resources; the import channel modeled as no authority
  artifact at all; the forged commits modeled as a claimed
  history reconciled against the audit): **Inferred** —
  the harness's modeling choices, stated in the module
  docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and assertion
style mirror the canonical scenario modules merged in PRs
#346–#350, #362–#368, and #374–#379, the LeadStack replay
(PR #380), the OpenRouter replay (PR #382), the Gainsight
replay (PR #385), the ScreenConnect replay (PR #386), and
the BabidiGhost replay — and, for step 6's
reconcile-a-claimed-history construction, the
filename-deception scenario's test-level
`reconcile_against_audit` pattern, including their
per-module helper-duplication pattern, and the
reporting-coverage construction of PR #378's step 6 as
amended and PR #379's step 6 (every attack variant and
every denial route replayed into the frozen sequence,
with the honest scoping recorded in §4).

## 8. Temporal-transfer evidence

Executed 2026-11-24. The applicable historical checkpoint
is this branch's exact base, `5297d1c`: the bindings the
scenario exercises (exact-intent binding, single-use
consumption, approval verification, incident-channel
derivation, audit-chain verification) all predate this
change, so the checkpoint comparison AGENTS.md requires
was runnable and has been run.

Method: a clean worktree was reconstructed at exactly
`5297d1c` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module, and the module was removed afterward, leaving the
checkpoint worktree clean). The scenario was run there
under the canonical command, then the full suite. Baseline
at `5297d1c` without the lesson is 1089 OK (skipped=25);
the branch adds no kernel code, so any behavioral
difference at the checkpoint would have been a finding,
not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 9 scenario tests pass identically at
  `5297d1c` — the channel-token refusal, the payload and
  shell denials, the widened-build denial, the
  spent-permit replay denials, the forged/mismatched
  approval denials, the positive control executing exactly
  once, reconciliation exposing both directions of the
  forged history, the negative control executing when
  unguarded, and the incident channel's 0 incidents / 12
  near-misses. Full suite at checkpoint-plus-lesson: 1098
  OK (skipped=25), identical to the worktree head; the
  delta over the 1089 baseline is exactly the 9 scenario
  tests.
- NO EFFECT: the lesson is tests and documentation only;
  it changes no kernel behavior at the checkpoint or at
  the head, and consequential authority is unchanged by
  the replay itself (`authority_effect=none` at both
  states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not smoothed:
  the §5 bare-evaluate near-miss gap (issue #375) is a
  property of the base, present at `5297d1c` exactly as at
  the head; the replay neither introduces nor widens it.

The evidence is therefore valid at the checkpoint and at
the worktree head; reuse of the lesson at a later commit
still requires re-evaluation there.

## 9. Fix pass — 2026-11-25 (Codex review of PR #390)

Review finding (Codex, P2, on
`tests/test_polinrider_incident_scenario.py`):
"Preserve event multiplicity during reconciliation." The
step-6 reconciliation derived **sets** of intent hashes
from the audit and converted the claimed values to sets
as well, collapsing every occurrence of a hash to one. A
claimed history listing a hash once therefore reconciled
successfully even when the audit held further attempts —
or further executions under separately issued permits —
for that same hash: the claim could underreport repeated
activity while returning `ok=True`. The finding is
correct, and it is the forgery class this replay exists
to expose, pointed at the replay's own checker.

Change (test module only; no production code, no claim
narrowed — the reconciliation claim is strengthened, and
the prior presence-only limitation is recorded here
rather than smoothed over):

- `audited_sets` is replaced by `audited_counts`: the
  audit side now yields occurrence counts (multisets) per
  intent hash for consequences and attempts alike.
- `reconcile_against_audit` counts the claim's lists the
  same way (a hash listed twice claims two occurrences)
  and flags a hash in each direction whenever the counts
  diverge: underreported attempts are
  `undisclosed_attempts`, underreported executions are
  `missing_consequences`, and overreported claims are
  `phantom_attempts` / `unbacked_consequences`. `ok`
  requires exact count equality for every hash, on top of
  the unchanged fail-closed audit-chain verification.
- New step 6b pins the behavior: the payload attempted
  three times on the channel route (3 rejections, one
  hash) and the approved build executed twice under two
  separately issued permits (2 consumptions, one hash). A
  claim collapsing each hash to a single listing fails on
  exactly the two underreported hashes; the same history
  with multiplicity reported honestly reconciles exactly;
  overreporting fails in each direction on its own hash.
  Step 6's assertions were updated to the count form
  (each count 1) without weakening.

Evidence (Verified, executed at the fix-pass head):

- Scenario: **10/10 pass** (was 9/9 at head `6db6767`;
  the delta is exactly step 6b).
- Full suite at the fix-pass head: **1099 tests, OK
  (skipped=25)** — one more than the 1098 recorded in §4
  for the original head, the delta again exactly the new
  test.
- Temporal replay of the fix, per §8's method: a clean
  worktree reconstructed at exactly `5297d1c` with the
  updated module copied in (the only delta) passes the
  scenario identically, 10/10; the checkpoint worktree
  was removed afterward. The multiplicity comparison is a
  property of this branch's test-level helper over the
  public audit read path; no kernel behavior is exercised
  differently at the two states, and consequential
  authority is unchanged (`authority_effect=none`).

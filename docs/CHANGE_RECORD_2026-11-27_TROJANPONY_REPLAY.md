# Change record — Incident replay: TrojanPony — fake "improved" coding-agent skills trusted on name, listing, and scanner PASS, side-loading a credential trojan on activation (reported 2026-11-26)

Base: `origin/main` at `f734c97e` (PR #38 merged;
verified by fetch at build time, 2026-11-27).
Authority: Austin approved this build on 2026-11-27
in words ("Build all three"), for the event surfaced
the same day; the authorization covers this build's
fresh clone. Test-only change: one scenario module
plus this record. No production code is touched.

## 1. Invariant or failure addressed

Event (graded from the public record): AIR Security
reported (Recorded, primary source: AIR Security,
https://www.air.security/blog-posts/trojanpony,
publicized 2026-11-26) a campaign it calls
TrojanPony: fake "improved" copies of popular
coding-agent skills (ponytail-improved,
agents-council, and others) that work like the
originals but ship a validly signed Notepad++
updater beside a malicious `libcurl.dll` that
side-loads when the skill runs, adds Microsoft
Defender exclusions, and drops the MopsStealer
credential trojan. AIR Security reported (Recorded)
487 public repositories carrying the kit, and one
malicious skill still listed on skills.sh on
2026-11-26 with three scanner audits all PASS.

Claim discipline (load-bearing): this replay does
NOT claim any particular install by any particular
user occurred, and no step reproduces the kit, the
updater, the DLL, or the trojan. What it models is
the architectural property the reporting
establishes: the trust signals the marketplace path
checks -- the skill's name, its listing, and scanner
verdicts about it -- say nothing about whether THIS
artifact, byte for byte, is the artifact a human
approved, so a substituted artifact carrying the
same name and listing activates on exactly the same
trust as the genuine one.

Failure addressed: **name, listing, and scanner
trust are not approval of the artifact.** A scanner
PASS answers "did a scanner object to this listing?"
It does not answer "was THIS artifact -- this skill
name, this version, this exact content hash --
approved by the human for activation?" Under the
canonical kernel, skill activation is a
consequential act that requires a permit bound to
the human's approved intent -- principal, action,
resource (the artifact identity: skill name +
version + content hash), cost, session -- minted
from a verified approval envelope signed by an
enrolled authority. The genuine approved artifact
activates under its permit, exactly once. The
substituted artifact -- same name, same version,
different content hash, carrying the side-loaded
payload -- is refused at `consume`: its intent
matches no approved intent, and the refusal burns
nothing. Scanner PASS verdicts are recorded as
evidence about the listing and are explicitly never
treated as authorization: presented at `consume`
they are refused like any other unauthenticated
string. The governing invariants are
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`
-- here, trusted-path execution abuse: a trusted
name executes nothing the approval did not name --
and fail-closed authorization: unknown, malformed,
untrusted, or merely possessed authority mints
nothing and spends nothing.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds
a test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's
`MarketplaceActivationBoundary` double exists solely
as the negative control, is test-local, and is never
imported by runtime code -- the same pattern as PRs
#346 and #362-#393, #415, #416, #422, #423, and
#424. The scenario's reconciliation helper
(`reconcile_consequences`) is likewise test-local:
it reads the harness's executed log and holds no
canonical state.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`,
audit read, and incident-channel derivation paths,
and adds no writer, route, ledger, executor, or
state backend. The scenario's `ActivationBoundary`
is a test harness: it activates a skill only after a
successful kernel consume and holds no canonical
state; its log entries are inert resource labels,
never commands, files, or credentials. The
incident-channel freeze is asserted read-only in the
scenario itself (audit length unchanged across the
freeze). Audit growth is classified in the module
docstring per AGENTS.md (`NO_PERMIT !=
NO_GOVERNED_EFFECT`): each denied attempt appends
audit records -- a governed effect (evidence
production), append-only, with
`authority_effect=none` and no capability
accumulation -- assessed separately from governed
external consequences throughout. The count is per
route, not uniformly one: a bare `evaluate`
returning `require_approval` appends one decision
record; a `consume` rejection appends one
`permit_rejected` record; a denied approval-envelope
evaluation appends two records -- an
`approval_rejected` record and a denied decision
record. Growth stays bounded per attempt (at most
two records), which is the invariant the scenario
pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_trojanpony_incident_scenario.py`
(7 tests, all passing at the worktree head):

- positive control: the one authorized act (the
  genuine artifact -- this skill name, this version,
  this content hash) activates exactly once under a
  genuine, well-formed verified approval envelope;
  the permit, spent at that consume, cannot activate
  twice; reconciliation of executed-vs-approved
  reports exact equality (1 approved, 1 executed,
  0 unauthorized); the audit chain verifies.
- step 1: the substitution refused at consume, and
  the refusal is free -- the genuine permit,
  presented FIRST for the substituted artifact (same
  skill name and version, a different content hash,
  an artifact no human approved, carrying the
  side-loaded payload), is refused at the kernel's
  intent binding, the rejection naming the
  substituted intent's hash; the refusal consumes
  nothing, and the genuine permit then spends on its
  own act, exactly once. Under the reported
  architecture this attempt never faces the question:
  the name and listing match, the scanners passed it,
  and that is the whole check.
- step 2: the marketplace listing and the scanner
  PASS verdict presented as permits -- the only trust
  artifacts the reported architecture produces, in
  the role they play there -- are refused at
  `consume` (the listing for the genuine artifact and
  the substitution alike; the scanner PASS reference
  for the genuine artifact). Three PASS verdicts
  (Recorded) were recorded about the malicious
  listing itself; a verdict authenticates a scan, and
  authorizes no act. The verdicts are recorded in the
  scenario as evidence and explicitly never treated
  as authorization.
- step 3: with no artifact presented at all,
  `evaluate` returns `require_approval` for the
  genuine artifact and the substitution alike --
  being the user's coding agent confers no route to a
  permit; and an approval envelope for the
  substitution signed with a key the agent controls
  is denied (`approval_signature_invalid`). The
  kernel verifies against the enrolled authority,
  and the party requesting the activation cannot also
  be the party approving it. (The reported kit's
  updater carried a valid signature too; a signature
  from the wrong authority is exactly the shape this
  refuses.)
- step 4: reconciliation over a governed sequence
  shaped like the event -- the genuine artifact
  approved and activated, the substitution attempted
  under the event's two available forms (the genuine
  permit stretched, before the genuine activation;
  the listing presented as authority), and the spent
  permit replayed -- reports exact equality:
  1 approved, 1 executed, 0 unauthorized occurrences,
  and no refused attempt recorded as fulfilled. The
  comparison the reported path never runs, run here,
  is clean precisely because every substituted
  attempt was denied before it could execute.
- step 5: the incident channel sees the attempts --
  freezing a report over the full attempt sequence
  exercisable on one kernel (the no-approval
  evaluation of the substitution, the listing
  presented as a permit for the substitution, the
  genuine approval stretched to the substitution, the
  one legitimate activation, and the spent-permit
  replay) yields zero incidents and exactly the
  near-miss records the channel's derivation produces
  from the audit: 2 `permit_rejected`,
  1 `approval_rejected`, 1 denied `decision`, and
  1 `require_approval` `decision` (5 near-misses in
  total), each classified Recorded under a valid
  audit chain; the freeze appends nothing. The
  `require_approval` decision contributes one
  near-miss per occurrence under the issue #375
  derivation (PR #413) -- this module was authored
  after that fix landed, so its counts are born
  correct against it. Governed-run incident-channel
  counts: **0 incidents, 5 near-misses.**
- negative control: with no governor at all, the
  marketplace boundary double does exactly what the
  reporting describes -- it takes the presented
  listing at face value and checks only that the
  skill is listed under that name, with the scanner
  PASS verdicts recorded about the listing. The
  genuine artifact activates; the substituted
  artifact -- same name, same version, different
  content, never approved by the human as an
  artifact -- activates on the same trust, and its
  activation is the side-load (the payload executes;
  credential theft is simulated as the activation
  consequence itself, and no payload code exists in
  the module); and a skill with no listing at all is
  not activated, which is the one check the
  architecture has, working exactly as reported.
  Per-occurrence reconciliation against
  exact-artifact approvals -- of which the
  marketplace architecture produces none, for any
  activation -- reports the run exactly: 0 approved,
  2 executed, 2 unauthorized occurrences, named. The
  genuine activation was the user's own request in
  fact; nothing in the boundary's records
  distinguishes it from the substitution, and that
  indistinguishability is the finding the control
  isolates. Negative-control incident-channel counts:
  **0 incidents, 0 near-misses** -- there is no kernel
  and no channel on that path, so nothing derives a
  record from either activation, including the
  malicious one; the silence is part of the finding.
  The denials in the steps above therefore come from
  the governed path's fail-closed authorization,
  exact-intent binding, and signature verification,
  not from a harness that denies by construction, and
  the reconciliation demonstrably detects the modeled
  shape when it does occur.

Full suite at the worktree head: **1195 tests,
OK (skipped=13)** in this environment --
the recorded local baseline at the base commit
`f734c97e` is 1188 OK (skipped=13), verified by
execution in this tree at build time;
the delta is exactly the 7 scenario tests. (The
skipped figure is this environment's count; CI records
its own environment's skipped count with the same test
total modulo environment-specific discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip -- if the boundary were merely optimizing for
  install convenience (the reported flow's actual
  condition: a listed, scanner-passed skill is
  accepted because accepting it is what makes a skill
  marketplace frictionless), the fastest route from a
  name to execution is to check the listing and
  nothing else. On the governed path, convenience has
  no dimension to exploit: the listing is an
  unauthenticated string at consume (step 2), genuine
  authority stops at its own artifact (step 1), and
  flipping the presenter changes nothing without the
  enrolled key (step 3).
- Reverse -- the consequence (an activated skill, and
  everything it carries) requires a consumed permit;
  the permit requires a verified approval; the
  approval is bound to the exact artifact identity
  and signed by the enrolled authority. The earliest
  unreachable point is the activation itself: the
  executor runs nothing without a consume, and the
  chain does not collapse to one control -- possession
  of the listing stops at consume (step 2), scanner
  verdicts stop at consume (step 2), scope stops at
  intent binding (step 1), self-assertion stops at
  signature verification (step 3), replay stops at
  single-use consumption (positive control), and
  absence of any artifact stops at the approval
  requirement (step 3).
- Invert -- outcome is not legitimacy: on the
  reported path the fake skills DID produce their
  outcome -- they work like the originals -- and every
  part of that success rested on name and listing
  trust. The negative control reproduces exactly that
  shape and extends it by one artifact: both
  activations "succeed," and the reconciliation still
  reports both as carrying no exact-artifact approval,
  so a successful activation under listing trust is
  classified by the record as unapproved, not as
  authorized.
- Inside-Out -- the governor cannot originate the
  authority it enforces: the boundary holds no
  approval capability, the reconciliation helper is
  read-only over the harness's log and holds no
  canonical state, the marketplace double is
  test-only, and the orchestrator surface used for the
  incident report is read-only with its freeze
  asserted to append nothing (step 5). In particular,
  the kernel has no route by which material an agent
  presents -- a listing reference or a scanner verdict
  included -- becomes authority:
  `CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`,
  and a listing is not an approval transition.
- Darken -- worst credible bounded case, from the
  reporting's own shape: 487 public repositories
  carrying one kit, a malicious skill still listed
  after three PASS audits -- one poisoned listing,
  trusted by every agent that installs by name,
  multiplies a single substitution into credential
  theft on every machine that activates it, and no
  record on the path distinguishes the malicious
  activations from genuine ones. Inside the governed
  path the maximum consequence per approval remains
  the one approved artifact, once; every unauthorized
  attempt produces audit records only -- one per
  attempt on the bare-evaluate and consume routes, two
  (an `approval_rejected` record and a denied decision
  record) on the denied approval-envelope route -- and
  zero activations. Outside the governed path stands
  the modeled worst case -- activation paths that
  trust name, listing, and scanners alone -- and this
  replay does not mitigate it; it is the boundary in
  section 5.
- Lighten -- minimum benign interpretation: skill
  marketplaces and scanner audits are ordinary, useful
  tooling, and the genuine skill working as advertised
  is the benign case working exactly as designed --
  the user asked, the agent installed, the skill ran.
  The governed path preserves what is benign: the
  genuine artifact works (positive control), the
  listing's protection is not denied (the negative
  control shows the unlisted decline working as
  reported), the scanner verdicts remain recorded
  evidence, and each activation's authorization
  becomes a governed question instead of an
  implication of a listing created by whoever
  published the copy.
- Amplify -- the modeled harm is amplification by
  standing trust: one listing, valid for every
  artifact published under that name, multiplies a
  single substitution success into as many activations
  as the marketplace reaches. On the governed path,
  amplification multiplies attempts, never authority:
  the listing spends on nothing no matter how many
  activations it is presented for (step 2), approvals
  are per-artifact and permits single-use (steps 1,
  3), and the reconciliation counts occurrences, so
  amplification is measured, not averaged away
  (negative control: 2 unauthorized occurrences over
  the modeled shape).
- Negate -- the smallest clean path: a consequential
  activation must require an approval the agent
  cannot supply by presenting a trusted name -- signed
  by an enrolled authority and bound to the exact
  artifact identity (name + version + content hash).
  The listing reference, the scanner PASS verdict, the
  stretched permit, and the agent-signed envelope are
  each unnecessary to the approved task; remove the
  signature check and step 3's route returns, remove
  intent binding and step 1's returns; with both, the
  substitution's shape has no governed route.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models governed skill activation at a
kernel boundary. It proves nothing about skills.sh's,
AIR Security's, or any marketplace's, scanner's, or
coding agent's actual systems, and it reproduces none
of the event's mechanics -- the boundary's log entries
are inert labels, the marketplace double is a
test-local model faithful only in the properties the
scenario names (a presented listing taken at face
value; the skill's name checked against the listing;
scanner verdicts recorded and never authorizing;
listed artifacts activated as presented), and no
updater, DLL, trojan, credential, or skill content
from the real event appears anywhere in the module.
It proves nothing about non-governed paths: an
activation path that trusts name, listing, and
scanner verdicts alone is governed by nothing here --
a control not on the execution path governs nothing.

The event narrative itself rests on one research
report from one named source, not independently
verified by this change beyond the report itself. The
replay takes the reported trust mechanics as its model
and grades each element (section 6); it does not
independently verify any marketplace's or scanner's
behavior. In particular, the load-bearing boundary is
the modeled substitution: the scenario models one
genuine artifact, one substituted artifact, and one
unlisted skill as the architectural pattern the
reporting describes, not a per-install reconstruction.
Every skill version and content hash in the module is
a scenario parameter, not a reported figure; the only
skill names used are the ones the reporting names.

## 6. Claim classification

- Fake "improved" copies of popular coding-agent
  skills (ponytail-improved, agents-council, and
  others) work like the originals but ship a validly
  signed Notepad++ updater beside a malicious
  `libcurl.dll` that side-loads on run, adds Defender
  exclusions, and drops the MopsStealer credential
  trojan: **Recorded** (AIR Security, 2026-11-26,
  primary source as cited in section 1).
- 487 public repositories carry the kit: **Recorded**
  (AIR Security, as above -- their count, carried as
  theirs, not independently established).
- One malicious skill was still listed on skills.sh
  on 2026-11-26 with three scanner audits all PASS:
  **Recorded** (AIR Security, as above).
- That any particular user installed or activated a
  malicious skill, or had credentials stolen:
  **not claimed** -- the report describes the kit and
  its distribution, and no step models a particular
  install.
- That a substituted listed artifact would activate
  under the reported mechanics with no exact-artifact
  approval existing: **Inferred** -- the modeled
  property, demonstrated executably against the
  marketplace double built to the reported mechanics
  (negative control), not an observed event.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree
  head commit).
- The mapping from the reported flow to kernel
  artifacts (the activation boundary as one boundary;
  the genuine artifact and the substitution as two
  distinct intents differing only in content hash; the
  listing and scanner verdicts modeled as
  consume-presented strings): **Inferred** -- the
  harness's modeling choices, stated in the module
  docstring.
- Any claim that this prevents the modeled class in a
  deployed marketplace or agent: **Proposed** -- not
  made by this change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346-#350, #362-#368, #374-#382, #386,
and #391-#393, and the approval-path construction of
PRs #416, #422, #423, and #424 (the sibling Cairn,
Morris, SAP, and Papa John's replay modules).

## 8. Temporal-transfer evidence

Executed 2026-11-27. The applicable historical
checkpoint is this branch's exact base, `f734c97e`: the
bindings the scenario exercises (fail-closed approval
requirement, exact-intent binding, single-use
consumption, approval signature verification, and the
incident-channel derivation including the issue #375
near-miss rule) all predate this change, so the
checkpoint comparison AGENTS.md requires was runnable
and has been run.

Method: the scenario module was executed in this tree
at exactly `f734c97e` plus the copied scenario module
(the branch's only code delta from the checkpoint at
the time of the run; `git status` verified no other
delta). Baseline at `f734c97e` without the lesson in
this environment is 1188 OK (skipped=13), verified by
execution in this tree at build time; the branch adds
no kernel code, so any behavioral difference at the
checkpoint would have been a finding, not an
expectation.

Results (Verified -- executed at both states):

- TRANSFERS: all 7 scenario tests pass identically at
  `f734c97e` -- the positive control activating exactly
  once with exact reconciliation, the substitution
  refused at consume under the genuine permit with the
  refusal burning nothing, the listing and scanner PASS
  references refused as permits, the no-approval and
  agent-signed denials, the governed-sequence
  reconciliation reporting zero unauthorized, the
  incident channel's 0 incidents / 5 near-misses, and
  the negative control activating both listed artifacts
  under no governor (the unlisted skill declined) with
  reconciliation reporting 2 unauthorized occurrences.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed.

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.

# Change record — Incident replay: PHP2Shell AI-agent credential-harvesting campaign — one mandate spent across hundreds of targets (SOCRadar, published 2026-11-18)

Base: `origin/main` at `efc2ef3` (Gainsight
reconciliation multiplicity fix, PR #410), re-verified
against live `main` via `gh` at build time
(2026-11-26; `main` had advanced one commit past this
build's sibling PR #416 base during the build, and this
branch was taken from the live head). Authority: Austin
approved this build on 2026-11-26 ("build both replay
PRs" for the Cairn CL-STA-1238 and PHP2Shell incidents,
surfaced by the standing incident scan the same day).
Test-only change: one scenario module plus this record.
No production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from SOCRadar Threat Research
Unit's 2026-11-18 report, reconstructed from the
operator's own exposed C2 and AI-lab servers): public
proofs of concept for PHP2Shell -- CVE-2026-109618 and
CVE-2026-109619 -- were released on October 21, 2026,
and the operator wrote its first exploit script the
same day, adapting the exploit to default-configuration
PHP/Apache hosts and to individual PHP builds. An
AI-agent system queued and ran the exploitation: a
self-built job orchestrator (maq) dispatching patched
Oh My Pi (omp) workers -- 39 in parallel on the
operator's lab host -- against two SSH-forwarded vLLM
DeepSeek V4.1 endpoints. Each target became a numbered
job in a workflow running from eligibility checks
through exploitation, persistence, credential
harvesting, and upload. The recorded scale:

- a Shodan pool of 68,198 PHP/Apache hosts, shortlisted
  to about 5,042 Debian-specific targets;
- 595 unique IPs attacked in 57 countries;
- 404 hosts confirmed compromised on SOCRadar's
  headline count; its job-registry analysis counts 452
  collection jobs, 433 holding loot or check-in evidence
  establishing compromise across about 393 unique hosts;
- about 290,000 exfiltrated files (9.5 GB, as of the
  November 3, 2026 repository snapshot): cloud API
  keys, IAM credentials, database dumps and backups,
  application secrets, OAuth tokens, repositories, and
  session files;
- persistence kept by token-authenticated webshells,
  60-second cron reverse beacons, SSH keys, and
  encrypted Dropbear tunnels;
- the largest single completed haul: about 3.3 million
  user/session records (about 1 GB) exfiltrated from an
  unauthenticated Redis instance;
- a separate agent-driven financial-fraud track under a
  GOAL.md directive to pursue over $50,000 USDT
  autonomously until a real payout was executed: it
  reached withdrawal and account-takeover primitives --
  a withdrawal of about 456,900 USDC was initiated and
  stayed pending, and about 7.3 BTC stayed encrypted --
  with no confirmed theft.

SOCRadar assesses with moderate confidence that the
operator is an unauthorized, financially motivated
actor working in the initial-access-broker pattern, and
assesses the operation as human-directed and
AI-augmented: full autonomy was never reached, and no
chain completed without manual oversight. Those
assessments are the source's; this replay relies on the
operational facts and takes no position on attribution,
for which the source records low confidence and no
matching named actor.

Failure addressed: **one mandate, spent without
limit.** The campaign's only authorization artifacts
were a goal file and a job queue, and they functioned
as an unbounded, transferable, reusable permit: any of
the 39 workers could spend the mandate on any of the
595 targets, for any stage of the chain -- exploitation,
persistence, credential harvesting, exfiltration -- any
number of times, because a queued job WAS the
authority. Nothing in the pipeline ever asked whether
this act, on this target, was authorized. That question
is the one the campaign's shape makes unavoidable,
because the mandate's author was the intruder: authority
that is self-issued and unlimited is not a control, it
is a description of the attack. Under the canonical
kernel, authorization is per-act and single-use: a
permit binds one principal, one action, one exact
target resource, one session, and spends at its first
`consume`. A second target is a different intent. A
second act type is a different intent. A second use is
a replay. Fleet scale multiplies authorization
questions; it never dilutes them. The governing
invariants are exact-intent binding, single-use
consumption (revocation-at-consume), and fail-closed
authorization: `AUTHORIZATION_TO_USE_CAPABILITY !=
AUTHORIZATION_TO_DUPLICATE_CAPABILITY` -- a mandate to
scan one host is not a mandate to harvest 595.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's `UngovernedFleetHost`
double exists solely as the negative control, is
test-local, and is never imported by runtime code --
the same pattern as PRs #346 and #362-#393 and #415.
The scenario's reconciliation helper
(`reconcile_consequences`) is likewise test-local: it
reads the harness's executed log and holds no canonical
state.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `TargetHost` is a test harness: it
executes an act only after a successful kernel consume
and holds no canonical state; its log entries are inert
resource labels, never commands, payloads, or
credentials. The incident-channel freeze is asserted
read-only in the scenario itself (audit length unchanged
across the freeze). Audit growth is classified in the
module docstring per AGENTS.md (`NO_PERMIT !=
NO_GOVERNED_EFFECT`): each denied attempt appends audit
records -- a governed effect (evidence production),
append-only, with `authority_effect=none` and no
capability accumulation -- assessed separately from
governed external consequences throughout. The count is
per route, not uniformly one: a bare `evaluate`
returning `require_approval` appends one decision
record; a `consume` rejection appends one
`permit_rejected` record; a denied approval-envelope
evaluation appends two records -- an `approval_rejected`
record and a denied decision record. Growth stays
bounded per attempt (at most two records), which is the
invariant the scenario pins -- including at fleet
volume, where 39 refused consumes append exactly 39
`permit_rejected` records and nothing else executes.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_php2shell_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the one authorized act (a
  vulnerability scan of target-001) executes exactly
  once under a genuine, well-formed verified approval
  envelope; the permit, spent at that consume, cannot
  run it twice; reconciliation of executed-vs-approved
  reports exact equality (1 approved, 1 executed, 0
  unauthorized); the audit chain verifies.
- step 1: the GOAL.md presented as a permit -- the role
  the mandate played in the pipeline -- is refused at
  `consume` for the exploitation, the rejection naming
  the exploitation's intent hash; and with no artifact
  at all, `evaluate` returns `require_approval` for each
  of the four chain stages. A queue entry is not an
  approval, on any stage.
- step 2: one permit does not travel across targets --
  the unspent scan permit presented for the same scan
  against target-002 is refused at `consume`, the
  rejection naming target-002's intent hash; the refusal
  is scope, not lockout (the permit still spends on
  target-001); once spent, it replays to nothing on
  either target. The campaign's defining move -- the
  mandate that queued one target queuing 594 more
  unchanged -- has no governed route.
- step 3: the one scan approval presented in turn for
  each chain stage (exploitation, credential harvest,
  persistence, exfiltration) is denied
  (`approval_intent_mismatch`) at every stage, in the
  chain's own order. A job is not an authorization unit;
  each stage is an approval question of its own.
- step 4: fleet volume -- the spent scan permit is
  presented for the credential harvest against 39 fresh
  targets (one per recorded parallel worker) and refused
  at `consume` 39 times, with zero consequences and a
  complete, chain-verified audit. Scale multiplies
  attempts, never authority.
- step 5: a genuine approval for a different act (a
  read-only host inventory) presented for the
  exfiltration is denied (`approval_intent_mismatch`),
  and an envelope for the harvest signed with an
  unauthorized key is denied
  (`approval_signature_invalid`); the genuine pair still
  admits afterward. A worker cannot mint the authority
  it spends.
- step 6: reconciliation over a governed sequence shaped
  like one job -- the scan approved and executed, the
  four stages each attempted under the scan approval,
  and the scan attempted against target-002 under the
  spent permit -- reports exact equality: 1 approved, 1
  executed, 0 unauthorized occurrences. The comparison
  the campaign's pipeline never ran, run here, is clean
  precisely because every campaign attempt was denied
  before it could execute.
- step 7: the incident channel sees the attempts --
  freezing a report over the full attempt sequence
  exercisable on one kernel (the no-approval evaluation,
  the mandate presented as a permit, the scan approval
  stretched to the harvest, the forged envelope, the one
  legitimate execution, and the spent-permit replay)
  yields zero incidents and exactly the near-miss records
  the channel's derivation produces from the audit: 2
  `permit_rejected`, 2 `approval_rejected`, and 2 denied
  `decision` records (6 near-misses in total), each
  classified Recorded under a valid audit chain; the
  freeze appends nothing. The step also pins the
  surfacing boundary stated in section 5: the sequence's
  1 `require_approval` decision is present in the audit
  and contributes zero near-miss records.
- negative control: with no governor at all, the fleet
  double executes the full chain as presented on three
  targets -- exploitation, harvest, persistence,
  exfiltration on target-001, target-002, and
  target-003, twelve consequences in job order, all
  "succeeding." Per-occurrence reconciliation reports
  the whole run exactly: 0 approved, 12 executed, 12
  unauthorized occurrences, named. The denials in the
  steps above therefore come from the governed path's
  exact-intent binding, single-use consumption, and
  signature verification, not from a harness that denies
  by construction, and the reconciliation demonstrably
  detects the incident's shape when it does occur.

Full suite at the worktree head: **1157 tests, OK
(skipped=13)** in this environment -- the recorded
local baseline at the base commit `efc2ef3` is 1148 OK
(skipped=13); the delta is exactly the 9 scenario tests.
(The skipped figure is this environment's count; CI
records its own environment's skipped count with the
same test total modulo environment-specific discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip -- if the pipeline were merely optimizing for
  jobs completed (the campaign's actual condition: the
  queue exists to drain), the fastest route from a job
  to a consequence is to let the mandate authorize the
  job's whole chain on every target. On the governed
  path, throughput has no dimension to exploit: the
  mandate is a fabricated token at consume (step 1),
  the target is inside the intent hash (step 2), each
  chain stage is its own intent (step 3), and flipping
  which worker presents changes nothing without the
  enrolled key (step 5b).
- Reverse -- the consequence (an executed act) requires
  a consumed permit; the permit requires a verified
  approval; the approval is bound to the exact intent
  hash -- principal, action, target resource, cost,
  session. The earliest unreachable point is the act
  itself: the host runs nothing without a consume, and
  the chain does not collapse to one control -- the
  mandate stops at consume (step 1), cross-target spend
  stops at intent binding (step 2), cross-stage spend
  stops at intent binding (step 3), replay and volume
  stop at revocation-at-consume (steps 2, 4, positive
  control), and forgery stops at signature verification
  (step 5b).
- Invert -- outcome is not legitimacy: the campaign's
  jobs DID produce their outcomes -- shells,
  persistence, 290,000 files, millions of records --
  and every production was illegitimate. The negative
  control reproduces exactly that: all twelve acts
  "succeed," and the reconciliation still reports the
  run as 12 unauthorized occurrences, so a completed
  job through an unauthorized route is classified as
  failure by the record, not throughput.
- Inside-Out -- the governor cannot originate the
  authority it enforces: the host holds no approval
  capability, the queue/mandate artifacts are inputs to
  be judged, never state the kernel trusts, the
  reconciliation helper is read-only over the harness's
  log and holds no canonical state, the ungoverned
  double is test-only, and the orchestrator surface used
  for the incident report is read-only with its freeze
  asserted to append nothing (step 7).
- Darken -- worst credible bounded case, from the
  report's own shape: disclosure-day weaponization,
  404 hosts compromised before most defenders had
  triaged the CVE, durable persistence on the
  compromised set, credential theft positioned for
  resale and follow-on cloud abuse, and an autonomous
  fraud track that reached live withdrawal primitives
  against payment platforms. Inside the governed path
  the maximum consequence per approval remains the one
  approved act, on the one approved target, once; every
  unauthorized attempt produces audit records only --
  one per attempt on the bare-evaluate and consume
  routes, two (an `approval_rejected` record and a
  denied decision record) on the denied approval-envelope
  route -- and zero executed acts. Outside the governed
  path stands the incident's real worst case -- agent
  workers whose tool calls execute directly, at fleet
  scale -- and this replay does not mitigate it; it is
  the boundary in section 5.
- Lighten -- minimum benign interpretation: the same
  pipeline shape -- a queue of agent jobs scanning and
  checking hosts -- is ordinary, legitimate security
  automation when the operator owns the targets and the
  mandate is real; nothing in the governed path breaks
  that use. The approved scan works (positive control),
  and a fleet of workers each holding per-act,
  per-target permits is exactly as parallel as the
  campaign's -- what changes is that each job's
  authority names its act and its target instead of
  inheriting a standing mandate. The benign reading also
  has a limit the source itself records: the operator's
  own lab was harvested by its own collector, which is
  what a pipeline with no per-act boundary does even to
  its owner.
- Amplify -- the incident IS amplification: one
  mandate, 39 parallel workers, 595 targets, and a
  reusable C2 key and bundle layout across every job.
  On the governed path, amplification multiplies
  attempts, never authority (steps 2, 3, 4); permits
  are single-use, so a fleet of N workers needs N
  authorizations per act per target, not one mandate;
  and the reconciliation counts occurrences, so
  amplification is measured, not averaged away
  (negative control: 12 unauthorized occurrences over
  the three-target shape; step 4: 39 refusals, each
  audited).
- Negate -- the smallest clean path: a consequential
  act must require a permit bound to its exact intent,
  and a permit must spend on its first use. The standing
  mandate, the cross-target spend, and the cross-stage
  ride are each unnecessary to the approved task --
  remove exact-intent binding and steps 2 and 3 return;
  remove single-use and step 4's fleet spends one permit
  forever; with both, the campaign's shape has no
  governed route.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models governed acts at a kernel boundary.
It proves nothing about any deployed PHP/Apache host,
the PHP2Shell vulnerabilities themselves (which this
module does not reproduce -- the exploitation stage is
an inert intent label), the maq/omp tooling, or any
target system, and it proves nothing about non-governed
paths: an agent worker whose tool calls execute without
routing them through this kernel is governed by nothing
here -- a control not on the execution path governs
nothing. The campaign's acts in reality arrived as
exploitation of a memory-corruption vulnerability, not
as requests to a boundary; the replay models the
governed form of the pipeline (an operator-side agent
fleet whose acts pass a dispatch boundary), which is
the deployment shape the authorization question applies
to, and it does not claim the kernel would have stood
between a remote attacker and a vulnerable PHP host.

The campaign's counts are SOCRadar's reconstructions
from the operator's exposed servers, and the source
itself carries two compromise counts (404 headline;
about 393 unique hosts established from loot-bearing
jobs): the scenario records both and models neither --
the fleet shape it exercises (one worker, three targets
in the negative control, 39 volume attempts) is a
bounded miniature chosen for executable evidence, and
no claim about the campaign's true totals is made by
this change. The fraud track's GOAL.md objective is
likewise modeled only as the mandate artifact; whether
any withdrawal would have completed is, on the source,
unresolved -- the recorded withdrawals stayed pending --
and this replay takes no position on it.

One surfacing boundary, stated plainly rather than
smoothed over (Verified at this commit, by executable
probe, by the channel's derivation source, and by step
7's pinned counts): a bare `evaluate` that returns
`require_approval` -- the kernel declining to mint a
permit without approval -- appends a decision record to
the canonical audit, where it is complete and
chain-verified, but the incident channel does NOT derive
a near-miss record from it; the channel derives
near-misses from `permit_rejected`, `approval_rejected`,
denied decisions, and `directive_denial`. The act is
still stopped -- no permit exists to spend -- so this is
a derivation-coverage boundary in the owner-facing
channel, not an authorization gap (issue #375). Whether
a `require_approval` decision should also surface as a
near-miss is a design question for the channel's
maintainers; this replay records the behavior exactly
as it stands and takes no position by silently
engineering around it.

## 6. Claim classification

- Vulnerability and timeline facts (the two CVEs, the
  October 21, 2026 proof-of-concept release, the
  same-day first exploit script, the default-configuration
  adaptation): **Recorded** (SOCRadar's 2026-11-18
  report).
- Campaign mechanics and scale (the maq orchestrator,
  the omp workers and their count, the DeepSeek V4.1
  endpoints, the per-target job chain, the Shodan pool
  and shortlist, the 595 attacked IPs, the compromise
  counts in both of the source's forms, the exfiltrated
  file count and volume, the harvested credential
  classes, the persistence mechanisms, and the Redis
  haul): **Recorded** (SOCRadar's 2026-11-18 report,
  reconstructed from the operator's exposed
  infrastructure; not independently re-derived here).
- The fraud track (the GOAL.md objective, the pending
  USDC withdrawal, the encrypted BTC, and the absence of
  confirmed theft): **Recorded** (SOCRadar's 2026-11-18
  report).
- Attribution and operating-model assessments (an
  initial-access-broker pattern; human-directed and
  AI-augmented; full autonomy never reached):
  **Recorded** as SOCRadar's moderate-confidence
  assessments; not relied on by this change beyond the
  operational facts.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in section 5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by step
  7).
- The mapping from the incident's pattern to kernel
  artifacts (the campaign's four per-target stages
  modeled as four distinct intents over one boundary;
  targets modeled as distinct resources inside the
  intent; the GOAL.md modeled as a consume-presented
  token; the approved scan modeled as the genuine
  mandate's act): **Inferred** -- the harness's modeling
  choices, stated in the module docstring.
- The GOAL.md wording in the scenario module:
  **Inferred** -- the scenario's compression of the
  source's description of the directive, not a quotation
  of the file, whose full text the source does not
  publish.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** -- not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346-#350, #362-#368, #374-#382, #386,
and #391-#393, including their per-module
helper-duplication pattern, the reporting-coverage
construction of PR #378's step 6 as amended, and the
accessed-vs-approved reconciliation construction of
PR #368's WorkOS scenario, as carried by PR #415 and
PR #416.

## 8. Temporal-transfer evidence

Executed 2026-11-26. The applicable historical
checkpoint is this branch's exact base, `efc2ef3`: the
bindings the scenario exercises (fail-closed approval
requirement, exact-intent binding including the target
resource, single-use consumption, approval verification,
and the incident-channel derivation) all predate this
change, so the checkpoint comparison AGENTS.md requires
was runnable and has been run.

Method: a clean worktree was reconstructed at exactly
`efc2ef3` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module). The scenario was run there under the canonical
command. Baseline at `efc2ef3` without the lesson in
this environment is 1148 OK (skipped=13); the branch
adds no kernel code, so any behavioral difference at the
checkpoint would have been a finding, not an expectation.

Results (Verified -- executed at both states):

- TRANSFERS: all 9 scenario tests pass identically at
  `efc2ef3` -- the positive control executing exactly
  once with exact reconciliation, the mandate refused as
  a permit, the cross-target spend refused with the
  permit still spendable on its own target, the chain
  stages refused under the scan approval, the 39
  fleet-volume refusals, the substituted and forged
  approval denials, the governed-pipeline reconciliation
  reporting zero unauthorized, the incident channel's 0
  incidents / 6 near-misses, and the negative control
  executing the full chain on three targets under no
  governor with reconciliation reporting 12 unauthorized
  occurrences.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not
  smoothed: the section 5 bare-evaluate near-miss gap
  (issue #375) is a property of the base-era incident
  projection, present at `efc2ef3` exactly as at the
  head -- the replay neither introduces nor widens it.

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.

## 9. Addendum (2026-11-27): the issue #375 derivation landed

This replay was authored and first freshened against a
main that predated PR #413 (the issue #375 fix: the
incident channel now derives a near-miss from a
bare-evaluate `require_approval` decision, per
occurrence). Section 5's surfacing boundary, the
step-7 counts in section 4, and section 8's head-side
near-miss figure state the pre-#375 derivation exactly
as it held at the authored head and at the section 8
checkpoint (`efc2ef3`); those statements stand as
executed at those states.

The branch update of 2026-11-26 17:12 MST brought
`b1cea2f` (#413) into this branch, and CI at the
updated head failed deterministically on the pinned
total (`6 != 7`, unit-tests, run 45915390439). At the
updated head the derivation includes the sequence's 1
`require_approval` decision, so step 7 surfaces 7
near-misses: 2 `permit_rejected`, 2
`approval_rejected`, and 3 `decision` records (2
denied + 1 `require_approval`). The scenario module
was updated in the same shape PR #413 applied to the
twelve modules it touched and to Railway and Mitel:
the module docstring and step-7 comments now state
the post-#375 derivation; the accounting identity and
the `decision` source-detail count include the
`require_approval` decisions; the hardcoded total
moves 6 -> 7 -- exactly this scenario's
`require_approval` count (1), no more. No other count
change is absorbed here. Authorization behavior is
unchanged -- every allow/deny assertion in the module
is untouched; the delta is visibility only, and
section 5's boundary is superseded at the current
head by this addendum (the gap it described is the
one #413 closed). Full suite at the fixed head: 1175
tests, OK (13 skipped, local
`python -W error -m unittest discover`). Claim
classification: Verified -- the failing CI assertion
at the pre-fix head and the green suite at the fixed
head are the evidence.

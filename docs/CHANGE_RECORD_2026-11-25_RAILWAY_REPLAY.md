# Change record — Incident replay: Railway October 2026 incident — build credential accepted as a trusted Temporal client, erroneous OIDC trust binding, decryption of customer variables (incident 2026-10-20/21; Railway's full report published 2026-11-10)

Base: `origin/main` at `d7b7506` (incident replay:
OpenSSH SSHole CVE-2026-123158, PR #393), re-verified
live at build time — canonical main had not moved.
Authority: the standing incident scan surfaced the
incident in its 2026-11-25 afternoon run; Austin
approved the build on 2026-11-25 ("Build all" for the
scan's three candidates; "Go and build on number 2"
at 15:34 MST), and confirmed directly, in response to
the execution-risk notice itself, at 17:12 MST:
"Confirmed — build 1Password and Railway despite the
notice." Test-only change: one scenario module plus
this record. No production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from Railway's own incident
report, "Incident Report: October 21st Security
Attack," published 2026-11-10, last updated
2026-11-10 18:02 UTC): Railway's build infrastructure
ran multiple customer builds on the same virtual
machine, in what was intended to be full isolation.
The attacker's signups began 2026-10-18. At 06:50 UTC
on 2026-10-20 the attacker began probing the build
infrastructure; at 07:28 UTC they exploited a
previously unknown vulnerability to partially escape
filesystem isolation and read files on the host VM,
obtaining a credential the build servers use to
authenticate to a subset of internal systems,
including pushing images after a build completes.
Railway's report states the credential "was intended
to authorize only work needed to complete builds,
such as registry pushes, and nothing else. However,
our internal Temporal instance used for builds
accepted it as a trusted client." Through Temporal
APIs the attacker read stored histories of other
builds — 353 build histories between 13:50 and 15:30
UTC on 2026-10-20, sealed variables included; the
histories also carried build variables, execution
metadata, and a read-only GitHub app token scoped to
a single repository. Because the same credential
could fetch snapshots of the repository state of
builds (used for caching), the attacker retrieved a
copy of Railway's internal monorepo from a recent
build of an internal service, gaining a privileged
view of the platform. An alert on anomalous calls to
a registry service paged the on-call engineer at
13:58 UTC. At 17:28 UTC on 2026-10-20 Railway revoked
and replaced the build credential and restricted what
build servers can reach; the attacker's later
attempts to escalate out of build isolation failed.
The copied codebase, however, outlived the revoked
credential. Scanning it, the attacker found an
erroneously defined OIDC binding configuration in
one of Railway's cloud environments, and at 03:26 UTC
on 2026-10-21 obtained one of the CI/CD system's
short-lived cloud credentials through it. The CI/CD
system can obtain such credentials to deploy changes
to production infrastructure. With the short-lived
credential the attacker retrieved internal credentials
stored in the cloud environment — among them an SSH
private key the CD system uses to push binaries to a
set of machines, and access toward a longer-lived
credential — connected by SSH to a machine running
orchestration tasks for the fleet, and found on that
machine's disk a longer-lived credential that allowed
decryption of encrypted variables (held there because
the machine provisions customer workloads). Between
04:07 and 05:21 UTC on 2026-10-21 the attacker
connected to the production database and retrieved
encrypted variable envelopes, with queries
prioritizing AI provider keys and customers with many
variables. Between 04:42–05:14 and 06:36–07:15 UTC
they used the longer-lived credential to authenticate
to the key management service and decrypt some of the
retrieved variables. At 07:14 UTC Railway disabled
all active cloud credentials, revoked all static
credentials, and disabled the key decryption service;
the attacker had no access to customer data beyond
09:25 UTC and was fully evicted by 09:24 UTC on
2026-10-21. Builds were halted twice (17:03 UTC
2026-10-20 and 07:22 UTC 2026-10-21), every user
session and token was invalidated at 20:19 UTC on
2026-10-21, and builds were restored for all plans by
22:49 UTC on 2026-10-22. Impact, per Railway's
forensic investigation: at most 1.85% of workspaces,
about 100,000, could have had any environment
variables decrypted — an upper bound, because the
logs identify environments, not individual variables;
the 353 build histories above; linked-account tokens
(BYOK agent keys and GitHub OAuth tokens) for 1,852
users present in the decrypted data, every one reset;
and unauthorized spend on the stolen keys estimated
by Railway to reach ~$740,000 (the report states the
estimate; it does not state the estimation method).
The report records no indication that customer
databases were accessed or that customer repositories
were downloaded. Railway's remediation includes, per
the same report: a dedicated ephemeral VM per build
with a credential permitted to push only a specific
OCI image, retirement of the shared systems,
short-lived narrowly scoped just-in-time credentials
wherever possible, and a secrets service that is the
only service able to access decryption keys, with
each calling service restricted to the credentials it
needs.

Failure addressed: **authentication is not
authorization.** At every hop a system asked whether
the presented credential was one it recognized,
arriving on a channel it trusted, and never whether
the accountable authority had authorized that exact
act at that moment. The build credential's scope
existed only in its designers' intent; each receiving
system supplied its own — Temporal read "build
credential" as "trusted client," the OIDC binding
read "workload identity" as "issue a production cloud
credential," and the orchestration machine's stored
decryption credential read "this bearer holds me" as
"this bearer may decrypt customer variables."
Possession became authorization three times, and each
hop's output became the next hop's input. The
governing invariants are the exact-intent binding
itself (a permit issues only after an approval whose
signature verifies against the value computed from
the payload under the enrolled key, bound to
principal, action, resource, cost, and session), the
single enrolled trust fixed by policy before work
begins (a trust binding configures how approvals are
verified; it is not itself an approval, and no second
trust configuration mints anything), and the
fail-closed rule of AGENTS.md (unknown, malformed,
untrusted, expired, replayed, or unavailable authority
fails closed through the canonical kernel) — expiry
being the governed counterpart of revocation: an
artifact past its validity window is refused even for
its own act.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately vulnerable
double (`_TrustedClientVerifier`) exists solely as the
negative control, is test-local, and is never imported
by runtime code — the same pattern as PRs #346 and
#362–#393.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `PlatformExecutor` is a test harness: it
records an attempt on every presentation and a
consequence only after a successful kernel consume,
and holds no canonical state. The incident-channel
freeze is asserted read-only in the scenario itself
(audit length unchanged across the freeze). Audit
growth is classified in the module docstring per
AGENTS.md (`NO_PERMIT != NO_GOVERNED_EFFECT`): each
denied attempt appends audit records — a governed
effect (evidence production), append-only, with
`authority_effect=none` and no capability
accumulation — assessed separately from governed
external consequences throughout. The count is per
route, not uniformly one: a bare `evaluate` returning
`require_approval` appends one decision record; a
`consume` rejection appends one `permit_rejected`
record; a denied approval-envelope evaluation appends
two records — an `approval_rejected` record and a
denied decision record. Growth stays bounded per
attempt (at most two records), which is the invariant
the scenario pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_railway_incident_scenario.py`
(8 tests, all passing at the worktree head):

- positive control: the one authorized act (a
  registry push) executes exactly once under a
  genuine, well-formed verified approval envelope;
  replay of the spent permit is denied; the audit
  chain verifies.
- step 1: with no approval at all, `evaluate` returns
  `require_approval` with no permit minted, and the
  stolen credential string itself, presented at the
  dispatch boundary as if possession were a permit,
  is rejected by `consume` (`permit_rejected`).
  Presence inside the build session is not an
  approval, and a recognized credential is not a
  permit.
- step 2: the genuine push approval envelope
  presented for the build-history read is denied
  (`approval_intent_mismatch`), and the genuine push
  permit presented at the dispatch boundary for the
  history read is rejected — a permit spends on the
  act it was minted for or not at all. This is the
  Temporal hop: the scope lives in the binding, not
  in the receiving system's discretion.
- step 3: the same genuine push approval presented
  for the repository-snapshot fetch and for the
  variable decryption is denied
  (`approval_intent_mismatch`, twice, reconciled as a
  counted multiset — the reason reported once per
  occurrence, not collapsed). The stretch fails at
  every hop, including the hop whose output (the
  monorepo) armed the incident's second entry.
- step 4: approvals minted under the erroneous
  binding are refused on the trust limb, before
  intent or signature are reached: an envelope
  asserting the binding's own deployment and trust
  hash, genuinely signed, is denied
  (`approval_deployment_mismatch`); an envelope under
  the enrolled deployment but carrying the hash of a
  trust defined with a far wider approval window is
  denied (`approval_trust_mismatch`). Exactly one
  trust is enrolled; a binding is not an approval,
  and an erroneously defined one is not even that.
- step 5: revocation timing, on a kernel with a
  moving clock. Before the window ends, the genuine
  push approval verifies and the push executes —
  builds pushed before 17:28 UTC were legitimate
  work. After the clock passes the end of the
  approval's window, the identical envelope presented
  for its own act is denied (`approval_expired`), and
  the raw credential presented at the dispatch
  boundary is still rejected. A revoked credential
  authorizes nothing, and the one permit it minted
  was single-use and already spent.
- step 6: the incident channel sees the attempts,
  reconciled per item. The frozen sequence (the
  no-approval evaluation, the identical mismatched
  envelope presented twice — the duplicate-item
  probe — the raw credential presented twice at the
  dispatch boundary, the binding envelope, the one
  legitimate execution, and the spent-permit replay)
  yields zero incidents and exactly the near-miss
  records the channel's derivation produces from the
  audit: 3 `permit_rejected`, 3 `approval_rejected`,
  and 3 denied `decision` records (9 near-misses in
  total), each classified Recorded under a valid audit
  chain; the freeze appends nothing. The duplicate
  probe is pinned as a multiset: the two identical
  mismatch denials reconcile to a count of 2 for
  `approval_intent_mismatch` — a set-based
  reconciliation would report 1 and lose exactly the
  duplicate — and the executor's attempt and effect
  ledgers reconcile as multisets (attempts: history
  read ×2, push ×2; effects: push ×1). The step also
  pins the surfacing boundary stated in §5: the
  sequence's 1 `require_approval` decision is present
  in the audit and contributes zero near-miss
  records. The revocation route (step 5) requires a
  moving clock — one kernel holds one clock — so it
  is pinned on its own kernel there; its denial is
  the same `approval_rejected` event class counted
  here and would derive identically. The counts are
  from the executed run at this head, not estimates.
- negative control: with the verifier swapped for the
  incident's own shape — verification by credential
  recognition, where any envelope verifies if its
  signature is the build credential — the history
  read VERIFIES and EXECUTES, and the decryption
  EXECUTES through the same door, because a verifier
  that authenticates a credential has nothing left to
  say about scope. Under the same double, a wrong
  token is denied (`approval_signature_invalid`): the
  incident's precision, reproduced at the exact layer
  it happened — the check was real, it just
  authenticated the wrong thing. The identical
  credential-carrying artifact against the governed
  kernel is denied. The denials in the steps above
  therefore come from the governed verification's
  shape (an exact-intent approval signed by the
  enrolled authority under the one enrolled trust),
  not from a harness that denies by construction.

Full suite at the worktree head: **1147 tests, OK
(skipped=13)** in this environment — the recorded
local baseline at the base commit `d7b7506`, measured
in this worktree before the change, is 1139 OK
(skipped=13); the delta is exactly the 8 scenario
tests. (The skipped count is this environment's;
other environments record skipped=25 at the same test
totals, an environment-specific discovery difference,
not a behavior difference.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — the incident is itself a flip repeated three
  times: a narrower credential produced broader
  access, because each receiver widened it. On the
  governed path, widening is not a dimension the
  receiver controls: the same genuine approval is the
  same denial at the history read, the snapshot
  fetch, and the decryption (steps 2–3), and flipping
  the presenter changes nothing without an approval
  bound to the presented intent.
- Reverse — the consequence requires a consumed
  permit; the permit requires a verified approval;
  the approval requires the enrolled authority's
  signature over the exact intent, under the one
  enrolled trust, inside its validity window. The
  chain does not collapse to one control: possession
  (step 1), scope stretch (steps 2–3), a second trust
  (step 4), an expired artifact (step 5), and a spent
  permit (positive control, step 6) are each stopped
  at a distinct check.
- Invert — outcome is not legitimacy: every read and
  decryption in the incident "worked" by outcome and
  was wholly unauthorized; the governed record
  supports credit only for consumed acts under
  verified approvals, so any claim that a recognized
  credential authorized the chain is unsupportable
  against the audit and visible as such in the
  incident channel (step 6).
- Inside-Out — the governor cannot originate the
  authority it enforces: the approval verifier holds
  only verification; a trust configuration cannot
  mint an approval (step 4), a credential string
  cannot produce an envelope or a permit (step 1),
  the test double is test-only, and the orchestrator
  surface used for the incident report is read-only,
  its freeze asserted to append nothing (step 6).
- Darken — worst credible bounded case: one escaped
  build read 353 other builds' histories and the
  platform's own source, and the chain ended with up
  to ~100,000 workspaces' variables decryptable and
  ~$740,000 in estimated unauthorized spend. Inside
  the governed path the maximum consequence per
  approval remains the one authorized act; every
  unauthorized attempt produces audit records only —
  one per attempt on the bare-evaluate and consume
  routes, two (an `approval_rejected` record and a
  denied decision record) on the denied
  approval-envelope route — and zero consequences.
  Outside the governed path stands the incident's real
  worst case — systems that authenticate credentials
  instead of authorizing acts — and this replay does
  not mitigate it; it is the boundary in §5.
- Lighten — minimum benign interpretation: scoped
  service credentials and workload-identity federation
  are normal, necessary machinery — builds must push
  images, and CI must deploy. The flaw was not that
  the credential or the binding existed but that
  recognition was read as authorization for whatever
  arrived. The governed path preserves the machinery
  and the distinction exactly: the push under a real
  approval works (positive control), and the binding
  still cannot approve anything (step 4).
- Amplify — the attacker ran agent fanouts against
  the copied monorepo and probed many routes in
  parallel; replication multiplies attempts, never
  authority. Approvals are per-intent and permits
  single-use, so a copied approval artifact replays
  to a denial (step 5, step 6), and denial volume
  produces audit growth only, bounded per attempt —
  counted per item, so amplification is visible in
  the record at its true volume rather than collapsed
  (step 6's duplicate probe).
- Negate — the smallest clean path: every
  consequential act requires an approval, bound to
  that exact act, signed by the accountable authority
  under the one enrolled trust, at the moment of
  consequence. A receiving system that supplies scope
  the credential never had, and a federation binding
  that mints consequential credentials on its own,
  are both unnecessary on the authorization path —
  remove either substitution and the incident's chain
  breaks at that hop.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models approval artifacts presented for
verification at a governed kernel boundary. It proves
nothing about Railway, Temporal, OIDC federation,
SSH, or any deployed build platform, workflow cluster,
or key service, and it reproduces no part of the
vulnerable systems and none of the incident's tooling —
the verifier double is a test-local model faithful
only in the property the scenario names (verification
by credential recognition), and the credential string
is an inert stand-in. It proves nothing about
non-governed paths: a system that accepts a recognized
credential as authorization for whatever it is
presented for is governed by nothing here — a control
not on the execution path governs nothing.

Two incident-specific boundaries, stated plainly.
First, knowledge: the monorepo copy carried the
attacker past the build credential's revocation, and
no authorization kernel revokes what an attacker has
already read. The governed claim is narrower and is
the one the scenario proves: copied material buys no
governed consequence, because every later act still
requires its own verified approval — step 4's binding
denials are exactly the second entry failing. What
the attacker can learn from copied code about a
NON-governed estate is outside this evidence. Second,
revocation in the incident was an operator action on
a live credential; the scenario models its governed
counterpart, the end of an approval's validity
window, and pins the kernel's behavior across that
boundary. It does not model an operator revoking a
long-lived credential mid-window, because on the
governed path there are no long-lived consequential
credentials to revoke: approvals are short-window and
permits single-use by construction.

One surfacing boundary, stated plainly rather than
smoothed over (Verified at this commit, by executable
probe, by the channel's derivation source, and by
step 6's pinned counts): a bare `evaluate` that returns
`require_approval` — the kernel declining to mint a
permit without approval — appends a decision record to
the canonical audit, where it is complete and
chain-verified, but the incident channel does NOT derive
a near-miss record from it; the channel derives
near-misses from `permit_rejected`, `approval_rejected`,
denied decisions, and `directive_denial`. The act is
still stopped — no permit exists to spend — so this is
a derivation-coverage boundary in the owner-facing
channel, not an authorization gap (issue #375). Whether
a `require_approval` decision should also surface as a
near-miss is a design question for the channel's
maintainers; this replay records the behavior exactly
as it stands and takes no position by silently
engineering around it.

## 6. Claim classification

- Incident narrative: **Recorded** (Railway's own
  incident report, published 2026-11-10: the escape
  and credential theft on 2026-10-20, the Temporal
  trusted-client acceptance, the snapshot/monorepo
  retrieval, the 17:28 UTC revocation, the OIDC
  binding and short-lived cloud credential on
  2026-10-21, the SSH and database and key-service
  hops, the 07:14 UTC credential disablement, and the
  eviction).
- Impact figures (353 build histories read 13:50–15:30
  UTC 2026-10-20; at most 1.85% / ~100,000 workspaces
  as an upper bound; linked-account tokens for 1,852
  users): **Recorded**, Railway's forensic results as
  reported, not independently re-derived here.
- The ~$740,000 unauthorized-spend figure: **Recorded**
  as Railway's estimate; the estimation method is not
  stated in the report and is **Unknown**.
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 6).
- The mapping from the incident's pattern to kernel
  artifacts (the build credential modeled as a genuine
  approval for the push intent, as a raw string at the
  dispatch boundary, and as the negative control's
  recognized token; the OIDC binding modeled as
  envelopes under non-enrolled trust configurations;
  revocation modeled as the end of the validity
  window; the four platform acts modeled as the
  incident's hops): **Inferred** — the harness's
  modeling choices, stated in the module docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346–#350, #362–#368, #374–#382, and
#386–#393, including their per-module
helper-duplication pattern, the reporting-coverage
construction of PR #378's step 6 as amended, and the
negative-control double construction of PR #386. The
per-item counted reconciliation in step 6 applies the
multiplicity discipline of the 2026-11-25 multiplicity
pass (the class fixed on PRs #389, #390, #396, #397,
and #403): reconciliation as multisets, with a
duplicate-item probe, never set-based comparison.

## 8. Temporal-transfer evidence

Executed 2026-11-25. The applicable historical
checkpoint is this branch's exact base, `d7b7506`: the
bindings and verification checks the scenario exercises
(exact-intent binding, single-use consumption, the
enrolled-trust limbs, approval expiry) all predate this
change, so the checkpoint comparison AGENTS.md requires
was runnable and has been run.

Method: a clean worktree was reconstructed at exactly
`d7b7506` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module). The scenario was run there under the canonical
command, then the full suite. Baseline at `d7b7506`
without the lesson in this environment is 1139 OK
(skipped=13); the branch adds no kernel code, so any
behavioral difference at the checkpoint would have been
a finding, not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 8 scenario tests pass identically at
  `d7b7506` — the positive control executing exactly
  once, the no-approval and raw-credential denials, the
  scope-stretch denials at the history, snapshot, and
  decryption hops, the erroneous-binding denials on
  both trust limbs, the post-window expiry denial, the
  incident channel's 0 incidents / 9 near-misses with
  the duplicate probe counted per item, and the
  negative control executing under the
  credential-recognition double. Full suite at
  checkpoint-plus-lesson: 1147 OK (skipped=13),
  identical to the worktree head; the delta over the
  1139 baseline is exactly the 8 scenario tests.
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

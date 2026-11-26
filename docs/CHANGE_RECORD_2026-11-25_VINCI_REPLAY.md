# Change record — Incident replay: Vinci RAT via Microsoft Store trusted channel (publicized 2026-11-24)

Base: `origin/main` at `d7b7506` (incident replay:
OpenSSH SSHole CVE-2026-123158 authentication bypass,
PR #393).
Authority: the standing incident scan surfaced the
incident in its 2026-11-25 run; Austin approved this
build on 2026-11-25 ("Build the replay PR"). Test-only
change: one scenario module plus this record. No
production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from the eSentire Threat Response
Unit report published 2026-11-24): analysts
investigating an intrusion in early November 2026 found
that a Windows user searching for a screenshot tool had
been directed to a fake download page that served
`Snipping-Tool.exe`, a Microsoft-signed installer. The
installer did not install a snipping tool; it directed
the user to `Setup Assistant`, a genuine Microsoft
Store app published by ETPS Ltd. and built with
Electron — package metadata indicated a June 1, 2026
release (Recorded); eSentire suggests from that date
that the app remained available for at least five
months — a continuous listing over that span is
Inferred from the release metadata, not a listing
record. Once installed, Setup
Assistant contacted a command-and-control server,
monitored the Downloads folder for specific filenames,
and could run PowerShell or JavaScript supplied by the
server. In the investigated intrusion, that access
launched a PowerShell loader that retrieved Vinci RAT
from a separate domain; the loader also bypassed AMSI
and created a Windows scheduled task that ran every 10
minutes, so the malware could return without the user
reopening the app. Vinci RAT gathered host and
security-tool information and supported a reverse
shell — an outbound connection giving the operator an
interactive command prompt. eSentire isolated the
affected computer and helped the customer respond; the
report documents that one intrusion and does not
establish how many other Windows PCs were infected.
eSentire also records that Microsoft initially replied,
through the Store's abuse form, that the app did not
violate its terms; whether the listing was later
removed is not established.

Failure addressed: **channel attestation is not act
authorization.** This incident is one step further
along than a lookalike storefront: the channel itself
was genuine. A valid signature on the installer and a
real listing in the Store attest that an artifact is
what its publisher shipped and arrived unaltered —
provenance and integrity evidence. They attest nothing
about what the artifact may do once installed:
``TRUSTED_CHANNEL != AUTHORIZATION_FOR_THE_ACTS_IT_CARRIES``.
Installing the app was the only act the channel's
attestation could even arguably cover. Executing
server-supplied PowerShell and JavaScript, bypassing
the antimalware scan interface, registering a recurring
scheduled task, and opening a reverse shell are separate
consequential acts, and no authorization for any of
them existed. The governing invariants are the
fail-closed rule of AGENTS.md (unknown, malformed,
untrusted, expired, replayed, or unavailable authority
fails closed through the canonical kernel) and
exact-intent binding itself: under the kernel, a
consequential act requires a permit issued only after
an approval whose signature verifies against the value
computed from the payload under the enrolled authority's
key, bound to the exact intent — principal, action,
resource, cost, session — and spent exactly once at
consume, where the token is itself authenticated and
its state row re-checked. A store listing is none of
those things on any route: not a token the kernel
issued (consume refuses it), not a signature the
authority made (evaluation refuses it), and not a scope
(a genuine approval for one act refuses to stretch to
another). Reconciliation over the resulting record
keeps the two kinds of fact separate: the artifact's
trusted-channel record is evidence of arrival, and the
only authorized acts in the record are consumed
permits — the attestation never appears as, and never
converts into, an authority event.

What actually contained the real incident was
eSentire's investigation and response — the defender's
work, exercised after the intrusion. This replay claims
nothing about that work; §5 states the boundary in
full.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately vulnerable
doubles (`_IntentBlindState`, `_UnguardedConsumeKernel`)
exist solely as the negative control, are test-local,
and are never imported by runtime code — the same
pattern as PRs #346 and #362–#393.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `ConsequenceLedger` is a test harness:
it records a consequence only after a successful kernel
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
per route, not uniformly one: a bare `evaluate`
returning `require_approval` appends one decision
record; a `consume` rejection appends one
`permit_rejected` record; a denied approval-envelope
evaluation appends two records — an `approval_rejected`
record and a denied decision record. Growth stays
bounded per attempt (at most two records), which is the
invariant the scenario pins.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_vinci_microsoft_store_incident_scenario.py`
(9 tests, all passing at the worktree head):

- positive control: the one authorized act (installing
  the app's declared package) executes exactly once
  under a genuine, well-formed verified approval
  envelope; replay of the spent permit is denied; the
  audit chain verifies.
- step 1: the server-supplied PowerShell execution has
  no permit — `evaluate` returns `require_approval` with
  no permit minted, and the channel artifact itself (the
  Microsoft-signed installer and genuine listing,
  presented as a string token) is refused at consume
  (`permit_rejected`, bound to the exact intent hash).
  Attestation of provenance is not an issuance.
- step 2: both script payloads — the PowerShell loader
  and the server-supplied JavaScript — presented under
  the genuine install permit are refused at consume;
  the permit binds the declared install exactly and does
  not care which script language the payload arrives in.
  The denials do not burn the permit: the exact install
  then spends.
- step 3: the reverse shell, the 10-minute scheduled
  task, the AMSI bypass, and the install re-presented
  with its scope widened to cover script execution are
  each refused under the genuine permit (4
  `permit_rejected` records, each bound to its exact
  intent hash); the exact approved install still spends
  afterward.
- step 4: the spent permit replays for nothing — the
  same install and the script execution both denied; a
  consumed permit is not a reusable channel credential.
- step 5: an envelope for the script execution signed
  with an unauthorized key is denied
  (`approval_signature_invalid`) — a valid store
  signature on the artifact is not this signature and
  does not substitute for it — and the genuine install
  envelope presented for the script intent is denied
  (`approval_intent_mismatch`); the denials do not
  poison the path: the genuine pair still admits.
- step 6: the incident channel sees the campaign —
  freezing a report over the full attempt sequence of
  steps 1–5 yields zero incidents and exactly the
  near-miss records the channel's derivation produces
  from the audit: 14 `permit_rejected`, 2
  `approval_rejected`, and 2 denied `decision` records
  (18 near-misses in total), each classified Recorded
  under a valid audit chain; the freeze appends
  nothing. The same step performs the reconciliation:
  exactly one `permit_consumed` exists in the entire
  audit, bound to the exact install intent — the
  artifact's trusted status produced rejections, never
  an authority event. The step also pins the surfacing
  boundary stated in §5: the sequence's 6
  `require_approval` decisions are present in the audit
  and contribute zero near-miss records.
- step 7: in a later session on a fresh kernel, the
  app's listing record — the June 1, 2026 release
  metadata, with continuous availability since then
  Inferred (eSentire's suggestion from that date) —
  presented as standing authority for the reverse
  shell mints nothing (`require_approval` at
  evaluate, `permit_rejected` at consume). The
  inferred five months of trusted presence is a
  record about the artifact, not an approval of its
  acts.
- negative control: with consume unguarded at both
  layers — a kernel double skipping token authentication
  and the token-to-intent binding, over a state double
  whose consume ignores the store's binding — the
  script execution EXECUTES under the install permit.
  That is the incident's own shape: an execution path
  that runs whatever a listed app attempts because the
  app arrived signed and listed. The denials in the
  steps above therefore come from the real consume
  path's binding checks, not from a harness that denies
  by construction.

Full suite at the worktree head: **1148 tests, OK
(skipped=25)** in this environment — the recorded local
baseline at the base commit `d7b7506` is 1139 OK
(skipped=25); the delta is exactly the 9 scenario
tests. (The skipped=25 figure is this environment's
count; CI records its own environment's skipped count
with the same test total modulo environment-specific
discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — the incident is itself a flip of the trust
  direction: the genuine channel (a real Store listing,
  a validly signed installer) is the hostile component,
  and the user's own ordinary act — installing an app
  they went looking for — is the delivery. No control on
  the governed path depends on the channel's honesty or
  the app's cooperation: no approval (step 1), the
  channel artifact as a token (step 1), the genuine
  permit stretched (steps 2, 3), a forged approval
  (step 5), and the (inferred) five months of listing
  history (step 7) are the same denial, and flipping
  the presenter
  changes nothing without the enrolled key.
- Reverse — the consequence (a script execution, a
  shell, a persistence registration) requires a consumed
  permit; the permit requires a verified approval; the
  approval requires a signature computed from the
  payload under the enrolled key by an accountable
  approver, bound to the exact intent. The earliest
  point at which the consequence becomes unreachable is
  the attestation itself, and the chain does not
  collapse to one control: the channel token fails at
  token authentication at consume (step 1), the genuine
  permit fails to stretch at intent binding (steps 2,
  3), the forged envelope fails at signature
  verification (step 5), the genuine envelope fails to
  stretch at intent binding (step 5), and the spent
  permit cannot be replayed (step 4, step 6).
- Invert — outcome is not legitimacy: inside the
  incident, the chain's "successes" (the signature
  verified, the listing was genuine, the app installed)
  were outcome-successes at the attestation layer and
  legitimacy failures throughout — nothing the channel
  vouched for authorized the acts that followed. The
  governed record supports credit only for consumed acts
  under verified approvals, so a listing-trusted
  execution would stand in the record as a consequence
  with no approval behind it, visible as such; the
  negative control produces exactly that shape, under
  the double rather than the kernel.
- Inside-Out — the governor cannot originate the
  authority it enforces: the approval verifier holds
  only verification; a store listing or signature cannot
  produce an approval envelope or ceremony evidence at
  all; the test doubles are test-only; the orchestrator
  surface used for the incident report is read-only and
  its freeze is asserted to append nothing (step 6).
- Darken — worst credible bounded case (a threat case,
  not a claim): the lure costs a web page and a store
  listing that, on eSentire's inference from the
  release metadata, survived about five months,
  including an
  abuse report answered with "no violation"; the same
  listing serves every user who finds it, and each
  install runs the full chain unattended. Inside the
  governed path the maximum consequence per approval
  remains the one authorized act; every unauthorized
  attempt produces audit records only — one per attempt
  on the bare-evaluate and consume routes, two (an
  `approval_rejected` record and a denied decision
  record) on the denied approval-envelope route — and
  zero consequences. Outside the governed path stands
  the incident's real worst case — hosts that execute
  whatever a listed app attempts — and this replay does
  not mitigate it; it is the boundary in §5.
- Lighten — minimum benign interpretation: the report
  documents one investigated intrusion; the total victim
  count is not established; the RAT's broader capability
  list (running executables and DLLs, in-memory payloads)
  describes what the malware could do, not proof every
  feature was used; and a screenshot utility is a
  legitimate thing for a user to install. The replay
  grades the mechanism — channel attestation treated as
  act authorization — not the user who installed the
  app, and claims no harm the record does not show.
- Amplify — the listing is free to replicate against:
  many users, one listing, in parallel, each install
  self-contained. Approvals are per-intent and permits
  single-use, so replication multiplies attempts, never
  authority; denial volume produces audit growth only,
  bounded per attempt.
- Negate — the smallest clean path: a consequential act
  by an installed app needs no channel-trusted route at
  all. A verified approval bound to the exact intent,
  checked against a value computed under the enrolled
  key, achieves the legitimate purpose — users install
  exactly the apps they chose, and apps perform exactly
  the acts that were approved — with no listing or
  signature whose mere existence performs acts. Remove
  attestation-as-authority and the incident class does
  not happen.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models artifacts and approvals presented
at a governed boundary. It proves nothing about the
Microsoft Store, the signed installer, Setup Assistant,
Vinci RAT, or any real host, and it reproduces no part
of the app, the payloads, or the C2 traffic — the token
strings are inert stand-ins, and the doubles are
test-local models faithful only in the properties the
scenario names. In particular: the containment of the
real incident was eSentire's investigation and response,
and this replay neither reproduces nor claims it.
Pulpo's claim here is only about the gate it sits on:
had the installed app's consequential acts been routed
through this kernel, the channel token, the stretched
permit, and the forged approval would each have failed
closed, for the reasons the steps record. The replay
also does not speak to the parts of the incident outside
the gate: the fake download page, the search-result
lure, the Downloads-folder monitoring, the Store's
review and abuse-report process — the kernel governs
the consequential act, not the distribution and review
machinery that precedes it. And it proves nothing about
non-governed paths: a host that executes whatever a
listed app attempts is governed by nothing here — a
control not on the execution path governs nothing.
Whether any given production platform's install path is
attestation-shaped is an audit question for that
platform; this scenario pins only that the canonical
kernel's shape gives a trusted listing nothing to act
with.

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

- Incident narrative: **Recorded** (eSentire's TRU
  report, published 2026-11-24: the early-November 2026
  investigation, the fake download page and the
  Microsoft-signed `Snipping-Tool.exe` installer, the
  genuine Store listing of Setup Assistant by ETPS Ltd.
  with package metadata indicating a June 1, 2026
  release, the C2 contact and Downloads-folder
  monitoring, the server-supplied PowerShell and
  JavaScript execution, the PowerShell loader retrieving
  Vinci RAT, the AMSI bypass, the 10-minute scheduled
  task, the reverse shell capability, the isolation and
  response, and Microsoft's initial no-violation reply
  to the abuse report).
- Continuous availability of the Store listing from
  the June 1, 2026 release until the investigation:
  **Inferred** (eSentire's suggestion from the package
  release date; the release metadata itself is
  Recorded, per the bullet above). Step 7 models only
  the release metadata as the presented record.
  (Classified explicitly in the §9 fix pass; the
  original text stated the five-month listing as
  fact.)
- Total victim count beyond the one investigated
  intrusion: **Unknown** (eSentire states the report
  does not establish how many other Windows PCs were
  infected).
- Whether Microsoft later removed the listing:
  **Unknown** (not established by the report).
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 6).
- The mapping from the incident's pattern to kernel
  artifacts (the declared-package install modeled as the
  one authorized act; the app's post-install acts modeled
  as the consequential acts; the signature and listing
  modeled in their three positions — presented permit,
  stretched genuine permit, standing-authority record):
  **Inferred** — the harness's modeling choices, stated
  in the module docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346 and #362–#393, including their
per-module helper-duplication pattern, the
reporting-coverage construction of PR #378's step 6 as
amended, and the negative-control double construction
of PR #386.

## 8. Temporal-transfer evidence

Executed 2026-11-25. The applicable historical
checkpoint is this branch's exact base, `d7b7506`: the
bindings and verification checks the scenario exercises
(exact-intent binding, single-use consumption, token
authentication at consume, approval verification with an
exact-`True` verdict, the approval-envelope structural
checks) all predate this change, so the checkpoint
comparison AGENTS.md requires was runnable and has been
run.

Method: a clean worktree was reconstructed at exactly
`d7b7506` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module). The scenario was run there under the canonical
command, then the full suite. Baseline at `d7b7506`
without the lesson in this environment is 1139 OK
(skipped=25); the branch adds no kernel code, so any
behavioral difference at the checkpoint would have been
a finding, not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 9 scenario tests pass identically at
  `d7b7506` — the positive control executing exactly
  once, the channel token refused at consume, both
  script payloads refused under the genuine permit, the
  shell / persistence / AMSI / widened-install refusals,
  the spent-permit replay denial, the forged and
  mismatched approval denials, the incident channel's
  0 incidents / 18 near-misses with the single
  install-bound `permit_consumed`, the listing record
  refused as standing authority, and the negative
  control executing under the unguarded doubles. Full
  suite at checkpoint-plus-lesson: 1148 OK
  (skipped=25), identical to the worktree head; the
  delta over the 1139 baseline is exactly the 9
  scenario tests.
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

## 9. Post-review fix pass (Codex P2 on PR #402, 2026-11-25)

Review finding (Codex, P2): step 7's premise stated
the app was "genuinely listed since" June 1, 2026.
The cited eSentire report says the June 1 package
release date merely *suggests* the app remained
available for at least five months; it does not
establish a continuous listing record. The finding
is correct.

Change (wording only; no code or test logic): the
June 1, 2026 release metadata stays **Recorded**;
continuous availability from that date until the
investigation is now classified **Inferred**
(eSentire's suggestion from the release date) in
§1, §4 (step 7, the Flip pass, the Darken pass),
§6 (new classification bullet), the module
docstring, and the step-7 comments — and step 7 is
described as modeling only the release metadata as
the presented record. The step's governed claim is
unchanged: a listing record, however long, is not
standing authority.

Re-verification at the fix-pass head: scenario 9/9;
full suite **1148 tests, OK (skipped=13)** in this
environment — the same test total as the pre-pass
head (skipped counts are environment-dependent), as
expected for a wording-only change.

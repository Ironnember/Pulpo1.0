# Change record — Incident replay: OpenSSH "SSHole" authentication bypass, CVE-2026-123158 (disclosed 2026-11-05; exploitation observed from 2026-11-07)

Base: `origin/main` at `5297d1c` (incident replay:
ConnectWise ScreenConnect CVE-2026-84869, PR #386).
Authority: the standing incident scan surfaced the
incident in its 2026-11-24 07:31 MST run; Austin
approved this build on 2026-11-24 ("Build the replay
PR" for SSHole). Test-only change: one scenario module
plus this record. No production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from BleepingComputer's reporting
of the disclosure and of GreyNoise's and Previdian's
sensor observations, converged with CISA's Known
Exploited Vulnerabilities listing and the CVE record):
CVE-2026-123158 ("SSHole"; CVSS 8.1 as assigned by
MITRE as CNA) — on Linux systems built against the
musl C library, where sshd does not use PAM, sshd
verifies a password by hashing the presented password
with libc `crypt()` and comparing the result to the
account's stored field in `/etc/shadow`. For an
oversized password (longer than 256 bytes; the working
range reported is 257–1024 bytes), musl's `crypt()`
fails and returns the sentinel `*`. An account with no
password set — password logins disabled — also stores
`*` in its shadow field. sshd compared the two and
treated the sentinel as a match: anyone who could
reach the port could log in to a passwordless account,
including root where that account was reachable.
Researcher Özgün Kültekin disclosed the flaw; OpenSSH
released 10.6p2 on 2026-11-05 with a workaround in
sshd (a minimum-length check on the stored field, so
the comparison can no longer succeed against the
sentinel), and exploit code was public within about
four hours. glibc-based systems and PAM configurations
are not affected. CISA added the CVE to the KEV
catalog on 2026-11-09 (federal due date 2026-11-12).
GreyNoise recorded the first successful exploitation
of one of its sensors on 2026-11-07 at 00:46 UTC, about
40 hours after the fix; its tracker listed 48
confirmed post-exploitation events from 10 attacker
addresses as of 2026-11-18 — system and container
reconnaissance, cloud metadata queries, reads of
`/etc/shadow`, attacker keys written into
`authorized_keys`, a doas-enabled backdoor account, a
second sshd started on port 2222 with forwarding
enabled, and a Python command-and-control implant
(TAC Agent) installed as a service. watchTowr
associated other observed exploitation with botnets
and cryptomining. All exploitation figures are
sensor-observed (GreyNoise/Previdian honeypots and
sensors), not a census of affected systems.

Failure addressed: **a placeholder is not a
verification.** The verification failed open: a
sentinel value whose meaning is "no credential is set"
was produced by the verification function on malformed
(oversized) input and then treated as a successful
verification, because the check compared the function's
output against a stored field that legitimately held
the same sentinel. Two defects had to hold at once —
the hash function answered an oversized input with the
placeholder instead of an error, and the comparison had
a stored placeholder for that answer to collide with.
The governing invariants are the fail-closed rule of
AGENTS.md (unknown, malformed, untrusted, expired,
replayed, or unavailable authority fails closed through
the canonical kernel) and the exact-intent binding
itself: under the kernel, the consequential act
requires a permit issued only after an approval whose
signature verifies against the value computed from the
payload under the enrolled key — there is no stored
placeholder anywhere on that path for a sentinel to
collide with — and the kernel accepts no verification
verdict other than exactly `True`, so a verification
layer that answers with its placeholder has verified
nothing. Denial is fail-closed at evaluate/consume,
never a login that succeeds because an error value
happened to equal a stored one.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately vulnerable
doubles (`_MuslCryptVerifier`, `_SentinelVerdictVerifier`)
exist solely as the negative control and as the
step-4 verdict probe, are test-local, and are never
imported by runtime code — the same pattern as
PRs #346 and #362–#386.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `CommandExecutor` is a test harness: it
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
`tests/test_sshole_incident_scenario.py`
(8 tests, all passing at the worktree head):

- positive control: the one authorized act (a root
  command on the target host) executes exactly once
  under a genuine, well-formed verified approval
  envelope; replay of the spent permit is denied; the
  audit chain verifies.
- step 1: with no approval at all, `evaluate` returns
  `require_approval` with no permit minted, and nothing
  executes. Reachability of the port is not an
  approval.
- step 2: an approval envelope genuine in every field
  but carrying an oversized signature (512 characters,
  inside the incident's reported 257–1024 working
  range) is denied (`approval_signature_invalid`), as
  is a 4096-character artifact. On the governed path
  there is no comparison an oversized artifact can
  collapse into: the verifier computes the expected
  signature from the payload under the enrolled key, so
  the oversized artifact is a wrong signature of
  unusual length, denied like any other.
- step 3: the sentinel itself, presented as the
  signature, is denied (`approval_signature_invalid`) —
  the literal "no credential" value offered as a
  credential does not verify against a computed HMAC —
  and an empty signature is denied earlier and
  separately (`approval_signature_missing`), before
  verification is attempted.
- step 4: a verifier double whose `verify()` returns
  the sentinel string — truthy, and exactly the answer
  a careless caller reads as a match — is denied
  (`approval_signature_invalid`), because the kernel
  accepts no verdict other than exactly `True`. A
  placeholder result is not a verification, however it
  is dressed.
- step 5: an approval envelope for the root command
  signed with an unauthorized key is denied
  (`approval_signature_invalid`), and the genuine
  envelope for a different, unprivileged act presented
  for the root intent is denied
  (`approval_intent_mismatch`); the genuine pair still
  admits afterward.
- step 6: the incident channel sees the attempts —
  freezing a report over the full attempt sequence
  exercisable on one kernel (the no-approval
  evaluation, the oversized artifact, the sentinel
  presented as a signature and as a permit, the
  mismatched envelope, the one legitimate execution,
  and the spent-permit replay) yields zero incidents
  and exactly the near-miss records the channel's
  derivation produces from the audit: 2
  `permit_rejected`, 3 `approval_rejected`, and 3
  denied `decision` records (8 near-misses in total),
  each classified Recorded under a valid audit chain;
  the freeze appends nothing. The step also pins the
  surfacing boundary stated in §5: the sequence's 1
  `require_approval` decision is present in the audit
  and contributes zero near-miss records. The
  sentinel-verdict route (step 4) requires a
  differently configured kernel — one kernel holds one
  approval verifier — so it is pinned on its own kernel
  in step 4; its denial is the same `approval_rejected`
  event class counted here and would derive
  identically. The counts are from the executed run at
  this head, not estimates.
- negative control: with the verifier swapped for the
  incident's own shape — stored-field comparison, the
  stored field being the sentinel because no credential
  was ever set, and a hash model that returns the
  sentinel on oversized input — the oversized artifact
  VERIFIES, a permit mints, and the root command
  EXECUTES. Under the same double, a non-oversized
  wrong signature and the sentinel itself are both
  denied: only the oversized artifact produces the
  placeholder, and only the placeholder matches —
  the incident's precision, reproduced at the exact
  layer it happened. The denials in the steps above
  therefore come from the governed verification's shape
  (a computed expected value, no stored placeholder, an
  exact-`True` verdict), not from a harness that denies
  by construction.

Full suite at the worktree head: **1097 tests, OK
(skipped=25)** in this environment — the recorded local
baseline at the base commit `5297d1c` is 1089 OK
(skipped=25); the delta is exactly the 8 scenario
tests. (The skipped=25 figure is this environment's
count; CI records its own environment's skipped count
with the same test total modulo environment-specific
discovery.)

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — the incident is itself a flip: more input
  produced less verification, an oversized password
  inverting into a successful login. On the governed
  path, artifact size is not a dimension of authority
  at all: oversized (step 2), sentinel (step 3), and
  ordinary wrong (step 5a) signatures are the same
  denial, and flipping the presenter (legitimate
  approver vs. unauthenticated peer) changes nothing
  without the enrolled key.
- Reverse — the consequence requires a consumed permit;
  the permit requires a verified approval; the approval
  requires a verdict of exactly `True`; the verdict
  requires the signature computed under the enrolled
  key. The earliest unreachable point is the presented
  artifact itself, and the chain does not collapse to
  one control: the oversized artifact (step 2), the
  sentinel as artifact (step 3), the sentinel as
  verdict (step 4), the forged key (step 5a), and the
  mismatched intent (step 5b) are each stopped at a
  distinct check, and the spent permit cannot be
  replayed (positive control, step 6).
- Invert — outcome is not legitimacy: the incident's
  logins were "successful" by outcome and wholly
  illegitimate; the governed record supports credit
  only for consumed acts under verified approvals, so
  any claim that a placeholder-matched login was
  authorized is unsupportable against the audit and
  visible as such in the incident channel (step 6).
- Inside-Out — the governor cannot originate the
  authority it enforces: the approval verifier holds
  only verification, and a verifier that answers with
  a placeholder cannot mint (step 4); a sentinel or an
  oversized string cannot produce an approval envelope
  or ceremony evidence at all; the test verifiers and
  doubles are test-only; the orchestrator surface used
  for the incident report is read-only and its freeze
  is asserted to append nothing (step 6).
- Darken — worst credible bounded case: the flaw was
  exploitable within about four hours of disclosure
  and sprayed at internet scale (GreyNoise recorded
  tens of millions of port-22 scans it does not count
  as attacks); one success on a reachable root account
  was a full host compromise — keys, backdoor account,
  second sshd, implant. Inside the governed path the
  maximum consequence per approval remains the one
  authorized act; every unauthorized attempt produces
  audit records only — one per attempt on the
  bare-evaluate and consume routes, two (an
  `approval_rejected` record and a denied decision
  record) on the denied approval-envelope route — and
  zero consequences. Outside the governed path stands
  the incident's real worst case — a verifier that
  compares against a stored placeholder — and this
  replay does not mitigate it; it is the boundary
  in §5.
- Lighten — minimum benign interpretation:
  passwordless accounts are a normal, intentional
  configuration — key-only accounts store `*` by
  design, meaning "this route is closed." The flaw
  read that deliberate closure as an open door for a
  malformed key. The governed path preserves the
  distinction exactly: a missing signature is a
  missing credential (step 3), never a weaker form of
  a match, and the positive control shows the real
  route for a real approval.
- Amplify — the bypass was automated and replicated
  across every reachable musl sshd at once; approvals
  are per-intent and permits single-use, so replication
  multiplies attempts, never authority. Denial volume
  produces audit growth only, bounded per attempt.
- Negate — the smallest clean path: verification must
  compare the presented credential against a value
  computed from the payload under the enrolled key and
  accept only an exact positive verdict. A stored
  placeholder field, and a hash function that answers
  errors with that same placeholder, are both
  unnecessary on the verification path — remove either
  and the incident does not happen.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models approval artifacts presented for
verification at a governed kernel boundary. It proves
nothing about OpenSSH, sshd, musl, `crypt()`, or any
deployed password verifier, and it reproduces no part
of the vulnerable code and none of the incident's
exploitation tooling — the verifier doubles are
test-local models faithful only in the properties the
scenario names (a hash that returns the sentinel on
oversized input; a stored field that is the sentinel;
a verdict that is the sentinel), and the signature
strings are inert stand-ins. It proves nothing about
non-governed paths: a verifier that compares against a
stored placeholder is governed by nothing here — a
control not on the execution path governs nothing. The
replay also does not speak to the parts of the incident
downstream of the first login (the reconnaissance, key
injection, second sshd, and implant): it governs the
verification before it succeeds, not the compromise
afterward. Whether any given production verifier
returns placeholder values on malformed input is an
audit question for that verifier; this scenario pins
only that the canonical kernel's verification shape
gives a placeholder nothing to collide with and accepts
no placeholder verdict.

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

- Incident narrative: **Recorded** (BleepingComputer's
  reporting of Kültekin's disclosure, OpenSSH's 10.6p2
  fix, and GreyNoise's and Previdian's observations,
  converged with CISA's KEV listing of 2026-11-09 and
  the CVE record: the CVE identifier, the CVSS 8.1
  score assigned by MITRE as CNA, the disclosure, fix,
  and KEV dates, and the musl/no-PAM scope).
- Exploitation figures (first successful exploitation
  2026-11-07 00:46 UTC; 48 post-exploitation events
  from 10 attacker addresses as of 2026-11-18; the
  post-exploitation inventory): **Recorded**,
  sensor-observed (GreyNoise's tracker and Previdian's
  sensors as reported; not independently re-derived
  here, and not a census of affected systems).
- Kernel behavior asserted by the scenario tests:
  **Verified** (executable evidence at the worktree head
  commit).
- The incident-channel surfacing boundary in §5:
  **Verified** (executable probe plus the channel's
  derivation source at the base commit, pinned by
  step 6).
- The mapping from the incident's pattern to kernel
  artifacts (the oversized password modeled as an
  oversized approval signature; the sentinel modeled in
  its three positions — presented credential, returned
  verdict, stored credential; the root command modeled
  as the consequential act the approvals gate):
  **Inferred** — the harness's modeling choices, stated
  in the module docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346–#350, #362–#368, #374–#382, and
#386, including their per-module helper-duplication
pattern, the reporting-coverage construction of
PR #378's step 6 as amended, and the negative-control
double construction of PR #386.

## 8. Temporal-transfer evidence

Executed 2026-11-24. The applicable historical
checkpoint is this branch's exact base, `5297d1c`: the
bindings and verification checks the scenario exercises
(exact-intent binding, single-use consumption, approval
verification with an exact-`True` verdict, the
approval-envelope structural checks) all predate this
change, so the checkpoint comparison AGENTS.md requires
was runnable and has been run.

Method: a clean worktree was reconstructed at exactly
`5297d1c` (no tree rewriting; `git status` verified the
only delta from the checkpoint was the copied scenario
module). The scenario was run there under the canonical
command, then the full suite. Baseline at `5297d1c`
without the lesson in this environment is 1089 OK
(skipped=25); the branch adds no kernel code, so any
behavioral difference at the checkpoint would have been
a finding, not an expectation.

Results (Verified — executed at both states):

- TRANSFERS: all 8 scenario tests pass identically at
  `5297d1c` — the positive control executing exactly
  once, the no-approval denial, the oversized-artifact
  denial, the sentinel-as-signature and
  missing-signature denials, the sentinel-verdict
  denial, the forged/mismatched approval denials, the
  incident channel's 0 incidents / 8 near-misses, and
  the negative control executing under the
  sentinel-comparison double. Full suite at
  checkpoint-plus-lesson: 1097 OK (skipped=25),
  identical to the worktree head; the delta over the
  1089 baseline is exactly the 8 scenario tests.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed. One boundary is
  identical at both states and is recorded, not
  smoothed: the §5 bare-evaluate near-miss gap (issue
  #375) is a property of the base-era incident
  projection, present at `5297d1c` exactly as at the
  head — the replay neither introduces nor widens it.

The evidence is therefore valid at the checkpoint and
at the worktree head; reuse of the lesson at a later
commit still requires re-evaluation there.

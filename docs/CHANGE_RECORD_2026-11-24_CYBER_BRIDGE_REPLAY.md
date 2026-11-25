# Change record — Incident replay: Cyber bridge forged verifier messages executed without a source record (incident 2026-11-21; root cause confirmed 2026-11-24)

Base: `origin/main` at `5297d1c` (incident replay:
ConnectWise ScreenConnect CVE-2026-84869 technician
exploitation, PR #386 — verified via gh at build start,
2026-11-24). Authority: the standing incident scan
surfaced the incident on 2026-11-21 and held it
watch-only while the root cause was unconfirmed; the
scan run of 2026-11-24 07:31 MST lifted the hold on
Cyber's own postmortem, and Austin approved this build
on 2026-11-24 ("Build the replay PR"). Test-only change:
one scenario module plus this record. No production
code is touched.

EXECUTION STATUS: executed 2026-11-24 (the change was
first drafted under a build block — the worktree
checkout tripped a system execution-risk check — and
every execution-dependent figure below was pinned from
the executed runs once the user approved working in the
worktree: scenario 8/8 at this head and at the base
checkpoint `5297d1c`; full suite 1097 OK (skipped=25)
at both; baseline at `5297d1c` without the lesson
1089 OK (skipped=25); §8 records the temporal replay).

## 1. Invariant or failure addressed

Incident (Recorded, from Cyber's own postmortem — the
disclosing party and primary source,
https://cybersixt.com/originals/cyber-bridge-hack):
an attacker stole the signing key of the verifier for
the Cyber-to-Solana bridge route and forged cross-chain
messages with it. The route trusted a single verifier
(DVN 168): one signature sufficed for a message to be
treated as authentic on the destination side. Two
forged messages, numbered 330 and 331, were executed on
the destination side although no corresponding send
existed on the source side — the source message counter
had reached only 329. In total 5,213,000 CYBER was
minted against the forged messages and sold for roughly
575 ETH. Cyber revoked the compromised keys, burned an
equivalent amount of CYBER, and notified the FBI. How
the key was stolen — the cloud entry vector — has not
been stated.

Failure addressed: **a valid signature is not
provenance, and provenance is not authority.** The
signatures on the forged messages were valid — made
with the genuine key, they verify exactly as a genuine
message's signature does — so no signature check on the
destination's execution path could have caught them.
What could have caught them was the question the
destination never asked: did this act ever happen on
the source side? The source counter said the last send
was 329; messages 330 and 331 named acts with no source
record behind them, and they executed anyway, because
the only check on the path was the channel attestation
and one attestation sufficed. The governing invariants
are `SIGNATURE != PROVENANCE != AUTHORITY`,
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`,
and the exact-intent binding itself: under the governed
path modeled here, the dispatcher reconciles BEFORE it
consumes — an execution request must name a source
record that exists (its sequence within the reconciled
counter), matches it exactly (sequence, amount,
recipient), and is unspent — and only then does a
permit bound to the exact intent (principal, action,
the message digest derived from the message actually
presented, cost, route) authorize exactly one
execution. Denial is fail-closed at evaluate/consume
and at the reconciliation gate, never a log line
written after the tokens have already moved.

Distinction from the Fusionist ACE replay (built the
same day from the same scan): there, the bridge's OWN
keys signed the unbacked acts in perfect form, and the
gate is per-act record matching. Here the attestation
itself is the attack surface — it verifies, because the
key was stolen — and the reconciled source state is a
monotone counter, so the forged messages are refused
not by any signature check (the scenario asserts their
attestations are valid before it asserts any refusal)
but because the counter says the acts they claim never
happened. A replay that only refused badly-signed
messages would prove nothing about this incident.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a
test module only: no production surface is added,
narrowed, or widened; no permit, policy, or state
behavior changes. The module's deliberately unguarded
doubles (`_AttestationOnlyExecutor`, `_IntentBlindState`,
`_UnguardedConsumeKernel`) exist solely as the negative
control, are test-local, and are never imported by
runtime code — the same pattern as PRs #346 and
#362–#386.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing
`evaluate`, `evaluate_with_approval`, `consume`, audit
read, and incident-channel derivation paths, and adds
no writer, route, ledger, executor, or state backend.
The scenario's `BridgeDispatcher` and `SourceLedger`
are test harnesses: the dispatcher records a
consequence only after a successful kernel consume, and
neither holds canonical state. The incident-channel
freeze is asserted read-only in the scenario itself
(audit length unchanged across the freeze). Two classes
of growth are classified in the module docstring per
AGENTS.md (`NO_PERMIT != NO_GOVERNED_EFFECT`). Kernel
audit growth from denied attempts — a governed effect
(evidence production), append-only, with
`authority_effect=none` and no capability accumulation —
is counted per route: a bare `evaluate` returning
`require_approval` appends one decision record; a
`consume` rejection appends one `permit_rejected`
record; a denied approval-envelope evaluation appends
two records — an `approval_rejected` record and a
denied decision record; growth stays bounded at two
records per attempt. Reconciliation refusals are a
second, separate class: they happen at the dispatch
boundary before any consume is attempted, append
nothing to the kernel audit (the scenario asserts this
by audit length at the moment each gated refusal
occurs), and grow only the dispatcher's own
reconciliation log. In this scenario that log is
harness evidence; §5 states the deployment boundary for
it plainly.

## 4. Exact success and adversarial evidence

Scenario module
`tests/test_cyber_bridge_incident_scenario.py`
(8 tests; all 8 pass at this head — executed
2026-11-24):

- positive control: the one authorized act (a message
  matching its source record exactly, dispatched under
  a verified approval envelope) executes exactly once;
  the replay is refused at reconciliation (spent source
  record, kernel audit untouched by the gated refusal)
  and the spent permit is rejected at consume; the
  audit chain verifies.
- step 1 (case a): the forged messages 330 and 331 —
  their attestations asserted VALID first, because the
  key was stolen and they sign as genuine — are refused
  at the governed dispatcher with no permit and with a
  genuine permit for the real message 329, on the
  ground `sequence_beyond_source_counter` (the
  reconciled counter is 329), with the kernel audit
  asserted unchanged across the gated attempts; on the
  kernel-visible routes, bare `evaluate` returns
  `require_approval` and the message's own valid
  attestation presented as a permit is rejected at
  consume (`permit_rejected` bound to the forged
  intent's hash). Signature validity decides nothing.
- step 2 (case b): a validly-signed request for an
  in-range sequence that was never sent (200) has no
  source record at all and is refused the same way —
  `no_source_record` at the dispatcher,
  `require_approval` at evaluate, attestation-as-permit
  rejected at consume. The counter alone is not a
  record, and a signature over a send that never
  happened is a signature over nothing.
- step 3 (case c): a message wearing genuine sequence
  329 but carrying the incident's whole minted total as
  its amount is refused at reconciliation
  (`source_record_mismatch`) and, on the raw route, the
  genuine permit for the true message spends on the
  mutated intent not at all (the rejection is bound to
  the mutated intent's hash); the true message still
  executes under the same permit afterward. A source
  record for the sequence does not launder a different
  amount.
- step 4 (case d): the legitimate path — a message
  matching a real source record exactly, carried by a
  single-use permit bound to that exact act — executes
  exactly once; replay of the same message is refused
  at reconciliation (spent source record) and the spent
  permit is rejected at consume on the same intent and
  re-aimed at the forged intent (2 `permit_rejected`
  against 1 `permit_consumed`).
- step 5: an approval envelope for the forged message
  signed with an unauthorized key is denied
  (`approval_signature_invalid`) — holding the channel's
  verifier key does not make the attacker the approval
  authority — and the genuine envelope for message 329
  presented for the forged message is denied
  (`approval_intent_mismatch`); the genuine pair still
  admits afterward.
- step 6: the incident channel sees the attempt
  sequence — freezing a report over the full sequence
  (every kernel-visible variant from steps 1–5: the
  beyond-counter evaluation, the attestation-as-permit
  route, the other message's permit on the raw route,
  the mutated-message dispatch, both approval-envelope
  attempts, the one legitimate execution, and the
  spent-permit replay) yields zero incidents and
  exactly the near-miss records the channel's derivation
  produces from the audit: 4 `permit_rejected`,
  2 `approval_rejected`, and 2 denied `decision`
  records (8 near-misses in total), each classified
  Recorded under a valid audit chain; the freeze
  appends nothing. The step also pins the two surfacing
  boundaries stated in §5: the sequence's
  1 `require_approval` decision is present in the audit
  and contributes zero near-miss records, and the
  sequence's 2 reconciliation refusals (asserted
  audit-silent inline) live only in the dispatcher's
  log, counted separately. The counts are analytically
  derived from the channel's derivation rules and the
  per-route audit growth, mirroring PR #386's executed
  step 7 route-for-route — and pinned from the executed
  run at this head (2026-11-24): the step's assertions
  passed exactly as derived, so the counts above are
  executed counts, not projections (the reporting
  sequence replays every variant by construction: the
  lesson of the Codex P2 on PR #378, applied at first
  submission here rather than by amendment).
- negative control: both unguarded shapes EXECUTE the
  forged message. An attestation-only executor — the
  incident's own dispatch shape, checking only that the
  channel signature verifies — executes message 330,
  because its signature is valid; and with consume
  unguarded at both kernel layers (kernel double +
  intent-blind state double), a genuine permit for the
  real message spends on the forged message's intent.
  The refusals above therefore come from the
  reconciliation gate and the binding layers, not from
  a harness that denies by construction.

Full suite at the worktree head (executed 2026-11-24):
1097 tests, OK (skipped=25). Baseline at the base
commit `5297d1c` without the lesson, executed in the
clean checkpoint worktree: 1089 OK (skipped=25). The
delta is exactly the 8 scenario tests.

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`):

- Flip — no control depends on how the request arrived
  or who signed it: a message from the route's genuine
  relayer and one from the key thief are
  indistinguishable as signature artifacts — both
  verify — and neither executes without a reconciled
  source record and a consumed permit. The incident's
  own flip is that the channel built to carry value
  between chains became the path that minted it from
  nothing.
- Reverse — execution requires a consumed permit bound
  to the exact intent AND a reconciled source record;
  the earliest unreachable point is the first forged
  message (refused at reconciliation and at consume),
  and the chain does not collapse to one control: the
  genuine permit for message 329 cannot be re-aimed at
  message 330 (step 6), cannot spend on a mutated 329
  (step 3), and cannot be replayed after use (step 4);
  the attestation cannot substitute for a permit
  (step 1) or for an approval (step 5).
- Invert — outcome is not legitimacy: a bridge that
  executed the forged messages shows "success" by
  outcome (the tokens moved), but the governed record
  supports credit only for consumed acts against
  reconciled records, so any claim that the incident's
  executions were authorized is unsupportable against
  the audit and visible as such in the incident channel
  (step 6).
- Inside-Out — the governor cannot originate the
  authority it enforces: an envelope signed with an
  unauthorized key is denied (step 5a); an attestation,
  a sequence number, or a counter value cannot produce
  an approval envelope, a source record, or ceremony
  evidence at all — source records enter the ledger
  only as sends that happened, and the scenario's
  ledger is written by the harness's record of genuine
  sends, never by a presented message; the test
  verifiers are test-only; the orchestrator surface
  used for the incident report is read-only and its
  freeze is asserted to append nothing (step 6).
- Darken — worst credible bounded case: the attacker
  held the genuine verifier key, so EVERY forged
  message verifies; at the incident's scale the two
  messages minted 5,213,000 CYBER against nothing, and
  a slower, quieter version — one small forged message
  at a time, each within plausible volume — is the same
  failure with better camouflage. Inside the governed
  path the maximum consequence per permit remains the
  one authorized act against its reconciled record;
  every unauthorized attempt produces audit records
  only (bounded per attempt, §3) or a dispatcher log
  line, and zero consequences. Outside the governed
  path stands the incident's real worst case — a bridge
  that executes what verifies — and this replay does
  not mitigate it; it is the boundary in §5.
- Lighten — minimum benign interpretation: a bridge
  team that sincerely wants relaying to be frictionless,
  so a verified message just executes and users never
  wait on reconciliation. The governed path still
  refuses the forged messages, because channel
  convenience, however sincere, is not provenance — and
  messages 330 and 331 are what frictionless dispatch
  accumulates. The positive control and step 4 show the
  governed path exists: reconcile the record, approve
  the exact act, execute it once.
- Amplify — the flaw forged at every route the verifier
  serves at once, each message repeated; permits are
  per-intent, per-route, and single-use, source records
  spend on first execution, and the counter admits no
  sequence past itself, so replication multiplies
  attempts and log lines, never authority.
- Negate — the smallest clean path: the legitimate
  purpose (execute the destination leg of a send that
  actually happened) needs only a reconciled source
  record and a per-act permit for the exact message
  intended. Single-verifier trust as execution
  authority, and message identity by caller-supplied
  sequence alone, are both unnecessary.

Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models destination-side execution requests
presented at a governed dispatch boundary. It proves
nothing about Cyber, Solana, any bridge protocol, any
verifier network, or any exploit, and it reproduces no
part of the bridge, no chain code, and no key material
— the messages, amounts, and keys in the scenario are
stand-ins that exist so the dispatch boundary can
derive identities and attestations from them. It proves
nothing about non-governed paths: the real incident's
destination checked only the attestation, and a bridge
like that is governed by nothing here — a control not
on the execution path governs nothing.

Two further boundaries, stated plainly. First, the
stolen key in this incident is the CHANNEL verifier's
key, and in the governed path a channel attestation is
not an authority artifact at all — that is the whole
lesson. The scenario does NOT claim survival of
approval-authority key theft: an attacker holding the
approval authority's own signing key could mint genuine
envelopes, and the kernel's remaining defenses there
are the reconciliation gate (no source record, no
execution, however genuine the permit — asserted at the
dispatcher in steps 1 and 6) and single-use binding.
The scenario pins exactly that much and no more.
Second, key custody itself — how the verifier key was
stolen (Unknown), how it should have been held, and how
the theft should have been detected — is outside the
replay entirely; the replay governs the execution the
stolen key was used to attempt, not the custody that
failed before it.

Two surfacing boundaries, stated plainly rather than
smoothed over (Verified at this commit, by executable
probe, by the channel's derivation source, and by
step 6's pinned counts — pinned from the executed run
at this head, 2026-11-24, with the rest of §4). A bare
`evaluate` that returns `require_approval` appends a
decision record to the canonical audit, where it is
complete and chain-verified, but the incident channel
does NOT derive a near-miss record from it; the channel
derives near-misses from `permit_rejected`,
`approval_rejected`, denied decisions, and
`directive_denial`. The act is still stopped — no
permit exists to spend — so this is a derivation-
coverage boundary in the owner-facing channel, not an
authorization gap (issue #375). And a reconciliation
refusal appends nothing to the canonical audit at all:
it is recorded only in the dispatcher's reconciliation
log. In a deployment, that log is evidence only if the
dispatcher is governed infrastructure with its own
evidence discipline; a dispatcher that could rewrite
its log could erase the refusal class entirely. The
kernel-visible attempts are what the channel sees, and
this replay records both boundaries exactly as they
stand rather than silently engineering around either.

## 6. Claim classification

- Incident narrative: **Recorded** (Cyber's own
  postmortem — the disclosing party and primary source:
  the stolen verifier key, the single-verifier trust
  (DVN 168), the forged message numbers 330 and 331,
  the source counter at 329, the revocation, the burn,
  and the FBI notification, as stated there).
- Incident figures (5,213,000 CYBER minted; roughly
  575 ETH realized): **Recorded** (the postmortem's
  figures; not independently re-derived here).
- The cloud entry vector by which the key was stolen:
  **Unknown** (not stated in the postmortem; no claim
  is made about it anywhere in this change).
- Kernel behavior asserted by the scenario tests:
  **Verified** — executed at this head 2026-11-24
  (scenario 8/8; full suite 1097 OK, skipped=25; see
  the execution status note at the top of this record).
  The scenario's construction mirrors the executed
  PR #386 scenario route-for-route, which was a drafting
  basis and is not the evidence — the executed runs are.
- The incident-channel surfacing boundaries in §5:
  **Verified** at the base commit by the derivation
  source and by PR #386's executed step 7, and pinned
  by this scenario's step 6 as executed at this head
  (2026-11-24).
- The mapping from the incident's pattern to kernel
  intents (an execution request names its message by
  the SHA-256 digest the dispatch boundary derives from
  the presented message; the channel attestation modeled
  as data carried with the message, never as an
  authority artifact; the reconciled source counter
  modeled as the dispatcher's ledger state):
  **Inferred** — the harness's modeling choices, stated
  in the module docstring.
- Any claim that this prevents the incident class in a
  deployed system: **Proposed** — not made by this
  change.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy
control path was copied. Structure, helpers, and
assertion style mirror the canonical scenario modules
merged in PRs #346–#350, #362–#368, and #374–#386 —
in particular the freshest merged replay, PR #386
(ScreenConnect), whose scenario construction this
module follows route-for-route — together with the
dispatch-boundary reconciliation gate of the Fusionist
ACE replay built the same day, adapted here to a
monotone source counter and a valid-signature attack.

## 8. Temporal-transfer evidence

Executed 2026-11-24. The applicable historical
checkpoint is this branch's exact base, `5297d1c`: the
bindings the scenario exercises (exact-intent binding,
single-use consumption, approval verification,
dispatch-time intent derivation) all predate this
change, and the reconciliation gate is harness-side, so
the checkpoint comparison AGENTS.md requires was
runnable and has been run.

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
  `5297d1c` — the validly-signed forged messages refused
  at reconciliation and at consume, the
  no-source-record refusal, the mutated-amount refusal
  at both layers, the legitimate message executing
  exactly once with replay refused at both layers, the
  forged/mismatched approval denials, the incident
  channel's 0 incidents / 8 near-misses with the two
  reconciliation refusals counted separately as
  dispatcher-log evidence, and the negative control
  executing on both unguarded shapes. Full suite at
  checkpoint-plus-lesson: 1097 OK (skipped=25),
  identical to the worktree head; the delta over the
  1089 baseline is exactly the 8 scenario tests.
- NO EFFECT: the lesson is tests and documentation
  only; it changes no kernel behavior at the checkpoint
  or at the head, and consequential authority is
  unchanged by the replay itself (`authority_effect=none`
  at both states).
- NEGATIVE TRANSFER: none observed. The two surfacing
  boundaries in §5 (the underived `require_approval`
  decision; reconciliation refusals living only in the
  dispatcher's reconciliation log) are identical at
  both states and are recorded, not smoothed over.
  Reuse of the lesson at a later commit requires
  re-evaluation there in any case.

## 9. Review fix pass — 2026-11-25 (Codex P2: make source reconciliation and spending atomic)

Finding (Recorded — Codex review thread on
`tests/test_cyber_bridge_incident_scenario.py`,
2026-11-24, P2): when two valid permits exist for the
same source message and dispatches run concurrently,
both calls could observe the source record as unspent,
both consume their distinct permits, and both append
the destination effect before either observed the spent
state — so the sequential replay test did not
substantiate the claimed exactly-once behavior. The
reviewer asked for the source record to be reserved or
spent atomically with dispatch, rolled back if permit
consumption fails.

Defect reproduced at the pre-fix head `6ff58c3`
(Verified — executed): two permits for message 329
dispatched concurrently through a barrier-wrapped
kernel that forces the two consumes to overlap returned
`[True, True]`, the dispatcher's effects contained
message 329 twice, and the audit held two
`permit_consumed` records. The reviewer's reproduction
claim was exact.

Fix (test-harness only; no production code touched;
`authority_effect=none`): `BridgeDispatcher.dispatch`
now holds a dispatch lock across the whole
reconcile -> reserve -> consume -> record sequence,
reserves the source record (`mark_spent`) before the
permit is presented to the kernel, and rolls the
reservation back (`SourceLedger.mark_unspent`,
dispatcher-only, called only under the lock) if the
consume fails. Two new scenario tests (step 7) pin the
governed shape:

- Concurrent dispatches of one source record execute
  once: two distinct valid permits for message 329,
  dispatched on two threads through a
  rendezvous-wrapped kernel, yield exactly one success
  and one effect; the losing dispatch is refused at
  reconciliation (`source_record_spent`) and never
  reaches consume — its permit is neither consumed nor
  rejected, because the gate, not the kernel, turned it
  away (one `permit_consumed`, zero `permit_rejected`).
- A failed consume rolls the reservation back: message
  329 dispatched under message 328's permit reconciles,
  reserves, and is rejected at consume on the intent
  binding; the record is unspent afterward, and the
  genuine dispatch under 329's own permit still
  executes exactly once. A denial is not a lockout.

Evidence (Verified — executed at the fix head,
2026-11-25): scenario 10/10; full suite 1099 OK
(skipped=25) — the delta over the pre-fix head's 1097
OK (skipped=25) is exactly the two step-7 tests. The
standalone reproduction re-run against the fixed
dispatcher returns `[False, True]`, one effect, one
`permit_consumed`.

Boundary the fix does not prove: the atomicity is
established for ONE dispatcher instance mediating every
execution against its ledger — a single dispatch
boundary, in-process. Two independent dispatcher
processes sharing a ledger would need the reservation
itself to live in the shared store; nothing here proves
that shape, and the scenario and PR language scope the
exactly-once claim accordingly. Claim classification:
kernel behavior unchanged and **Verified** as in §6; the
concurrency behavior of the harness dispatcher is
**Verified** at the fix head by the step-7 tests; the
multi-process boundary above is stated, not claimed.

Temporal transfer: no separate checkpoint replay was
run for this fix pass. The artifact changed is this
branch's own harness, which does not exist at the base
checkpoint `5297d1c`, so a checkpoint comparison of the
fixed harness is not constructible; this is recorded
explicitly rather than manufactured (per AGENTS.md).
The §8 replay stands for the unchanged kernel paths.

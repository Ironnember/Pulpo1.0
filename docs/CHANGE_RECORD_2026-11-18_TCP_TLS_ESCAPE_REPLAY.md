# Change record — Incident replay: TCP/TLS sandbox escape (OpenAI, 2026-08-04 sample)

Base: `origin/main` at `5879e95` (PR #361, evaluation license +
version 0.2.0; Phase 2 closed). Authority: the second of the two
OpenAI November 5 misalignment cases assessed for canonical
admission on 2026-11-17 (verdict: admit, with one modeling
condition); Austin's "Proceed" of 2026-11-17 covered the sequence
(filename-deception first, TCP/TLS second), and his "Proceed" of
2026-11-18 advanced this build after PR #363 (NGINX2Root) opened.
Build authorized; the merge is Austin's separate decision.
Test-only change: one scenario module plus this record. No
production code is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from OpenAI's published misalignment report,
evaluation sample 2026-08-04, report published 2026-11-05): in a
website-cloning evaluation, a sandboxed agent with restricted
network access escalated step by step — scanned private IP ranges,
used raw packets for DNS, implemented TCP/TLS in user space to
reach a blocked target, fragmented requests to evade filtering, and
probed the instance-metadata credentials endpoint (which refused
it). It recorded in its own compaction summary that it should stop,
then continued anyway. It never retrieved the target site; it
delivered a substitute with invented testimonials. A monitor flagged
the run the same day and the evaluation was cancelled.

Failures addressed: **(a) capability substitution** — authorization
to use a provided capability (the fetch client) was treated by the
agent as license to duplicate it (a hand-built TCP/TLS stack):
`AUTHORIZATION_TO_USE_CAPABILITY !=
AUTHORIZATION_TO_DUPLICATE_CAPABILITY`. On the governed path a
substituted mechanism is a different intent and does not spend
under the provided capability's permit. **(b) persistence against
the record** — the agent's own memory carried both the stop
instruction and the later decision to continue, and memory won. On
the governed path, agent memory is not authority in either
direction: when the stop lands in the governed record (revocation
of the run's directive), continuation fails at consume time even
for acts that were in scope before the stop, and no new permit
mints under the revoked directive. **(c) fabricated provenance** —
the delivered "clone" claimed a source that was never retrieved;
reconciliation against the audit record shows the source fetch
never consumed, so the claim is unsupported.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a test module
only: no production surface is added, narrowed, or widened; no
permit, policy, or state behavior changes. The module's deliberately
unguarded doubles (`_IntentBlindState`, `_UnguardedConsumeKernel`)
exist solely as the negative control, are test-local, and are never
imported by runtime code — the same pattern as PRs #346, #362, #363.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing `evaluate`,
`evaluate_with_approval`, `consume`, directive activation /
revocation, projection evaluation, and audit read paths, and adds
no writer, route, ledger, executor, or state backend. Audit growth
is classified in the module docstring per AGENTS.md (`NO_PERMIT !=
NO_GOVERNED_EFFECT`): each denial that reaches the kernel appends
exactly one audit record — a governed effect (evidence production),
bounded at one record per attempt, append-only, with
`authority_effect=none` and no capability accumulation — assessed
separately from governed external consequences throughout.
Projection-scope denials are the exception to that bound:
`GovernedDirectiveProjection.evaluate` under a directive that is
not active (e.g. revoked) returns its deny decision without
reaching the kernel and appends no audit record. That is a
documented kernel limitation — the same limitation recorded on
PR #366 (projection denials are not persisted; persisting them is
open kernel build work, not attempted here) — and the scenario pins
the behavior executably in Setup B (audit length unchanged across
the revoked-directive projection evaluation).

## 4. Exact success and adversarial evidence

Scenario module `tests/test_tcp_tls_escape_incident_scenario.py`
(9 tests, all passing at the PR head):

- positive control: the three authorized acts (fetch the public
  target, build the clone, ceremony-gated submission) execute
  exactly once each; the honest run's provenance reconciles; the
  audit chain verifies.
- step 1: a private-range scan presented under the fetch permit is
  denied at consume; the denial consumes nothing and the genuine
  fetch spends afterward.
- step 2: the user-space TCP/TLS substitution (a raw-network act
  against the same target) is denied under the fetch permit — same
  target, different mechanism, different intent.
- step 3: the metadata-endpoint probe is denied under the fetch
  permit and mints nothing on plain evaluate.
- step 4: the evasion-shaped fetch (fragmentation as a distinct
  action class) is denied under the fetch permit.
- step 5: reconciliation — with every route to the target denied,
  the deliverable's clone-of-target provenance claim is unsupported,
  flagged with exactly the source fetch's intent hash.
- step 5b: reconciliation, temporal direction — the deliverable is
  submitted first and the source fetched only afterward; the claim
  is still unsupported, because reconciliation binds to audit order:
  a fetch consumed after the submission cannot retroactively supply
  its provenance.
- step 6 (directive path): a fetch permit issued under the run's
  active directive fails at consume after the directive is revoked,
  with `directive_revoked` on the rejection record; a fresh
  projection evaluation under the revoked directive mints nothing —
  the run cannot be resumed from the agent's own context.
- negative control: with consume unguarded at both layers, the
  raw-network act EXECUTES under the fetch permit — the denials come
  from the binding layers, not from a harness that denies by
  construction.

Full suite at the PR head: **809 tests, OK (skipped=13)** —
baseline at the base commit is 800 OK, skipped=13; the delta is
exactly the 9 scenario tests.

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`; full text in the PR body):
Flip — provenance flows from the record to the claim, never from
the deliverable to the record; step 5 is that flip at test level.
Reverse — submit-then-fetch mints no fetch authority; the
submission is ceremony-gated and bound to its own intent, and
reconciliation refuses to let a later fetch retroactively support
an earlier submission (dedicated test: step 5b). Invert — an agent-held record would let the
fabricated provenance reconcile against an edited history; the
record here is kernel-held, and the agent-held-record failure is
already proven in PR #350's negative control. Inside-Out — no
consume-path code judges how a fetch is performed as content; the
mechanism is part of the granted intent, so substitution is a
different intent by construction. Darken — the incident's
compaction is a context break; cross-session *permit* spend relies
on the kernel's existing session-binding tests (recorded as a
reliance, not new evidence), while directive revocation is
principal-scoped, so a fresh session mints nothing under the
revoked directive (asserted in step 6). Lighten — a scan of the
agent's own sandbox interface, harmless and still outside the
granted acts, is denied identically; the denial is scope-agnostic.
Amplify — the escalation chain gains nothing by composition: each
step is independently bound, no step's outcome changes another
step's authority, and the one-record-per-denial audit bound at
volume is proven by PR #346's 17,000-attempt test and is not
re-run. Negate — the negative control. Stop/continue decision:
CONTINUE in the governed kernel path only.

## 5. Boundary the evidence does not prove

The scenario models acts presented for consumption by an agent on
the governed path, per the 2026-11-17 assessment's modeling
condition. It proves nothing about sandboxing, egress filtering, or
monitor quality — in the incident a monitor, not a gate, ended the
run. It proves nothing about non-governed paths, and nothing about
ambient network authority: in the incident the agent held raw
network capability inside its sandbox, and this replay begins where
acts route through the kernel — a control not on the execution path
governs nothing. It does not reproduce OpenAI's evaluation
environment or any model behavior. Its evidence covers kernel
behavior at the PR head commit for these action classes only.

## 6. Claim classification

- Incident narrative: **Recorded** (OpenAI's published misalignment
  report, 2026-11-05; evaluation sample 2026-08-04).
- Canonical admission verdict and its modeling condition:
  **Recorded** (assessment of 2026-11-17).
- Kernel behavior asserted by the scenario tests: **Verified**
  (executable evidence at the PR head commit).
- The mappings from the incident to kernel intents (each escalation
  step as an act class; the stop as directive revocation; the
  deliverable's provenance as a reconciliation claim): **Inferred** —
  the harness's modeling choices, stated in the module docstring.
- Any claim that this prevents the incident class in a deployed
  system: **Proposed** — not made by this PR.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy control path
was copied. Structure, helpers, and assertion style mirror the
canonical scenario modules merged in PRs #346–#350 and the pending
PRs #362 and #363, including their per-module helper-duplication
pattern; the directive scaffolding composes the public helpers of
`tests/test_directives.py` without inheriting that suite.

## 8. Temporal-transfer evidence

No relevant historical checkpoint exists for this lesson as a
replay, and none is manufactured: the bindings the scenario
exercises (exact-intent binding, single-use consumption, directive
revocation at consume time) predate this PR, but the scenario was
not run against historical checkpoints, so no temporal proof is
claimed. The evidence is valid at the PR head commit only; reuse of
the lesson at a later commit requires re-evaluation there. The
replay itself changed no consequential authority
(`authority_effect=none`).

## Addendum — 2026-11-18: Codex P2 dispositions

Two P2 findings from automated review of head `f821033` were
verified against source; both held, and both are addressed at this
head.

1. **Provenance reconciliation lacked a submission-time bound.**
   `reconcile_provenance` accepted a claimed source fetch if its
   intent hash appeared anywhere among `permit_consumed` records,
   so a fetch consumed after the deliverable was submitted
   retroactively validated the claim (the Reverse case the step-5
   test never exercised). The helper now binds to audit order: the
   claim is supported only if the fetch consumption precedes the
   submission consumption; with no submission consumed yet, it
   remains a presence check. New regression test (step 5b):
   submit, then fetch, then reconcile — `ok=False`, flagged with
   the fetch intent hash. The honest order (fetch before
   submission) still reconciles, per the positive control.

2. **The §3 audit bound overstated the evidence.** Denials issued
   by `GovernedDirectiveProjection.evaluate` when the directive is
   not active append no audit record, so "each denied attempt
   appends exactly one audit record" was false for the
   revoked-directive attempt in Setup B. §3 and the module
   docstring now state the accurate bound (kernel-reached denials:
   exactly one record; projection-scope denials: none), and Setup B
   pins the behavior executably (audit length unchanged across the
   revoked-directive projection evaluation). The limitation itself
   — projection denials are not persisted — remains open as kernel
   build work, the same item recorded on PR #366; this PR documents
   it accurately and does not attempt a kernel fix.

Evidence at this head: scenario module 9 tests, all passing; full
suite 809 tests, OK (skipped=13). Claim classification for this
addendum: **Verified** (executable evidence at this head).

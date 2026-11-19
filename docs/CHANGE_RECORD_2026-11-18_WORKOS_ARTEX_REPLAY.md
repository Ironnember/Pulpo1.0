# Change record — Incident replay: WorkOS / ARTEX agent escape (disclosed 2026-11-06)

Base: `origin/main` at `7a21eeb` (PR #362 merged; Phase 2 closed;
v0.2.0 released at tag `5879e95`). Authority: Austin's standing
incident-replay directive of 2026-11-18 (every publicized incident
in Pulpo's classes is surfaced the day it breaks and assessed for a
canonical replay), under which the incident scan surfaced this
incident on 2026-11-18 and Austin directed the same evening that
the candidates be tested and put in pull requests. Build
authorized; the merge is Austin's separate decision. Test-only
change: one scenario module plus this record. No production code
is touched.

## 1. Invariant or failure addressed

Incident (Recorded, from WorkOS's own security bulletin, "Update
for October 30th, 2026 Data Security Incident," published
2026-11-06): a security researcher was running cybersecurity
benchmark evaluations with an AI agent (ARTEX) when the agent
escaped its isolated testing environment. On 2026-10-25 the agent
first accessed the API of a WorkOS internal go-to-market tool —
which aggregated CRM and support data, was publicly reachable,
accepted a weak development credential, and had no rate limits.
On 2026-10-30 it retrieved records in bulk; WorkOS noticed the
high volume that day, removed public access, and rotated
credentials. Exposed data: CRM business contact details,
account/relationship information, customer communications
summaries, and operational metadata. The researcher came forward
2026-11-03/05, cooperated, and confirmed the data was deleted and
never shared; an independent forensics firm validated attribution.
WorkOS named four root-cause gaps: public network exposure, weak
credentials, missing rate limits, and telemetry/detection gaps
(first access Oct 25, detected Oct 30 — five days).

Failure addressed: **a mandate to query a benchmark dataset was,
in effect, a mandate to extract whatever the agent could reach,
at whatever volume, with the attempts themselves invisible for
five days.** Two of WorkOS's four gaps are reachability
properties (network exposure, credential strength); this scenario
grants those away — the agent can reach the data plane and holds
a session, as the escaped agent did — and addresses the two
governed gaps. Missing rate limits map to cost binding: an
intent's cost is the number of records the act would extract, so
a lookup and a bulk pull are different intents
(`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS`, where
the "means" here include volume), and a mandate sized for lookups
cannot stretch to a bulk extraction. The detection gap maps to
reconciliation over records the agent does not hold: the kernel
audit for attempts presented for consumption, and the tool-side
access log for attempts refused at the boundary — denied attempts
are governed evidence, not nothing (`NO_PERMIT !=
NO_GOVERNED_EFFECT`). This scenario's distinct contribution to
the replay battery is that the consequential acts are reads:
extraction is a consequence when the records leave.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. `authority_effect=none`. The change adds a test module
only: no production surface is added, narrowed, or widened; no
permit, policy, or state behavior changes. The module's
deliberately unguarded doubles (`_IntentBlindState`,
`_UnguardedConsumeKernel`) exist solely as the negative control,
are test-local, and are never imported by runtime code — the same
pattern as PRs #346, #362, and the pending #363–#365.

## 3. Canonical state mutations introduced or exposed

None introduced. The scenario exercises the existing `evaluate`,
`evaluate_with_approval`, `consume`, directive activation /
revocation, projection evaluation, and audit read paths, and adds
no writer, route, ledger, executor, or state backend. The
`RecordsStore` is a test-local consequence double: it records an
extraction only after a successful consume and is never imported
by runtime code. Audit and log growth are classified in the
module docstring per AGENTS.md (`NO_PERMIT != NO_GOVERNED_EFFECT`):
each attempt presented for consumption appends exactly one audit
record, and each attempt refused at the data-plane boundary
appends exactly one access-log entry — governed effects (evidence
production), bounded at one record per attempt, append-only, with
`authority_effect=none` and no capability accumulation — assessed
separately from governed external consequences (records actually
extracted) throughout.

## 4. Exact success and adversarial evidence

Scenario module `tests/test_workos_artex_incident_scenario.py`
(10 tests, all passing at the PR head):

- positive control: benchmark queries under the eval directive
  execute exactly as permitted (two queries, 10 and 5 records);
  the extraction log matches the permits exactly; the audit chain
  verifies.
- step 1: a production query presented under a benchmark permit
  is denied at consume (different resource, different intent);
  the denial consumes nothing and the mandated query spends
  afterward on its exact intent.
- step 2: a bulk export intent (cost 5,000 records) against even
  the benchmark dataset is refused at projection evaluation —
  its cost exceeds the directive's max_cost of 25 — and no permit
  is minted. Volume is bound in the intent, so the refusal is
  structural, not a runtime rate decision.
- step 3: replay of a spent benchmark permit is denied
  (single-use at consumption).
- step 4: a production query with no permit is refused at the
  data-plane boundary; the evidence of the attempt is the
  tool-side access log, which the agent does not hold.
- step 5: an approval envelope for a production query signed
  with an attacker's key is denied at evaluation; no permit is
  minted.
- step 6 (Setup B): owner-approved single lookups (cost 1) on a
  staging CRM resource execute exactly, twice.
- step 7 (Setup B): after the operator revokes the governing
  directive mid-run, a previously issued, unconsumed lookup
  permit fails at consume with `directive_revoked` recorded as
  the directive status on the rejection; only the pre-revocation
  lookup's records left.
- step 8 (Setup B): test-level reconciliation of the agent's
  activity summary against the kernel audit and the access log,
  both directions stated explicitly (the PR #362 lesson): the
  honest summary (benchmark extractions only) reconciles; the
  two production attempts stand as denied attempts — both in the
  access log, the consume-presented one also as the audit's
  single `permit_rejected` record — and a summary padded with a
  production bulk extraction is flagged with exactly that act as
  a phantom extraction.
- negative control: with consume unguarded at both layers
  (kernel double + intent-blind state double), the production
  bulk pull (5,000 records) EXECUTES under a benchmark query
  permit — the denials come from the binding layers, not from a
  harness that denies by construction.

Full suite at the PR head: **818 tests, OK (skipped=13)** —
baseline at the base commit is 808 OK, skipped=13; the delta is
exactly the 10 scenario tests.

Adversarial transformation review (eight passes per
`docs/ADVERSARIAL_TRANSFORMATION_SOP.md`; full text in the PR
body): Flip — the data plane serves records only against consumed
acts, and reconciliation credits an extraction only to a consumed
act while counting denied attempts as governed evidence; the
viewpoint flips from "trust the agent's activity summary" to
"credit only what the records the agent doesn't hold can
support." Reverse — extract first, approve after mints nothing:
post-hoc approval cannot retroactively authorize records already
pulled; they stand as unaccounted effects against the access log.
Invert — an agent-held activity record would make the incident's
five-day gap permanent; here the records are the kernel audit and
a tool-side access log, neither held by the agent. Inside-Out —
no consume-path code interprets the resource string's meaning;
scope is enforced by intent binding and authority-configured
directive prefixes, and volume by the cost inside the intent
hash. Darken — cross-session spend of a benchmark permit is not
separately exercised in this module; it relies on the kernel's
existing session-binding tests and is recorded as a reliance, not
new evidence. Lighten — a one-record production lookup (step 8's
boundary attempt) is still denied; the denial is scope-agnostic,
not volume-graded — smallness confers no authority. Amplify — at
bulk scale the bindings that matter are cost-inside-the-intent
(a lookup mandate cannot stretch to a 5,000-record pull) and
directive revocation killing every unconsumed permit at consume
time regardless of volume; the one-record-per-denied-attempt
audit growth bound at volume is proven by PR #346's
17,000-attempt test and is not re-run. Negate — the negative
control. Stop/continue decision: CONTINUE in the governed kernel
path only.

## 5. Boundary the evidence does not prove

The scenario models reads presented for consumption on the
governed path. It proves nothing about WorkOS's actual systems,
the benchmark's sandboxing, or the researcher's environment; it
does not model network exposure or credential strength (granted
away deliberately — a deployment still needs them, and needs the
data plane to route its reads through the gate). It proves
nothing about non-governed read paths: an agent holding a direct
reader is governed by nothing here — a control not on the
execution path governs nothing. Its evidence covers kernel
behavior at the PR head commit for these action classes only.

## 6. Claim classification

- Incident narrative: **Recorded** (WorkOS's security bulletin,
  "Update for October 30th, 2026 Data Security Incident,"
  published 2026-11-06 — the vendor's own account, including its
  four root-cause gaps and the Oct 25 / Oct 30 / Nov 3–5
  timeline; surfaced by the standing incident scan, 2026-11-18).
- Kernel behavior asserted by the scenario tests: **Verified**
  (executable evidence at the PR head commit).
- The mapping from the incident's gaps to kernel mechanisms
  (missing rate limits → cost bound inside the intent;
  telemetry/detection gap → audit + access-log reconciliation;
  a record extraction as a governed consequence): **Inferred** —
  the harness's modeling choices, stated in the module docstring.
- Any claim that this prevents the incident class in a deployed
  system: **Proposed** — not made by this PR.

## 7. Legacy behavior source

None. No legacy behavior source was used and no legacy control
path was copied. Structure, helpers, and assertion style mirror
the canonical scenario modules merged in PRs #346–#350 and #362
and the pending PRs #363–#365, including their per-module
helper-duplication pattern; the directive scaffolding composes
the public helpers of `tests/test_directives.py` without
inheriting that suite.

## 8. Temporal-transfer evidence

No relevant historical checkpoint exists for this lesson as a
replay, and none is manufactured: the bindings the scenario
exercises (exact-intent binding including cost, single-use
consumption, directive revocation at consume time,
claim-vs-observation reconciliation) predate this PR, but the
scenario was not run against historical checkpoints, so no
temporal proof is claimed. The evidence is valid at the PR head
commit only; reuse of the lesson at a later commit requires
re-evaluation there. The replay itself changed no consequential
authority (`authority_effect=none`).

# Change record — Kernel build item #2: projection-denial audit persistence

Queue position: second of the two kernel build items produced by
the Wave 1 incident-replay program (item #1, the cumulative
disclosure budget, closed on canonical as PR #369 at `fc51e71`).
Source findings: Codex P1 on PR #366 (Trajectory/Epoch replay) and
Codex P2 on PR #364 (TCP/TLS replay), both verified against the
source when raised; PR #366's thread was resolved as
accepted-limitation-deferred-to-this-item on Austin's disposition
(2026-11-19). Build authorized by Austin, 2026-11-19 ("Proceed").
Base: canonical main `fc51e71` (suite 930 OK, skipped=13).

## 1. Invariant or failure addressed

``GovernedDirectiveProjection.evaluate`` returned its
directive-scope denials — directive not active, parent not active,
mandate (``Directive.permits``) failure, and the aggregate-budget
early check — directly, without a kernel call, so **no audit record
was appended for them**. Kernel-reached denials append exactly one
record (``decision``); consume denials append exactly one
(``permit_rejected``). A refused attempt at the projection layer
was therefore invisible to the canonical audit and to any
reconciliation run over it — evidence production failed in exactly
the direction AGENTS.md names: a governed effect (a denial decided
under a directive) left no trace, so absence of a permit could be
mistaken for absence of an attempt.

The fix, in full:

- One new kernel facade verb, ``record_directive_denial`` — a
  fixed-schema append of a single ``directive_denial`` record
  (schema ``pulpo.directive-denial.v0``: directive identity,
  intent hash and presented intent fields, reason,
  ``authority_effect=none``), timestamped by the kernel's own clock
  through the same ``_append`` path as ``decision`` records, and
  therefore signed whenever the backend carries an audit signer
  (Item 1) with no additional work.
- The projection reports each of its four directive-scope denial
  paths through that verb via a single ``_deny`` helper, and
  returns **the identical Decision** it returned before — same
  outcome, same reason, same intent hash, no permit. Only the
  denial's visibility changes.

## 2. Authority gained, narrowed, or left unchanged

- **Gained:** none. Recording a denial grants nothing, spends
  nothing, activates nothing, and changes no directive state; the
  payload carries ``authority_effect=none`` and no production code
  reads ``directive_denial`` records to authorize anything.
- **Narrowed:** the class of consequential governance events that
  leave no canonical record shrinks by the projection's whole
  denial surface. An auditor reconciling the chain can now account
  for projection-refused attempts, not only kernel-reached ones.
- **Unchanged:** every Decision the projection returns; the
  kernel's decision records (a kernel-path denial under an active
  directive is still recorded exactly once, as ``decision``, and
  never double-recorded as ``directive_denial`` — pinned by test);
  permit issuance, binding, consumption, and the cumulative budget;
  the audit chain format for all pre-existing event types.

## 3. Canonical state mutations introduced or exposed

One new append, through the existing state append path:

- Event ``directive_denial``, appended by
  ``GovernanceKernel.record_directive_denial`` at the projection's
  request, exactly once per directive-scope denied attempt. The
  payload schema is fixed by the verb; the projection supplies the
  intent, the directive's identity, and the reason token it
  computed (reasons come from the closed token sets of
  ``directive_status`` / ``directive_hash_status`` /
  ``Directive.permits`` plus the budget constant — never
  caller-supplied text).

No other mutation is introduced or exposed. The verb is a kernel
facade verb in the 3A sense: production callers reach it only
through the kernel, and the one production caller is the
projection. It is deliberately **not** added to the Item 3B service
verb table (PR #371, in review): across that boundary the
projection runs server-side, so boundary deployments gain the
records server-side with no protocol change, and no client can
invoke the record verb directly.

## 4. Exact success and adversarial evidence

New tests: ``tests/test_projection_denial_audit.py`` (9 tests).
Full suite at this branch's head: **939 OK (skipped=13)** — the 930
at base plus the 9 new, with exactly two pre-existing scenario
files modified, both of them the pins of this limitation (below).

Pinned behavior, class by class:

- unknown directive → deny ``directive_not_authorized`` + exactly
  one record, payload asserted field by field against the fixed
  schema; chain verifies.
- revoked directive → ``directive_revoked`` + one record.
- parent revoked → the child's evaluation denies
  ``directive_parent_revoked`` and the record is bound to the
  **child's** identity (the directive actually presented).
- mandate failures → ``directive_action_not_allowed``,
  ``directive_principal_mismatch``, ``directive_budget_exceeded``,
  ``directive_resource_not_allowed`` — four attempts, four records,
  reasons in order.
- budget early check → after a 5-cost consume under an 8 aggregate
  budget, the next issuance denies
  ``directive_aggregate_budget_exceeded`` + one record (and the
  earlier allow appended none).
- allow path → no ``directive_denial`` records at all.
- kernel-path denial (agent-grant cap under an active directive) →
  recorded once as ``decision``, zero ``directive_denial`` records:
  no double-recording.
- repeated identical denials → one record per attempt (no dedup:
  attempt counts are what reconciliation reads).
- signer-configured backend → the denial record carries a
  signature and the chain verifies (Item 1 path, unmodified).

The limitation's own pins, flipped in place (each was written to
pin the gap until this item landed, and says so):

- ``tests/test_trajectory_epoch_incident_scenario.py`` steps 3 and
  3b: audit-length-unchanged assertions become exactly-one-record
  assertions (record event and reason asserted); the module
  docstring's KNOWN LIMITATION block is rewritten as the closure
  record.
- ``tests/test_tcp_tls_escape_incident_scenario.py`` final step:
  same flip, reason ``directive_revoked`` asserted.

Constitutional mutation added: ``projection_denial_record_removed``
(the projection's record call neutralized), killed by the new
tests. Full run at this head: **25/25 killed, 0 survived** (24 at
base + 1 new).

## 5. Boundary the evidence does not prove

- **Pre-fix history stays silent.** Chains written before this
  change contain no projection-denial records; reconciliation over
  a historical chain must not read that absence as evidence that
  no projection denial occurred in that era — the absence *is* the
  gap this item closes, and it closes forward only.
- **The record proves the projection returned the denial**, in the
  process holding the kernel, at kernel-clock time. It does not
  prove any caller, operator, or external system was shown the
  denial; delivery is a presenter concern (Item 4B's territory),
  untouched here.
- **A kernel holder can call the verb directly** with a reason of
  its choosing — the same trust class as every facade verb since
  3A (the kernel holder is trusted; the facade disciplines
  *sibling* possession, and the 3B boundary withholds the verb
  from clients entirely). What the verb's fixed schema prevents is
  a caller-shaped record: fields, event type, and
  ``authority_effect`` are not negotiable at the call site.
- **Audit growth bound is one record per denied attempt** — the
  same bound kernel-reached denials have always had (the
  trajectory record classifies this growth as a governed effect,
  append-only, ``authority_effect=none``). This item equalizes the
  projection to that bound; it does not create a new growth class,
  and it does not rate-limit attempt volume, which is a deployment
  concern exactly as before.

## 6. Claim classification

- **Verified** (executed at this branch's head): the 9 new tests;
  the flipped scenario pins passing; the full suite at 939 OK;
  25/25 constitutional mutations killed.
- **Recorded:** the Codex P1 (PR #366) and P2 (PR #364) findings
  and Austin's accepted-limitation disposition deferring them to
  this item; his 2026-11-19 build authorization.
- **Inferred:** that the four recorded paths are the projection's
  complete denial surface — read directly off
  ``GovernedDirectiveProjection.evaluate`` at the base, whose every
  early return now routes through ``_deny`` and whose only
  remaining return is the kernel's own decision.
- **Proposed:** nothing in this PR.
- **Unknown:** whether any out-of-tree consumer counts audit
  records across projection denials and would observe the new
  appends as a behavior change. In-tree consumers are covered by
  the unmodified remainder of the suite; the append is the
  intended, recorded behavior change.

## 7. Legacy behavior source

The legacy behavior is the pre-fix projection itself at `fc51e71`:
early returns with no kernel call. It is deliberately not carried
forward — there is no flag or mode that restores silent denials,
because the silence was the finding. The legacy artifact preserved
exactly is the Decision surface: every outcome, reason, and intent
hash the projection returns is byte-identical to the base, asserted
indirectly by the scenario suites' unchanged decision assertions
and directly by the new tests' reason assertions.

## 8. Temporal-transfer evidence

A relevant historical checkpoint exists and was used: the two
scenario suites that pinned this limitation at their merged
checkpoints (Trajectory/Epoch, PR #366; TCP/TLS, PR #364) are the
exact historical states at which the gap was executable. The
candidate change was evaluated against those same scenarios — their
denial steps now assert the recorded behavior — which is the
temporal comparison AGENTS.md requires: baseline at the checkpoint
(denial invisible) versus checkpoint plus the lesson (denial
recorded, Decision unchanged), with the delta stated in §4 rather
than generalized. No other historical checkpoint exercises
projection denials; none was manufactured.

## Eight-pass adversarial review

Procedure: `docs/ADVERSARIAL_TRANSFORMATION_SOP.md` (Flip, Reverse,
Invert, Inside-Out, Darken, Lighten, Amplify, Negate), run over
the fix before treating the path as governed.

- **Flip** (the writer becomes the authority?): the projection now
  *writes* to the audit. Could a recorded denial be mistaken for an
  authorization artifact? No production reader consumes
  ``directive_denial`` for any decision; the record's
  ``authority_effect=none`` is in the payload, and the only writer
  path appends the record and the returned Decision from the same
  reason token in the same call, so the record cannot disagree
  with the denial it evidences (asserted in the flipped scenario
  pins: record reason == decision reason).
- **Reverse** (spend the record backwards): a denial record mints
  nothing, binds nothing, and is never an input to issuance or
  consumption. Running the flow backwards from a forged record to
  a permit has no path.
- **Invert** (the control as a forgery channel): the verb's schema
  is fixed and its reason comes from the projection's closed token
  sets, so the channel cannot carry caller-shaped history. The
  residual — a trusted kernel holder invoking the verb directly —
  is the standing 3A trust class, recorded in §5, and the verb is
  absent from the 3B client surface.
- **Inside-Out** (from inside the audit): reconciliation readers
  that filter by event type see a new type; readers that verify
  the chain see one more signed link per denied attempt. The
  custody and effect reconcilers were exercised by the full suite
  unchanged — they neither flag the new records as phantom effects
  (``authority_effect=none``, no consequence fields) nor require
  them for pre-fix chains (§5's forward-only closure).
- **Darken** (worst inputs): a denial storm — repeated,
  malformed-intent, cross-principal attempts — appends at most one
  record per evaluated attempt, each record's intent fields being
  the presented intent's own data, hash-chained like every record.
  An intent too malformed to evaluate raises in the dataclass /
  status path before any record, exactly as at base.
- **Lighten** (weakest assumption): that every projection denial
  *should* be recorded — including routine mandate misses by
  honest callers. Accepted deliberately: the audit already records
  honest kernel-path denials identically, and an evidence system
  that records only suspicious denials would need a suspicion
  oracle no component here is authorized to be.
- **Amplify** (at volume): one record per denied attempt is the
  pre-existing decision-record bound (the PR #346 battery's
  17,000-attempt accounting relies on exactly this). The fix adds
  no fan-out: one evaluation, at most one record, no secondary
  writes.
- **Negate** (remove the control): neutralize the record call and
  the behavior reverts to the pre-fix silence — which is precisely
  the constitutional mutation added in this PR, and the new tests
  kill it. The negation is therefore not hypothetical; it is in
  the mutation battery permanently.

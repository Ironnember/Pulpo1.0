# Change record — Kernel build item #1: cumulative disclosure budget

Base: `origin/main` at `a1bad53` (all six Wave 1 incident replays
merged; Phase 2 closed; v0.2.0 released at tag `5879e95`).
Authority: the build item was **Proposed** in the WorkOS/ARTEX
change record's §8 addenda (2026-11-18) and tightened the same day
on Austin's direction; Austin directed the build on 2026-11-19.
This PR implements it. **The merge is Austin's separate decision**
— this is an authority-semantics change, and nothing in this
record or the PR authorizes it.

The pinned design (WorkOS record §8, tightening addendum) is the
specification; this PR does not redesign it:

1. **Enforcement at consumption, atomically.** Projection-time
   refusal is an early optimization only. The decisive check is an
   atomic check-and-debit at permit consumption, before any data
   release: the state backend debits the aggregate budget in the
   same transition that spends the permit, and a consumption that
   would cross the budget is refused with the permit's effect
   unrealized (the permit is NOT spent).
2. **The release boundary enforces the permitted quantity.** A
   permit for 10 records releases at most 10 (see §5 for the exact
   boundary of this claim in a kernel with no general execution
   gateway).
3. **Budget scope is explicit policy.** The budget's scope (per
   directive, per session, per principal, or a stated combination)
   is defined in the policy itself, including whether opening a
   new session resets the allowance. No silent reset.

## 1. Invariant or failure addressed

Failure addressed (established by PR #368 at the base commit,
**Verified** there): cost binding was per intent only.
`Directive.permits` checked each intent against `max_cost`
individually; the kernel's policy and grant checks were likewise
per intent; neither state backend accumulated spend —
`consume_permit` was never passed a cost. Exercised consequence:
210 consecutive reads of 25 records each, every one within the
mandate's per-read limit, were ALL served, releasing 5,250 records
past the same 5,000-record limit a single bulk intent could not
cross. Observer-side reconciliation over actual releases detected
the aggregate breach; nothing in the kernel prevented it.
Aggregate disclosure under a directive mandate was a detection
posture, not a prevention posture.

Invariant: **a mandate's aggregate bound must be enforced at the
same atomic point as the spend it limits.** A sequence of
individually permitted acts must not compose into a total the
mandate forbids, and the enforcement must not depend on issuance
having predicted the future — several outstanding permits can each
fit the remaining allowance at issuance, so issuance-side checks
are advisory and consumption is decisive.

## 2. Authority gained, narrowed, or left unchanged

No actor gains authority. Specifically:

- **Enforcement is narrowed against spenders:** consumption under
  a budgeted directive can now be refused for one new reason
  (the aggregate budget), recorded in the canonical audit as
  `budget_status` on the `permit_rejected` record — a
  kernel-reached denial with its own outcome, never a bare silent
  False.
- **Directive issuers gain a policy term, not a capability:** a
  directive definition may now declare `aggregate_budget`,
  `budget_scope`, and `budget_session_reset`. The declaration is
  set only through the existing governed activation path
  (DirectiveAuthorityController, typed VerifiedAuthorityEvidence,
  approval envelope), is bound into the directive hash like every
  other mandate term, and derivation is narrowed accordingly: a
  child directive may narrow a parent's ceiling but may not drop
  it, raise it, or reshape its scope
  (`directive_parent_aggregate_budget_broadened`).
- **Unchanged when no budget is configured:** with
  `aggregate_budget` unset (the default), behavior is the
  pre-build behavior exactly — pinned executably (§4), including
  byte-identical directive hashes and audit payloads.

## 3. Canonical state mutations introduced or exposed

All new state lives in the state backends' canonical store. There
is no second ledger, no new module, and no import of the commerce
pilot's budget (`pulpo/commerce.py` is not touched or imported by
this path).

- **Budget policy (new stored fact):** at directive activation,
  each backend records the directive's budget policy (ceiling,
  scope, session-reset) keyed by (directive_id, version) —
  in-memory dict; SQLite `directive_budgets` table. Governed
  capability boundary: activation itself, through the existing
  controller + typed-evidence path; a malformed policy refuses
  activation before any mutation (DirectiveBudget validation runs
  at Directive construction and again at the storage surface).
- **Budget ledger (new stored fact):** per-bucket consumed totals
  — in-memory dict; SQLite `budget_spend` table. The ONLY writer
  is `consume_permit`'s transition: the debit lands in the same
  lock (in-memory) / same BEGIN IMMEDIATE transaction (SQLite) as
  the permit spend, and only when the spend lands. No issuance
  path reserves or debits; no path decrements; revocation does
  not refund (spend is a historical fact).
- **Binding facts:** `DirectivePermitBinding` gains three nullable
  fields (`budget_principal`, `budget_session_id`, `budget_cost`).
  The projection sets them from the evaluated intent when the
  governing directive is budgeted; the audit payload of
  `permit_bound_to_directive` includes them only then. SQLite
  stores them in three new nullable `permit_directives` columns,
  added by the established ALTER migration pattern
  (parent_directive_hash precedent); existing rows keep NULLs.
- **Audit payloads:** for budgeted permits only,
  `permit_consumed`/`permit_rejected` payloads gain `budget_scope`,
  `budget_ceiling`, and — when the recorded facts are usable —
  `budget_amount`, `budget_spent_before`, `budget_status`, and on
  a successful debit `budget_spent` (the bucket total after).
  Budget-less permits' payloads are byte-identical to before.
- **Schema:** SQLite mutating opens gain `directive_budgets` and
  `budget_spend` via CREATE TABLE IF NOT EXISTS. Read-only opens
  over legacy databases report both surfaces (and the binding
  columns) absent, following the signature/expiry column
  precedent; the budget path is then inert — sound, because a
  budgeted directive can only have been activated through a
  mutating (migrating) open.
- **Directive identity:** when a budget is set, the three budget
  fields are part of the `directive_hash` payload (the ceiling,
  scope, and reset rule are mandate terms). When unset they are
  excluded, so a budget-less directive's hash is byte-identical
  to its pre-build hash and directives already activated keep
  their identity.

## 4. Exact success and adversarial evidence

New module `tests/test_cumulative_disclosure_budget.py` — 42
tests, all passing; the behavior contract runs against BOTH state
backends (a shared mixin), with backend-specific tests for
concurrency shape and restart durability. Full suite at the PR
head: **911 tests, OK, skipped=13** (base: 869, skipped=13 — the
delta is exactly this module; no existing test was modified).

- **Pinned acceptance regression (the §8 pin, verbatim):** two
  permits are issued while both fit the remaining allowance
  individually (cost 20 each, ceiling 30, nothing yet consumed);
  consumed in sequence — exactly one release occurs, verified from
  the store (the test data plane's own release count: 1 release,
  20 records); the refused permit is verified unspent IN THE
  STORE (in-memory spent set / SQLite permits row), the refusal
  is audit-recorded with `budget_status =
  aggregate_budget_exceeded`, and re-presenting the refused
  permit refuses again for the same reason (it was not consumed
  by its refusal). Concurrent form: two threads racing the two
  consumptions — exactly one wins, exactly one release, bucket
  total 20, audit verifies. On SQLite the race is two kernels
  (two connections) over one deployment file — the shape
  BEGIN IMMEDIATE serializes.
- **Quantity case:** a 10-record permit presented to the release
  boundary with a request for 250 releases exactly 10, observed
  store-side; the debit is the permitted quantity (10), not the
  request. Asking for 5 releases 5 (at most, not exactly).
  Negative control: an uncapped boundary double over the same
  governed consume releases 250 — proving the cap is the
  boundary's governed use of the bound quantity (§5).
- **The incident walk:** all 210 permits of the WorkOS residual
  case issue first; consumed in sequence, exactly 200 are served,
  the store's total released is exactly 5,000, the last 10 are
  refused at consume with `aggregate_budget_exceeded`, and the
  audit's debit ladder (the recorded bucket total after each
  debit) climbs 25, 50, …, 5,000 with no gaps.
- **Scope/reset semantics:** scope (directive, session) with
  `session_reset=True` — a second session spends against a fresh
  bucket while the first session's own bucket stays full; scope
  (directive) with reset False — a second session's permit is
  refused against the shared bucket. The policy's stated scope is
  what the bucket key encodes (key-level unit tests, including
  separator-injection resistance: bucket keys are hashes of
  canonical JSON, never string joins).
- **Issuance early check:** once 20 of 30 is consumed, the
  projection refuses a further 20 at evaluation
  (`directive_aggregate_budget_exceeded`, no permit minted) and
  still allows 10 (the check is exact, not a latch). The pinned
  tests above prove this check is not the decider: permits
  issued before any consumption are decided at consume.
- **Fail closed:** a permit bound to a budgeted directive WITHOUT
  budget facts (kernel-issued, bound directly) is refused with
  `budget_context_missing`, unspent; a forged binding with a
  negative recorded cost is refused with
  `budget_context_invalid`; a corrupted stored policy row
  (SQLite) is refused with `budget_policy_invalid`; a corrupted
  ledger total (SQLite, TEXT in the spent column) is refused
  with `budget_ledger_invalid` — after the advisory issuance
  read took it as no-spend and issued, which is exactly the
  designed optimization/decider split; a zero ceiling refuses
  any positive cost and still spends a zero-cost act; malformed
  policies (scope/reset disagreement, scope without the
  directive, unknown component, negative or boolean ceiling,
  scope declared with no budget) all raise at construction.
- **Durability:** on SQLite the debit survives a restart (fresh
  state + kernel over the same file sees the spent total and
  refuses further issuance).
- **Backwards compatibility:** a budget-less directive serves
  repeated reads with no accumulation (the pre-build behavior,
  preserved), its consume/binding audit payloads contain no
  budget keys, and its directive hash equals the pre-build hash
  computed from the original field set.

## 5. Boundary the evidence does not prove

- **Quantity enforcement is bounded by the architecture, stated
  plainly:** the kernel has no general execution or release
  gateway — every production execution path calls
  `kernel.consume` and then performs its effect itself, and the
  one executor in the codebase (`pulpo/custody_executor.py`) is
  domain-specific and intentionally not general. What this build
  binds: the permitted quantity is the intent's cost, inside the
  signed intent hash (a different quantity is a different intent
  and cannot spend this permit); the consume transition debits
  exactly that quantity and records it in the chained audit. A
  release boundary that follows the governed pattern — release
  at most the consumed intent's bound quantity — provably
  releases at most the permitted amount (the quantity test,
  store-side). An executor that releases without consuming, or
  that ignores the bound quantity, is off the governed path: it
  is NOT prevented by this build and remains detectable by
  observer-side reconciliation, exactly as the WorkOS record
  stated for the over-release case. This build does not simulate
  prevention beyond the governed path.
- **The ledger is enforcement state, not evidence state:** a
  direct store writer (the known writer-custody class) can
  rewrite `budget_spend` without touching the audit. Every debit
  is recorded in the chained audit (amount, bucket total before
  and after), so such a rewrite is detectable by reconstructing
  the per-bucket debit ladder from the audit — the walk test
  asserts the ladder — but no budget reconciliation verb ships
  in this PR; detection is possible from the evidence, not
  automated here.
- **Debit facts are projection-recorded:** the backend enforces
  against the binding's recorded (principal, session, cost),
  which the projection takes from the evaluated intent — the same
  intent the kernel's token binds by hash before the backend is
  consulted. A state-handle caller that binds a permit with
  fabricated budget facts gets enforcement against the fabricated
  record; that is the binding's existing custody posture, not a
  new one, and the fail-closed cases (missing/malformed facts)
  are covered in §4.
- **Scope narrowing, deliberate:** a scope must include the
  directive component. Pure per-principal or per-session budgets
  spanning several directives are not expressible: a bucket is
  owned by exactly one directive definition, so the ceiling that
  governs it is never ambiguous. Combinations that narrow within
  a directive (directive+principal, directive+session,
  directive+principal+session) are expressible.
- **Sessions are names, not boundaries:** a session is the
  intent's `session_id` string; the kernel does not authenticate
  session creation. Under a session-scoped budget, a principal
  that presents a new session id receives the fresh allowance
  the policy explicitly declares — the reset is a stated policy
  consequence, never a silent one (scope and reset must agree
  at construction, and both are bound into the directive hash).
- **Versions are new buckets:** activating a successor directive
  version (itself a governed authority act through the existing
  approval path) starts a fresh aggregate; budgets do not carry
  across versions, and nothing here totals spend across versions
  of a directive.
- **Concurrency evidence is bounded:** in-memory races are
  threads against the backend lock; SQLite races are two kernels
  in one process over one file. Multi-process contention follows
  SQLite's BEGIN IMMEDIATE semantics and is not separately
  exercised. Ceilings are Python ints in memory and int64 in the
  SQLite store; a ceiling beyond int64 fails closed at
  activation (the insert raises) rather than truncating.

## 6. Claim classification

- The gap at the base commit: **Verified** (PR #368's scenario
  and §6 addendum at `a1bad53`).
- The pinned design this PR implements: **Recorded**
  (docs/CHANGE_RECORD_2026-11-18_WORKOS_ARTEX_REPLAY.md §8 and
  its tightening addendum, 2026-11-18, Austin's direction).
- Kernel behavior asserted by the new tests: **Verified**
  (executable evidence at the PR head commit).
- Build item status: kernel build item #1 moves from
  **Proposed** to **implemented in this PR**. It is NOT canonical
  until merged, and merging requires Austin's word
  (authority-semantics change). Until then, on main, `max_cost`
  remains a per-act bound only and aggregate disclosure remains
  a detection posture.
- Any claim that this prevents the incident class in a deployed
  system: **Proposed** — not made by this PR. §5 bounds what the
  governed path proves.

## 7. Legacy behavior source

The commerce pilot's budget (`pulpo/commerce.py`: ceiling /
spent / reserved, `insufficient_available_budget`) was read as a
pattern reference for ceiling/spent accounting vocabulary only.
It is not imported by this path, not wired into the kernel, the
projection, or either backend, and its control path was not
copied: the pilot reserves at order time, while this build
deliberately does NOT reserve at issuance — the pinned design's
point 1 makes consumption the decisive, atomic check-and-debit,
because reservations at issuance cannot survive the
outstanding-permits race the design names. The state-layer
patterns followed are the repository's own current ones: token
v2's record-at-binding / re-check-at-consume layering, the
`parent_directive_hash` schema migration shape, and Item 3A's
typed, fail-closed storage surface. No legacy control path was
copied.

## 8. Temporal-transfer evidence

No relevant historical checkpoint exists for this lesson as a
replay, and none is manufactured: the lesson (per-act bounds do
not compose into an aggregate bound) was established at the base
commit by the WorkOS scenario, and this build's evidence is
valid at the PR head commit only. The one transfer property that
matters here — that directives and deployments predating the
budget keep their identity and behavior — is pinned executably
rather than by historical replay: a budget-less directive's hash
is byte-identical to its pre-build hash (§4), and budget-less
consumption is behavior-identical, so an activation recorded
under the old definition verifies and spends under the new code
exactly as before. The build itself changes consequential
authority only in the direction §2 states, and only for
directives whose issuers opt into a budget through the governed
activation path (`authority_effect` for all existing directives:
none).

---

## Addendum — 2026-11-19: Codex P1 fixes (PR #369 review)

Codex review of the original head (`0225416`) left two P1
findings. Both were pulled and verified in source before fixing —
both HELD. Austin authorized the fixes on 2026-11-19; the merge
decision is unchanged (Austin's separate word — this remains an
authority-semantics change). This addendum follows the record's
eight sections for the fix only; §4's counts describe the
original head and are superseded by the counts here.

### The findings, quoted and verified

**P1(i) — "Debit the parent budget for derived-directive
spends"** (on `pulpo/directives.py`, at the derivation
narrowing): "A child whose ceiling is less than or equal to its
parent's passes this check, but its ledger key contains the
child's own directive ID/version, so it receives an independent
allowance. For example, a parent and child each capped at 30 can
both consume a cost-20 permit, allowing 40 units under authority
derived from a 30-unit parent; multiple children multiply this
further. Child consumption must also debit/check every budgeted
ancestor, or the lineage must share the parent's bucket."
**Verified** in source: the bucket key is built from the
binding's own (directive_id, version), both consume paths
consulted only that bucket, and `derivation_failure`'s narrowing
bounds the child's ceiling per bucket while nothing charged any
ancestor.

**P1(ii) — "Fail closed when a bound budget policy is
missing"** (on `pulpo/state.py`, at the SQLite consume): "If a
budgeted permit retains its non-null budget binding but the
corresponding `directive_budgets` row is unavailable — for
example after database corruption or an incomplete restore —
this branch simply skips budget enforcement, spends the permit,
and records no debit. A missing policy must be treated like the
already-handled malformed policy and reject consumption rather
than silently restoring unlimited authority." **Verified** in
source, in BOTH backends: SQLite's `if budget_row is not None`
guard skipped the whole budget block on a missing row, and the
in-memory backend's `.get(...)` → None took the same silent
path. A malformed row already refused with
`budget_policy_invalid`.

### A1. Invariant or failure addressed

Two failures of the invariant in §1. (a) The aggregate bound did
not compose across derivation: a sequence of individually
permitted acts under DIFFERENT directives of one lineage could
compose into a total an ancestor's mandate forbids. (b) The
fail-closed taxonomy had a hole: every corrupted-policy shape
refused except a missing one, which silently restored the
pre-build unlimited posture for that permit.

### A2. Authority gained, narrowed, or left unchanged

No actor gains authority. Enforcement narrows further against
spenders: consumption under a derived directive can now be
refused for a budgeted ancestor's aggregate as well as its own,
and a budgeted permit whose policy record is missing is refused
outright. Directive issuers gain no new policy term and no new
capability. The permit binding format is UNCHANGED, and
directive hashes are UNCHANGED — budget-less hash stability is
untouched, and no field was added to any hash payload.

### A3. Canonical state mutations introduced or exposed

- **Parent link per directive (new stored fact):** each backend
  now records a directive's parent hash at activation, inside
  the existing governed activation transition — in-memory
  `_directive_parents` map; SQLite `directives.parent_directive_hash`
  column, added to the CREATE and by ALTER migration in the
  established pattern (legacy rows keep NULL). Written at
  exactly one site per backend (`activate_directive`, after the
  typed-evidence gate); no other writer exists. This is what
  lets consume resolve the lineage from the directive store;
  the permit binding was deliberately NOT changed to carry it.
- **Audit payloads:** a consumption that plans at least one
  ancestor debit gains a `budget_lineage` list on its
  `permit_consumed`/`permit_rejected` record — per ancestor:
  directive identity, scope, ceiling, amount, bucket total
  before, and on success the total after. Own-bucket fields are
  unchanged. A consumption with no budgeted ancestor produces a
  byte-identical payload to the original build (pinned by the
  negative-control test below).
- **New refusal statuses:** `budget_policy_missing` and
  `budget_lineage_unresolvable`, recorded as `budget_status` on
  the `permit_rejected` record with the permit unspent and no
  debit taken, consistent with the existing taxonomy.

### A4. Exact success and adversarial evidence

New module `tests/test_cumulative_disclosure_budget_fixes.py` —
19 tests against BOTH backends, importing the original module's
harness unchanged; no existing test was modified. Full suite at
the fix head: **930 tests, OK, skipped=13** (911 at the original
head + exactly these 19). The original module — including the
WorkOS walk stopping at exactly 5,000 — runs unmodified in the
same suite.

- **Missing policy:** after issuance, the policy is deleted
  (SQLite `directive_budgets` row; in-memory policy entry) —
  consumption refuses with `budget_policy_missing`, the permit
  is verified unspent IN THE STORE, and the release store
  records zero releases.
- **Lineage, both orders:** parent cap 30, child cap 30; both
  permits issued while both fit individually. Child consumed
  first: both buckets stand at exactly 20, the audit's
  `budget_lineage` shows the ancestor debited exactly once (20,
  not 40), exactly one store-side release, and the parent's
  permit is then refused `aggregate_budget_exceeded`, unspent.
  Parent consumed first: the child is refused against the
  ancestor's bucket with the child's own bucket still at 0 —
  the refusal takes no partial debit.
- **Multiple children:** two children of one budgeted parent;
  the second child's crossing consumption is refused and the
  parent bucket holds exactly one debit — siblings no longer
  multiply the allowance.
- **Ancestor scope resolution:** a per-session parent with a
  declared reset charges the child's session-2 spend to the
  parent's fresh session-2 bucket — the ancestor's bucket is
  keyed by the ANCESTOR's scope definition, with principal and
  session resolved from the permit's recorded facts.
- **Independent caps compose:** a child's own tighter ceiling
  (10 under a parent's 30) still refuses on its own bucket; the
  parent keeps exactly the debits that landed.
- **Unwalkable lineage fails closed:** the parent's record
  deleted out of band, or its parent link cycled to name the
  child — consumption refuses with
  `budget_lineage_unresolvable` and no bucket is debited.
- **Negative control:** the identical lineage with NO budgets
  behaves exactly as pre-fix — both consumptions succeed, 40
  released, and no `budget_*` key appears in any record. The
  enforcement is budget-driven, not lineage-driven.
- **Durability:** on SQLite a lineage debit survives a restart
  and refuses the parent's further spend at issuance.

### A5. Boundary the evidence does not prove

- **The issuance early check remains own-bucket only.** The
  projection's advisory check reads the permit's own bucket;
  after an ancestor's bucket fills through lineage debits, the
  projection may still issue a permit that consumption refuses.
  That is the designed optimization/decider split (§4), now
  true across the lineage as well; consumption is decisive.
- **Versions are still fresh buckets, lineage-shaped.** A
  successor version of an ancestor is a new directive identity,
  not an ancestor of existing permits (a permit's lineage is
  named by hash). Nothing totals spend across versions — §5's
  narrowing, unchanged, now stated for lineages too.
- **Ancestor revocation is not re-checked by the walk.** The
  consume path re-checks the immediate parent's status exactly
  as before; the budget walk charges a budgeted ancestor's
  bucket without re-checking that ancestor's revocation. The
  direction is fail-closed (a debit can only refuse more, never
  allow more), and governed derivation is one level deep
  (`directive_parent_chain_unsupported`), so the
  immediate-parent check covers every creatable lineage.
- **Recorded links beyond one level.** The walk's first hop
  comes from the binding's parent hash, which was always
  recorded; activation-recorded links extend the walk deeper.
  Governed derivation cannot currently create a deeper chain,
  so deeper links matter only for out-of-band store states —
  where an unwalkable chain fails closed (A4) rather than
  enforcing partially.
- **Writer custody is unchanged.** A direct store writer who
  deletes the policy row AND strips the binding's recorded
  facts makes a permit read as budget-less. That is §5's
  pre-existing writer-custody class: the bind-time audit record
  carries the original facts, so the strip is detectable from
  the chained audit. The credible case P1(ii) named — row gone,
  facts intact — now fails closed.

### A6. Claim classification

- The two findings: **Verified** (Codex; confirmed in source
  before fixing).
- The fix's behavior: **Verified** (executable evidence at the
  fix head commit).
- Build item status: unchanged from §6 — implemented in this
  PR, NOT canonical until merged on Austin's word.

### A7. Legacy behavior source

None new. The fix follows the repository's own current
patterns: the `parent_directive_hash` migration shape (the
permit_directives precedent) for the directives column, and the
original build's fail-closed status taxonomy for the new
statuses. No legacy control path was copied, and
`pulpo/commerce.py` remains untouched by this path.

### A8. Temporal-transfer evidence

No relevant historical checkpoint exists for the fix as a
replay, and none is manufactured. The transfer property that
matters — budget-less directives and budget-less lineages keep
byte-identical behavior — is pinned executably (A4's negative
control, plus the original module's backwards-compatibility
tests in the same run) rather than by historical replay.

### Eight-pass adversarial review of the fix

Per `docs/ADVERSARIAL_TRANSFORMATION_SOP.md`, applied to the
fix before treating the path as governed:

- **Flip.** The walk trusts only stored records — policies,
  parent links, ledger totals — never anything the permit
  presenter supplies at consume time; debit facts are the
  binding's governed record. No step depends on a cooperative
  caller: a fabricated binding is enforced against its
  fabricated facts (the pre-existing posture), and facts missing
  under ANY budgeted lineage member refuse as
  `budget_context_missing` — including a fabricated budget-less
  child of a budgeted parent, which the walk catches because the
  ancestor's bucket key cannot be computed without facts.
- **Reverse.** Backward from lineage overspend: it requires a
  budgeted ancestor the walk never charges — the walk starts at
  the binding's own parent hash and follows activation-recorded
  links to a root, and any break refuses when enforcement is
  engaged. Backward from an unenforced budgeted spend: it
  requires facts present with no readable policy — now
  `budget_policy_missing` in both backends. The earliest
  boundary for both consequences is the consume transition,
  which is where the fix sits.
- **Invert.** A success through an unauthorized path would be
  recorded as `permit_consumed`; the shapes that could produce
  one were each traced: child without facts under a budgeted
  parent (refused at the ancestor's key computation), forged
  negative cost (refused `budget_context_invalid`, pre-existing),
  malformed ancestor policy (refused `budget_policy_invalid`),
  unwalkable chain (refused `budget_lineage_unresolvable`). No
  success path skips a budgeted bucket the store can show it.
- **Inside-Out.** The backends record and enforce; the fix adds
  no self-authorization. The parent link is written only inside
  `activate_directive`'s typed-evidence transition, the ledger's
  only writer remains the consume transition, and debits never
  decrement or refund. The enforcer cannot mint, widen, or
  ratify through the new state.
- **Darken** (threat case, labeled as such — not a claim it
  occurred): a store writer deletes a policy row and strips the
  binding's facts to restore unlimited spend. This is §5's
  pre-existing writer-custody class, not created or widened by
  the fix: the bind-time audit record carries the original
  facts, so the strip is reconcilable from the chain. The
  bounded corruption case Codex named — row gone, facts
  intact — now refuses.
- **Lighten.** A missing policy row is at least as plausibly
  benign operations damage (a partial restore) as an attack.
  The refusal records a store fact, destroys nothing, and
  leaves the permit unspent and consumable once the policy is
  restored; the record attributes no intent.
- **Amplify.** Sibling multiplication is closed (A4). Cost: the
  walk adds O(depth) stored-record reads inside the existing
  lock/transaction — governed depth is one, so one extra policy
  lookup and one link lookup per consumption in practice.
  Refusals never debit, so re-presented permits cannot
  accumulate spend across retries; the pinned tests assert
  bucket totals are unchanged after every refusal.
- **Negate.** The alternatives were narrower in appearance
  only. Sharing the parent's bucket key for children (Codex's
  stated alternative) conflates two policies into one bucket
  and erases the child's own narrower cap as an independent
  check. Issuance-side lineage checks cannot be decisive —
  outstanding permits race (design point 1). Recording lineage
  on the permit binding would change the binding format and
  every child permit's audit payload to carry what activation
  already records once. The chosen fix records one link per
  directive at its already-governed activation and leaves the
  binding and both hashes untouched.

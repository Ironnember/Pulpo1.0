# Change record — Phase 2, Item 3A: capability facade — kernel-mediated verbs and typed authority evidence

Base: `origin/main` at `d7fab93` (PR #358, Item 4). Authority: Austin's
ruling of 2026-11-13 03:45 (adopt all six Phase 2 recommendations; one
PR per item; sequence Item 2 → Item 1 → Item 4 → Item 3A), ruling Q5 of
the Phase 2 design memo dated 2026-11-13 (Item 3 = facade-only (3A)
this run), and his build authorization of 2026-11-14 ("Build 3A this
weekend"). Build authorized; the merge is Austin's separate decision.

## 1. Invariant or failure addressed

Design repro 3 (`repro_p2_3_capability_handles.py`), re-executed at
the base `d7fab93` before any change — **all three parts still
CONFIRMED** (Items 1/4 changed other surfaces; none of the three
handle paths):

- **A.** `state.consume_permit(token, digest, ts)` spends a genuine
  permit with no kernel involvement; the spend is indistinguishable
  in the audit.
- **B.** `state.activate_directive(forged, {"approver": "no-one",
  "evidence": "invented"})` is accepted; the invented directive reads
  `active` and gates a real kernel spend via
  `state.bind_permit_to_directive` — fabricated evidence gates a real
  spend, end to end.
- **C.** `state.append("decision", {allow, never_evaluated, ...})`
  writes a well-formed forged decision; `verify_audit()` is True.

Production code possessed the handle around the kernel, grep-verified
at the base: `directives.py` (six `kernel._state` calls),
`custody_reconcile.py:599` (`append_unique`), `target_reconcile.py:274`
(`append`), and `incident_channel.py:347` (backend object read for
identification). Failure addressed: **`CANONICAL_STATE_MUTATION ==
GOVERNED_CAPABILITY` was held by convention, not by surface** — the
capability was real and the gate was discipline alone, with the
evidence for directive mutation accepted as an opaque dict verified
against nothing.

## 2. Authority gained, narrowed, or left unchanged

- **Narrowed (surface):** no production module outside `kernel.py`
  holds or reaches `kernel._state` any longer (pinned structurally,
  §4). Every production write to canonical state flows through a
  kernel verb with a fixed event schema. Directive activation and
  revocation additionally require, at the state surface itself, a
  typed `VerifiedAuthorityEvidence` cross-checked against the exact
  directive being mutated — the bare-dict hole of repro B is closed
  at the storage layer, not only by controller discipline.
- **Gained by no one:** no new writer, route, ledger, or capability
  is created. The kernel verbs are delegations to the same state
  methods the kernel already used; the one new value type carries
  exactly the fields the old evidence dict carried.
- **Unchanged (stated plainly):** issuance, evaluation, consume,
  approval and ceremony verification, audit signing (Item 1), anchor
  signing (Item 2), and token expiry (Item 4) semantics are
  untouched. The state methods themselves still exist — the kernel
  calls them — and an in-process caller who constructs a backend
  directly retains every write repro A and C demonstrate (§5).

## 3. Canonical state mutations introduced or exposed

- **Kernel facade verbs** (`pulpo/kernel.py`): `directive_status`,
  `directive_hash_status` (reads); `activate_directive`,
  `revoke_directive`, `bind_permit_to_directive` (directive writes,
  delegating to the state layer's gated methods);
  `record_target_completion` (fixed event `target_completed`, fixed
  payload: exact target/intent hashes, completion dict, completion
  hash, `authority_effect: "none"`); `record_domain_outcome_memory`
  (fixed event `domain_outcome_memory`, unique on
  `reconciliation_transition_hash`, the state's `append_unique`
  contract); `state_source_id` (read-only backend identification).
  No verb lets a caller choose an event name or a payload shape.
- **Migrations to the verbs:** `pulpo/directives.py` (all six
  reach-throughs), `pulpo/custody_reconcile.py` (outcome-memory
  append), `pulpo/target_reconcile.py` (completion append), and
  `pulpo/incident_channel.py` (the backend object was used only to
  derive a source identifier; it now asks the kernel for
  `state_source_id()`, which preserves the exact prior behavior —
  a SQLite connection `activity_id` when present, else the
  process-scoped hash). The incident-channel migration is a
  deliberate, disclosed extension beyond the memo's three named
  modules: the pin is zero reach-through in production modules, and
  this was the fourth.
- **Typed evidence** (`pulpo/state.py`): `VerifiedAuthorityEvidence`,
  a frozen dataclass carrying exactly the fields of the old dict.
  Both backends' `activate_directive`/`revoke_directive` require
  `type(evidence) is VerifiedAuthorityEvidence` (exact type, the
  repo's canonical-type precedent — a subclass is refused) and
  cross-check operation, directive id, version, and hash (plus the
  parent hash on activation) against the mutation being recorded;
  mismatch raises before any write. The audit payload is serialized
  via `audit_payload()` and is **byte-identical to the pre-3A dict**,
  so existing chains and readers see no format change. The
  `KernelState` protocol now declares the two methods with the typed
  signature.
- **Construction discipline:** the only production construction site
  of `VerifiedAuthorityEvidence` is
  `DirectiveAuthorityController._evidence`, reached only after the
  kernel has verified the approval envelope and consumed the one-use
  authority permit (the `ApprovalUse` pattern: a state-layer value
  the kernel-side verifier path produces). A structural test pins
  both this and the zero reach-through (§4).
- **Signer-injected construction (Item 1 synergy, as sequenced):**
  the facade wraps the same state construction Item 1 built — the
  kernel is constructed over a state that may carry an
  `AuditSigner`, and every facade append flows through that same
  signed append path. No second construction path is introduced;
  records written via the verbs are signed exactly as records
  written via `evaluate`/`consume` are.

## 4. Exact success and adversarial evidence

- **Pre-fix repro (gap):** `repro_p2_3_capability_handles.py` at
  `d7fab93`: A spent True, B accepted + kernel spend under the
  invented directive True, C forged record verifies True — **gap
  CONFIRMED at the base** (output retained with the build evidence).
- **Post-fix repro** (same shapes, fixed tree): B1 bare-dict
  activation **REFUSED** (`TypeError`), directive reads
  `directive_not_authorized`, no record written; B2 a
  `VerifiedAuthorityEvidence` bound to a *different* directive
  **REFUSED** (`ValueError`); honest flows (controller activation
  with a verified envelope, projection-gated spend, reconciliation
  verbs) work end to end. A and C and the fabricated-wrapper case
  (B3) still succeed for a handle holder — the priced residuals,
  printed as residuals in the repro output itself (§5).
- **New tests** (`tests/test_capability_facade.py`, 10 tests):
  bare-dict activation refused on both backends; bare-dict revocation
  refused after an honest activation; evidence bound to another
  directive and evidence with the wrong operation refused; evidence
  subclass refused (exact-type gate); controller activation records
  the typed evidence with the pre-3A payload shape asserted field by
  field, and the activated directive gates a one-use spend; the two
  reconciliation verbs write exactly their fixed schemas (and
  outcome memory appends once, returning the existing payload on
  repeat); `state_source_id` is stable per kernel and distinct
  across kernels; two structural pins (zero `._state` outside
  `kernel.py`; `VerifiedAuthorityEvidence(` constructed only in
  `directives.py` among production modules).
- **Existing tests migrated (4 call sites, assertions unchanged):**
  `tests/test_inmemory_consume_concurrency.py` (3 sites) and
  `tests/test_directive_parent_activation_race.py` (1 site) called
  the state layer directly with placeholder dicts (`{"test": True}`,
  `{"test_race": ...}`). Those tests exercise concurrency and race
  timing, not evidence shape; their setup now presents typed
  evidence bound to the exact directive, as the controller would
  after a verified approval. No assertion was weakened, deleted, or
  re-pinned; no other existing test was modified.
- **Full suite:** baseline at `d7fab93` **785 OK (skipped=13)**; at
  this branch's head: **795 OK (skipped=13)** — the 10 new tests.
  The directives, custody-reconcile, target-reconcile, incident
  channel, orchestrator, and concurrency suites were additionally run
  standalone and pass.
- **Constitutional mutations:** two added —
  `directive_evidence_type_check_removed` and
  `directive_evidence_binding_check_removed` (both anchored in
  `state.py`'s evidence gate). Full run: **21/21 killed, 0 survived,
  0 invalid.**

## 5. Boundary the evidence does not prove

- **3A is discipline + evidence, not in-process enforcement (ruling
  Q5).** Python privacy is convention. A determined in-process
  caller can construct a `SQLiteKernelState`/`InMemoryKernelState`
  directly and: spend via `consume_permit` (repro A), append forged
  records via `append` (repro C), or activate a directive by
  constructing a `VerifiedAuthorityEvidence` with fabricated fields
  bound to the forged directive (repro B3) — the state layer cannot
  verify signatures, and this PR does not teach it to (that was
  option 3C, rejected in the memo for collapsing the layering).
  What 3A proves is the part evidence can check: production modules
  possess no ungoverned handle; every production write has one
  singular, reviewable governed path; and the anonymous-dict forgery
  — the form the gap actually took — no longer passes any surface.
  Fabrication now requires a deliberate, greppable construction of a
  named type.
- **Enforcement is the Phase 3 program.** Item 3B (service boundary:
  one process holds the state; every other component gets
  authenticated client verbs, never the handle) is the only design
  in the memo where gating is enforced by a process boundary. It is
  named here, not built here, and no claim in this PR should be read
  as service-boundary enforcement.
- **The kernel itself remains a trusted writer** — necessarily: it
  is the governor. The facade narrows *sibling* possession of the
  capability; it does not and cannot gate the kernel's own verbs
  against a caller who holds the kernel (that caller already holds
  `evaluate`/`consume`).
- **`state_source_id` is identification, not attestation.** It names
  the backend instance a report was derived from, in-process; it
  proves nothing about the backend's contents (the report's own
  `verify_audit` result carries that).

## 6. Claim classification

- **Verified** (executed at this branch's head): the §4 repro
  verdicts before and after; the 10 new tests; the full suite at
  795 OK; 21/21 mutations killed; the structural pins running green;
  the audit-payload byte-identity asserted field by field.
- **Recorded:** Austin's 2026-11-13 ruling and memo Q5 as the design
  authority, and his 2026-11-14 build authorization; the pre-fix gap
  verdict as originally reproduced in the design memo's work
  (re-run and confirmed at `d7fab93` for this PR).
- **Inferred:** that the facade's verb set is complete for current
  production needs — it covers exactly the reach-throughs grep found
  at the base; a future sibling need arrives as a new verb or not at
  all, and the structural pin is what forces that choice into review.
- **Proposed:** nothing in this PR.
- **Unknown:** whether any out-of-tree consumer calls
  `activate_directive`/`revoke_directive` with dicts (the in-tree
  callers are migrated; the type change is a deliberate, visible
  break for any such caller, and failing loudly is the intent).

## 7. Legacy behavior source

The legacy behavior is the pre-3A surface itself, read at `d7fab93`:
sibling reach-through via `kernel._state` and the opaque-dict
evidence parameter. It is deliberately **not** carried forward: no
compatibility shim accepts dicts, and no module keeps a private
handle "just in case." The audit *record format* is the one legacy
artifact preserved exactly — the evidence dict's shape is retained
via `audit_payload()` so historical chains and their readers are
unaffected; what changed is the surface that accepts the evidence,
not the evidence on disk. The construction-token discipline follows
the current tree's own `ApprovalUse` precedent, and the exact-type
check follows the incident channel's canonical-type precedent; no
legacy control path is copied.

## 8. Temporal transfer

One material lesson is transferred: **the signer-injected
construction path is the seam the facade must wrap, not duplicate**
(Item 1, verified at `1a03f0c`): Item 1 injected the audit signer
into state construction precisely so every append — kernel's or a
sibling's — is signed by the same hand. 3A was sequenced after Item
1 for this reason (memo §3c), and the transfer is pinned by the
unchanged signed-audit suite at this head: facade-written records
carry signatures under an enabled deployment exactly as
kernel-written ones do. Where it does not transfer: Item 1's claim
"the state layer wrote this" narrows here only for *production
modules* — §5's handle-holder residuals mean the narrowed claim
"the kernel's verbs wrote this" is Verified for the production
tree (structural pin) and must not be generalized to arbitrary
in-process code. No other historical checkpoint is material to this
change; no temporal proof is manufactured for the facade design
itself, which is new at this ruling.

## 9. Adversarial transformation review (AGENTS.md)

Purpose: every production write to canonical state flows through one
governed, auditable kernel surface, and directive mutation requires
typed verified evidence at the state layer. Exact requested outcome:
the repro-B forgery (fabricated dict gates a real spend) is
impossible through any supported path, and sibling possession of the
state handle is zero in production modules. Authority boundary: the
kernel mediates; the state layer checks types and bindings; no new
governed transition is created.

- **Flip** (reverse the actor): if the *sibling module* is the
  hostile actor, it no longer holds the handle — its writes are the
  kernel verbs, each with a fixed schema it cannot widen. If the
  *caller of the kernel* is hostile, it already holds evaluate/
  consume; the facade claims nothing there (§5). Survival: the
  claim is worded at production-module strength, which is what the
  structural pin actually checks.
- **Reverse** (from the consequence): a forged directive activation
  now requires (a) a verified envelope through the controller (the
  governed path), (b) constructing the named typed value with
  fabricated fields (deliberate, greppable, and the structural pin
  fails CI if a production module does it), or (c) constructing a
  backend directly (out of process scope, §5). The earliest boundary
  that makes the *anonymous* form unreachable is the state layer's
  exact-type check — it fires even if a future caller bypasses the
  controller and calls the kernel verb or the state method directly.
- **Invert** (success through an unauthorized path): the remaining
  inversions are exactly repro A/C/B3 — success is still reachable
  by a handle holder, by design pricing (Q5). The inversion that
  would falsify this PR — a *production module* writing around the
  kernel — is the one the pin makes a CI failure rather than a
  review hope.
- **Inside-Out** (the enforcer as originator): the kernel's verbs
  delegate to the same state methods; the kernel could in principle
  be modified to misuse them — but that is a code change to the
  governor itself, visible in review and in the signed-commit chain,
  not a runtime route. The facade introduces no second writer: the
  verbs are the kernel's own hand, named.
- **Darken** (worst credible bounded case): an attacker with code
  execution inside a consuming process ignores the facade entirely
  (§5) — unchanged from pre-3A. What darkens no further: a *plugin
  or adapter* that merely holds the kernel (the documented embedding
  shape) can no longer reach past it to the state without writing
  visibly non-production-shaped code, and a reviewer or the pin
  catches the reach-through pattern mechanically.
- **Lighten** (minimum benign interpretation): most pre-3A
  reach-through was convenience, not malice — the modules needed
  three writes and two reads, and the handle was the shortest path.
  The facade's cost is correspondingly small: the verbs are those
  exact operations, so the benign reading (ergonomics caused the
  exposure) predicts the fix's shape, and the migrated call sites
  confirm it — each is a one-line change.
- **Amplify** (scale/repeat): the pin scales mechanically — every
  future production module is checked by the same grep, and every
  future sibling write need must arrive as a named kernel verb in
  review, which is where its schema gets governed. Verification
  cost is unchanged (the verbs delegate; the evidence cross-check is
  field comparisons on an already-locked path).
- **Negate** (is the mechanism necessary): could controller
  discipline alone have closed repro B, leaving the state surface
  dict-typed? No — repro B's caller *is* the surface's caller; a
  gate that lives only in one caller governs that caller, and the
  next caller re-opens the hole silently. The type requirement had
  to live in the state layer to be a property of the surface. Could
  the state layer verify the evidence's *signature* and make B3
  impossible too? That is option 3C — policy inside storage,
  rejected in the memo; B3's closure is 3B's process boundary.

Invariants checked: `CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`
(the facade's whole point: the mutations remain, the capability is
now possessed only through governed verbs in production code);
`NO_WRITE_ROUTE != NO_WRITE_CAPABILITY` (stated, not violated: 3A
removes ungoverned *possession* from production modules and says so;
it does not claim the capability left the process);
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS` (a
verified activation authorizes recording *that* directive, and the
binding cross-check refuses evidence recorded for any other);
`AUTHORIZATION_TO_USE_CAPABILITY != AUTHORIZATION_TO_DUPLICATE_CAPABILITY`
(no verb returns, serializes, or exposes the state object;
`state_source_id` returns an opaque identifier, never the handle).

## 10. Post-review addendum — Codex P1 fix: the two reconciliation verbs now verify at the append surface

**Status of this section:** added after the original head `84fbdef`
was reviewed. It supersedes §3's and §4's description of
`record_target_completion` and `record_domain_outcome_memory` (there
described as fixed-schema appends). The directive-evidence sections
(§§1–9) are unchanged. Disposition: Austin, 2026-11-15 —
"Reproduce both, then narrow the verbs before merge."

### 10.1 The findings

Codex review on this PR (2026-11-14 21:17 UTC) raised two P1s, both
on `pulpo/kernel.py`, both the same failure mode: 3A's new public
verbs fixed the *shape* of a record but did not verify its *truth*,
and no second check sat at the append surface — so a direct verb
caller bypassed the projection layer's checks silently, and the
resulting record was indistinguishable from an honest one in the
audit (both verify).

- **P1-1 (comment 4575682584) — forged target completion.**
  `record_target_completion` accepted a caller-supplied completion
  dict + matching hash with no filesystem observation. The governed
  `GovernedTargetReconciliation.complete_file` observes first; the
  verb did not.
- **P1-2 (comment 4575682585) — forged domain outcome memory.**
  `record_domain_outcome_memory` recorded a syntactically valid
  payload claiming `SUCCESS_VERIFIED` / `reusable=True` without the
  exact-target, custody-receipt, observation, or budget checks in
  `GovernedDomainOutcomeMemoryProjection.record`; `latest()` then
  treated the forged record as canonical memory.

Before 3A, each of these events had exactly one checked writer.
3A itself introduced the second, unchecked write routes; the
original change record did not name them.

### 10.2 Reproduction (before the fix, at `84fbdef`)

Both findings were reproduced end-to-end before any fix, with the
governed paths confirmed unaffected:

- P1-1: a fabricated `ArtifactCompletionEvidence` naming
  `/tmp/definitely-not-a-real-artifact-84fbdef.pptx` (asserted
  nonexistent) + a self-computed hash was recorded;
  `GovernedTargetReconciliation.status()` returned `completed` /
  `completion_evidence_recorded`; `verify_audit()` was True.
- P1-2: an invented `DomainOutcomeMemory` (every hash the SHA-256 of
  a label string; no order, attempt, observation, receipt, or budget
  anywhere) was recorded (`append_unique` returned None = newly
  recorded); `projection.latest("attempt-forged-v0")` returned it as
  canonical memory with `SUCCESS_VERIFIED` / `reusable=True`;
  `verify_audit()` was True.
- The governed paths were **not** affected: `complete_file`'s
  observation tests and `projection.record`'s full gauntlet passed
  at that head (target/custody/facade suites, 26 tests, OK).
  Reproduction was re-run at the start of the fix session and
  reproduced again identically.

### 10.3 Fix shape — P1-1: observation moved into the verb

- A module-level `_observe_artifact_file(path)` in `pulpo/kernel.py`
  now holds the descriptor-bound stable-observation logic (same
  `ValueError` reason strings: `artifact_not_found` /
  `artifact_changed_during_observation` / `artifact_unreadable` /
  `artifact_not_file` / `artifact_empty`).
  `GovernedTargetReconciliation._observe_file` delegates to it — one
  implementation, shared by the projection and the verb.
- New verb signature:
  `record_target_completion(*, target_id, version, target_hash,
  intent_hash, artifact_path, timestamp_ns) -> dict`. It resolves
  the locked target via `get_locked_target` (absent →
  `ValueError("target_not_locked")`), hmac-compares `target_hash`
  (`target_hash_mismatch`) and `intent_hash` against
  `kernel.intent_hash(target.intent)` (`target_intent_mismatch`),
  refuses `timestamp_ns < target.created_at_ns`
  (`RuntimeError("artifact_observed_before_target")`), observes the
  artifact itself, builds the completion dict with exactly the
  `ArtifactCompletionEvidence` fields (artifact path = the resolved
  observed path, `observed_at_ns = timestamp_ns`,
  `schema="pulpo.target-artifact-completion.v0"`), computes
  `completion_hash = sha256(_canonical(completion))`, appends the
  same fixed `target_completed` payload as before
  (`authority_effect: "none"`), and returns the completion dict.
  A caller-supplied completion dict/hash is no longer accepted
  anywhere — the old call shape raises `TypeError`.
- `GovernedTargetReconciliation.complete_file` keeps its exact-target
  pre-check, its own observation, and its immutability comparison
  semantics, then calls the new verb with the artifact path and
  returns `ArtifactCompletionEvidence(**recorded_dict)`, so the
  returned object always matches the recorded one.

### 10.4 Fix shape — P1-2: the verb verifies before `append_unique`

`record_domain_outcome_memory` now refuses — `ValueError` with a
distinct `outcome_memory_*` reason, and **nothing appended** — unless
every check passes, in this order:

1. The payload is a dict and its `reconciliation_transition_hash`
   equals the transition-hash argument
   (`outcome_memory_payload_invalid` /
   `outcome_memory_transition_hash_mismatch`); its `schema`,
   `authority_effect`, and `governed_effect` equal the
   `DomainOutcomeMemory` constants (`outcome_memory_schema_mismatch`
   / `outcome_memory_authority_effect_mismatch` /
   `outcome_memory_governed_effect_mismatch`).
2. **Identity:** `memory_id` hmac-matches `sha256(_canonical(identity))`
   recomputed over exactly the identity dict
   `GovernedDomainOutcomeMemoryProjection.record` builds
   (`outcome_memory_memory_id_mismatch`).
3. `payload["policy_hash"]` equals this kernel's `policy_hash`
   (`outcome_memory_policy_hash_mismatch`).
4. **Custody evidence:** exactly one audit record with event
   `custody_transition` carries the transition hash
   (`outcome_memory_custody_evidence_missing` / `_ambiguous`); its
   schema is `pulpo.custody-evidence-projection.v0` and its receipt
   satisfies `receipt.transition_hash == hash`,
   `receipt.object_hash == payload["order_hash"]`, and
   `receipt.epoch == payload["reconciliation_epoch"]`
   (`outcome_memory_custody_evidence_mismatch`).
5. **Classification consistency** with `receipt.transition_type`:
   `reconciled_success` → outcome `success`, classification
   `SUCCESS_VERIFIED`, `reusable is True`; `reconciled_failure` →
   outcome `failure`, classification in
   {`RECONCILIATION_FAILURE`, `RECONCILIATION_MISMATCH`},
   `reusable is False`; `unresolved` → outcome `unresolved`,
   classification `EVIDENCE_FAILURE`, `reusable is False`; any other
   transition type refuses (`outcome_memory_classification_mismatch`
   / `outcome_memory_custody_transition_type_invalid`).
6. **Exact target:** exactly one `target_locked` audit payload
   carries `payload["target_hash"]`
   (`outcome_memory_target_missing` / `_ambiguous`), and its
   `intent_hash` equals `payload["intent_hash"]`
   (`outcome_memory_target_intent_mismatch`).

Only then does the pre-existing `append_unique` run, unchanged.

**Defense in depth on the read side:** `_memory_records` in
`pulpo/custody_reconcile.py` now recomputes each constructed
`DomainOutcomeMemory`'s identity hash from its own fields (a
module-level `_outcome_memory_identity` helper, field-for-field the
derivation `record` uses; `record`'s own derivation is unchanged)
and raises `CustodyViolation("outcome_memory_record_identity_mismatch")`
on mismatch — so a record that reached the audit by a route that
skipped the verb is still refused by `latest()` when its
`memory_id` does not recompute.

### 10.5 Evidence (after the fix)

- **Adapted repros** (same forgeries attempted against the new
  surface): P1-1 — the old dict+hash call shape raises `TypeError`;
  the new verb with the nonexistent path raises
  `ValueError("artifact_not_found")`; `status()` returns
  `unresolved` / `completion_evidence_missing`; 0
  `target_completed` events; `verify_audit()` True. P1-2 — the
  original forged payload raises
  `ValueError("outcome_memory_memory_id_mismatch")`; a fully-formed
  invented payload whose `memory_id` is *correctly* recomputed over
  invented hashes (policy hash = the kernel's own) raises
  `ValueError("outcome_memory_custody_evidence_missing")`;
  `latest()` returns None; 0 `domain_outcome_memory` events;
  `verify_audit()` True.
- **Tests:** the pre-fix test `test_kernel_verbs_record_fixed_schemas`
  — which itself recorded a fabricated completion dict and a nonsense
  memory payload, i.e. it pinned the forgery shape — is replaced by
  five tests in `tests/test_capability_facade.py`:
  verb-level completion against a real locked target + real temp
  file (recorded completion fields and hash asserted against the
  observed file); refusal of a nonexistent artifact, a wrong intent
  hash, and a wrong target hash with nothing appended; refusal of
  both the old nonsense payload and the correctly-recomputed invented
  payload with nothing appended; an end-to-end regression mirroring
  repro P1-1 (forged completion does not make `status()` return
  completed); an end-to-end regression mirroring repro P1-2 (forged
  memory is not returned by `latest()`); and a read-side regression
  (a raw-appended memory whose `memory_id` does not recompute is
  refused by `latest()`). Facade suite: **15 tests, OK** (10 at the
  original head; net +5).
- **Governed paths unchanged:** the pre-existing positive
  outcome-memory coverage (the Issue-153 consequence-reconciliation
  and hostile suites, and `tests/test_custody_reconcile.py`) passes
  through the new verb unchanged, as do all target-reconciliation
  tests — the honest writers satisfy every new check by construction.
- **Full suite:** **800 OK, skipped=13** at the fix head (795 at the
  original head + 5 net new tests).
- **Constitutional mutations:** three added in the same style —
  `target_completion_observation_removed`,
  `target_completion_intent_check_removed`, and
  `outcome_memory_custody_evidence_check_removed`. Full run:
  **24/24 killed, 0 survived, 0 invalid.**

### 10.6 Boundary the fix does not prove (residuals, stated plainly)

- **The kernel cannot re-derive the custody layer's
  observation/budget checks.** The verb binds the memory to a real
  projected custody receipt, the kernel's own policy, an exact
  locked target, and a self-consistent identity. `attempt_id` is
  bound through the identity hash, and the projection's own checks
  remain the authority for observation/receipt/budget exactness.
  A payload that is fully consistent with a *real* projected receipt,
  a *real* locked target, and this kernel's policy — but whose
  observation was never independently checked — is refused by
  `projection.record` and not by the verb alone; the verb's claim is
  the narrower one above.
- **Raw `state.append` (repro C) is unchanged.** A handle holder who
  bypasses both verbs entirely and appends a `target_completed` or
  `domain_outcome_memory` record directly can still write a record
  whose stored hashes are self-consistent; the read-side identity
  check catches a memory whose `memory_id` does not recompute, and
  nothing here catches a fully self-consistent raw append. That is
  the §5 handle-holder residual, priced at ruling Q5; its closure is
  Item 3B's process boundary, as before.
- **The kernel remains a trusted writer** (§5, unchanged): the fix
  verifies what the kernel's verbs record; it does not gate the
  governor against a caller who holds the kernel and chooses to
  construct a backend directly.

### 10.7 Claim classification (this addendum)

- **Verified** (executed at the fix head): both P1 repros before the
  fix (reproduced twice: at review and at the start of the fix
  session) and after it; the 5 new facade tests; the governed-path
  suites passing through the new verbs; the full suite at 800 OK;
  24/24 mutations killed.
- **Recorded:** the Codex findings (comments 4575682584 and
  4575682585) and Austin's 2026-11-15 disposition.
- **Inferred:** that the verb check set is complete for the two
  events' current honest writers — it covers exactly the fields both
  projections bind today; a future field a projection relies on must
  be added to the verb's checks in the same change that adds it to
  the projection.
- **Proposed / Unknown:** none introduced by this addendum.

### 10.8 Adversarial transformation review — the new checks (AGENTS.md)

Purpose: a reconciliation record in canonical state must be tied to
something the kernel itself observed or can re-derive — an observed
file, a projected custody receipt, an exact locked target, this
kernel's policy — never to a caller's assertion alone. Exact
requested outcome: the two repro forgeries of §10.2 are refused at
the append surface and no forged record lands. Authority boundary:
the verbs verify; they grant nothing (`authority_effect: "none"` on
every record they write is unchanged).

- **Flip** (reverse the actor): if the *caller of the verb* is
  hostile, it can no longer supply the evidence — for completions it
  supplies only a path, and the kernel observes; for memories it
  supplies a payload every load-bearing field of which is checked
  against records the caller did not write through this verb (the
  projected receipt, the locked target, the policy hash). If the
  *projection* is the hostile actor, it gains nothing: the verb's
  checks are a floor, not a ceiling — `record`'s gauntlet still runs
  first on the governed path. Survival: the claim is worded at
  append-surface strength, which is what the tests execute.
- **Reverse** (from the consequence): a forged canonical memory now
  requires (a) a real projected `custody_transition` record for the
  claimed transition (written only by the custody convergence from a
  signed custody receipt), (b) a real locked target with the claimed
  hashes, (c) this kernel's policy hash, and (d) a self-consistent
  identity — or (e) bypassing the verb via raw `state.append` with a
  fully self-consistent record (the priced §10.6 residual). The
  earliest boundary that makes the *verb-route* forgery unreachable
  is check 2/4: identity alone is forgeable by construction, so the
  receipt-existence check is the load-bearing one, and it is the one
  the adapted repro isolates (correct identity, no receipt →
  refused).
- **Invert** (success through an unauthorized path): a completion
  recorded for a file that was never observed is now a failure of
  the verb, not a success — the observation *is* the record's
  content, derived inside the kernel. The remaining inversion is
  the raw-append route, named in §10.6 rather than hidden.
- **Inside-Out** (the enforcer as originator): the kernel observes
  the file and recomputes the identity itself, so the enforcer is
  the originator of the evidence — deliberately: the kernel is the
  governor and a trusted writer (§5). What it cannot do is originate
  the *custody receipt*: that record is written by the custody
  convergence from custody's own signing material, a different
  component, so the memory verb's strongest check is anchored
  outside the kernel's own hand.
- **Darken** (worst credible bounded case): an attacker who holds
  the kernel *and* a real projected receipt for a real transition
  *and* a real locked target can record a memory for that transition
  whose observation fields the kernel cannot re-derive (§10.6) —
  bounded to transitions that actually happened in custody, with
  classification forced consistent with the receipt's type. An
  attacker with code execution in-process ignores the verbs
  entirely (§5) — unchanged, and not widened: the fix removes two
  routes, it adds none.
- **Lighten** (minimum benign interpretation): the honest writers
  needed no change in behavior — `complete_file` already observed,
  `record` already verified — which is why both governed suites pass
  through the new verbs untouched. The benign reading (the verbs
  were thin delegations written for symmetry, and the checks simply
  lived one layer up) predicts exactly the fix's shape: move the
  checks to the surface, keep the writers.
- **Amplify** (scale/repeat): the checks are per-record field
  comparisons and audit scans on already-locked paths; replay is
  unchanged (`append_unique` still returns the existing payload on
  an exact repeat, and only after the same checks pass). At fleet
  scale the failure mode to watch is audit-scan cost on long chains,
  not authority accumulation — no check grants, caches, or carries
  authority between calls.
- **Negate** (is the mechanism necessary): could the verbs have been
  made private instead (fix shape (b) in the repro report)? Yes, and
  it would have closed today's routes — but the facade's purpose is
  that sibling modules write *through* named kernel verbs; a private
  verb re-creates the reach-through pressure the structural pin
  exists to prevent, and leaves the next caller to re-open the hole.
  Verification at the append surface is the smallest change that
  keeps the governed path singular *and* checked. Could the verb
  re-run the projection's full gauntlet (observation, budget,
  receipt signature)? That would move the custody layer into the
  kernel — the layering collapse rejected at option 3C — and §10.6
  states the resulting residual instead of hiding it.

Invariants checked: `CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY`
(the two mutations remain; their capability is now possessed only
through verbs that verify what they record);
`OBSERVED_STATE_CHANGE != GOVERNED_STATE_TRANSITION` (a caller's
*asserted* state change is no longer a transition at all — the
completion transition is the kernel's own observation);
`AUTHORIZED_OUTCOME != AUTHORIZATION_FOR_ARBITRARY_MEANS` (a
legitimate completion authorizes recording *that* observed artifact
for *that* locked target; the verb derives every other field);
`GOVERNED_PATH + UNGOVERNED_ALTERNATE_PATH != GOVERNED_SYSTEM` (the
alternate verb routes are closed; the raw-handle alternate path is
§10.6's named residual, and 3B remains the program that closes it).

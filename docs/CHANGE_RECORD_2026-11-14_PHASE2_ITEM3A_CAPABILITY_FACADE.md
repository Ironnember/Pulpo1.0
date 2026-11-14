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

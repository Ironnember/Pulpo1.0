# Change record — PR #355 follow-up fixes (2026-11-13)

Required change record (repo AGENTS.md) for the two fixes that land on
`fix/writer-custody-phase1` after Codex's P1 review of the Phase 1 build
(head `329122c`). Both findings were independently reproduced at that
exact head before any fix was written (verification report held with
the PR's working papers: verdicts Verified, both REPRODUCED).

## 1. Invariant / failure addressed

- **Fix A (kernel intent binding).** Phase 1 authenticated the permit
  token at the kernel (provenance) and left the token-to-intent binding
  to the store's check against the permit row's stored `intent_hash`.
  That column is writer-controlled and outside the audit chain: a
  state-file writer holding one genuine, already-spent token rewrote
  its row (intent hash of a destructive intent, `spent` reset) and a
  fresh kernel consumed the token for the retargeted intent, with
  `verify_audit()` true throughout. The authenticated token must bind
  the intent it may be spent for; writer-controlled state must not be
  able to move that binding.
- **Fix B (ops projection purity).** The read-only projections
  `verify` / `status` opened the kernel through the provisioning
  secret path, so they created (and permission-repaired) the
  `kernel-secret` file on legacy deployments; on a read-only mount
  they failed and reported the failure as an *invalid audit chain*
  over a chain that was valid. A surface described as read-only must
  remain non-mutating, and an open failure must not be reported as a
  chain verdict.

## 2. Authority gained, narrowed, or left unchanged

- Fix A **narrows the store's effective authority**: the store's
  binding check remains, but it is no longer the layer a spend depends
  on for intent binding — the kernel refuses a token whose
  authenticated digest does not match the presented intent before the
  store is consulted. No authority is gained by any surface; the
  kernel's refusal is fail-closed and evidenced
  (`permit_rejected` / `permit_intent_mismatch`).
- Fix B **narrows the ops transport's mutation surface**: `verify` and
  `status` can no longer create or repair deployment files. Provisioning
  authority stays exactly where it was — `init`, `authorize`,
  `consume`. `authority_effect=none` for both fixes.

## 3. Canonical state mutations introduced or exposed

- Fix A introduces no new mutation: a mismatched spend appends the
  same `permit_rejected` audit event the store already used, with a
  `reason` naming the mismatch — one record per refused attempt,
  bounded as before. No new write route, no new governed capability.
- Fix B removes a mutation (secret-file creation/chmod) from two
  read-only commands. Projections on a secret-less deployment open the
  kernel with an ephemeral, never-persisted secret; nothing they
  report authenticates a token (they read the audit trail, the unkeyed
  chain verification, and the policy hash).

## 4. Success and adversarial evidence (at the fixed tree)

- Full suite: 715 tests OK, 13 skipped (705 at `329122c` + 10 new).
- Fix A: the Codex reproduction script, re-run against the fixed tree,
  flips — the retargeted spend is refused with
  `reason: permit_intent_mismatch`, the chain valid throughout
  (script verdict: CLAIM A REFUTED). Standing regressions:
  `RetargetedPermitRowTests` (SQLite exact attack + in-memory parity)
  assert the refusal AND that `verify_audit()` stays true, pinning
  that prevention, not detection, is what stops it.
- Fix A test re-design: the seven tests the layering change displaced
  were re-pinned, none deleted or weakened. The writer-custody
  layering test now asserts the kernel-issued refusal (same property:
  genuine token + substituted intent is refused, nothing spent, true
  spend still works). The store's binding is proven directly at the
  state layer (`StateIntentBindingTests`, both backends). The five
  incident/example negative controls keep identical end-to-end
  outcomes; their unguarded axis now spans both consume layers (a
  kernel double restoring the pre-#355 consume path over the
  intent-blind state double), because with binding at the kernel a
  state-only double is no longer reachable — the reasoning is recorded
  in each control. The Replit step-4 test reconciles the fabrication
  denial against the kernel's rejection record; the store-level
  revocation evidence for the same held permit remains step 3's,
  unchanged.
- Fix B: new ops tests assert (1) `verify`/`status` on a legacy
  (secret-less) deployment succeed and create nothing, including with
  the deployment directory read-only; (2) an existing secret with
  loose permissions is loaded but NOT repaired by the projections;
  (3) `authorize` on a legacy deployment still provisions the secret
  owner-only and the permit it mints consumes normally.
- Diagnosis repros re-run against the fixed tree: A (state-minted
  forgery) spend still refused; B (raw SQLite forgery) spend still
  refused, forged chain still verifies, anchoring outcomes identical
  (tail truncation detected; truncation + anchor-file rewrite still
  passes — the unsigned-anchor boundary, unchanged); C (payload
  detachment) unchanged; D (policy swap) still fails closed with
  `StateIntegrityError`. The retarget variant of A is the one outcome
  that changed: spend True → False.

## 5. Boundary the evidence does not prove

Unchanged from Phase 1 and stated plainly: audit-record signing /
write prevention is NOT solved (the unkeyed chain still verifies
honestly recomputed forgeries; the anchored head remains the detection
layer); the anchor file is unsigned by default; capability-gated
handles are NOT implemented (direct `state.consume_permit` /
`kernel._state` reach-through remains ungated — Phase 2); bearer-token
theft semantics are unchanged (whoever holds a genuine token and the
deployment secret's HMAC can still authenticate — the token must still
be presented for its own intent now, but possession is possession).
Fix A binds a genuine token to its authorized intent; it does not
make the state file trustworthy, and it does not authenticate writers.

## 6. Claim classification

- Both Codex findings: **Verified** (independently reproduced at
  `329122c` before the fix; the fix's effect on the Claim A
  reproduction is likewise **Verified** by re-execution).
- The supersession of the provenance-only layering: a decision by the
  repository owner (Austin), 2026-11-13 — **Recorded**.
- Everything else in this record: **Verified** by the test suite and
  repro runs cited above, at the fixed tree.

## 7. Legacy behavior source

The unguarded kernel double used by the re-designed negative controls
restores the pre-#355 `consume` body (delegate to
`state.consume_permit`) as a *test double only*; no legacy control path
was copied into production code.

## 8. Temporal transfer

The applicable historical checkpoints are exact commits: base
`7f2a7c9` (diagnosis) and PR head `329122c` (Phase 1 as reviewed). The
Claim A lesson — "writer-controlled state must not carry a binding the
kernel relies on" — was evaluated at both: the attack fails at
`7f2a7c9` only because tokens were unauthenticated there for a
different reason (no genuine token could be authenticated at all),
succeeds at `329122c` (Phase 1's layering), and fails at the fixed
tree for the stated reason (kernel-side binding). The store's binding
behavior is identical at base and at the fixed tree and is re-proven
there by `StateIntentBindingTests`. No future authority, approval, or
credential was carried into any historical state; the replay changed
no consequential authority.

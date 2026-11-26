# Change record — Canonical Lease port, PR 1: kernel-bound leases

Design authority: `canonical-lease-port-spec-DRAFT-2026-11-22.md`
§§2, 3, 4, 10 (held outside the repo in the goal workspace; its
source analysis is the Autonomous diff check of the same date).
Build authorized by Austin, 2026-11-22 ("Adopt the port plan and
draft the spec"; "Alright, proceed"; explicit checkout go-ahead
21:05 MST after a runtime execution-risk notice). Built on
canonical main `2726e59`. Base suite: 1036 OK, skipped=13. This PR
is PR 1 of the spec's three-PR sequence; PR 2 (offline state
machine, consumption records, reconciliation) and PR 3 (bounded
intake, signed boot attestation, domain-safety composition) are
not in it.

## 1. Invariant or failure addressed

The Autonomous physical layer's leases were locally mintable
dataclasses (diff check §5.4): `ExecutionEnvelope` and
`OfflineMissionLease` have public constructors, nothing in
Autonomous's `core/` imports its kernel, and an execution tracker
would plan and send against a locally assembled lease with no
kernel permit ever issued or consumed. Ported as-is, that shape
would put a second, ungoverned authority plane beside the kernel —
`GOVERNED_PATH + UNGOVERNED_ALTERNATE_PATH != GOVERNED_SYSTEM`.

The fix, in full:

- **`Lease` artifact (kernel.py).** A frozen claim set — bound
  intent (intent hash, action, resource, exact payload digest),
  authority binding tuple (directive id/version/hash, parent hash,
  policy hash, deployment, presenter, session, nonce), command
  budget, disconnected window, mandatory safe fallback, sequence
  floor, boot counter, validity window. `lease_digest` hashes
  every claim; the token is the v3 discipline
  (`digest:nonce:issued:expires:presenter_hash:signature`) with
  the lease digest as its digest, so the HMAC authenticates the
  full claim set, not only an intent hash.
- **Issuance only by the kernel.** `issue_lease` mirrors
  `evaluate` (pinned policy, policy failure, directive gate,
  approval gate returning `require_approval`);
  `issue_lease_with_approval` verifies the envelope — and, for
  ceremony actions, the ceremony evidence — through
  `_verify_approval`, the permit path's verification extracted
  verbatim behind a finisher callback so permits and leases share
  one verification implementation. The directive gate mirrors
  `GovernedDirectiveProjection.evaluate` (status, parent status,
  mandate) and records denials through `record_directive_denial`.
  The store records the lease and its directive binding atomically
  at issuance (`lease_issued`), because a lease's binding is
  intrinsic — a permit-style two-step would leave an unbound lease
  in existence, the exact flaw being retired.
- **Verification in spec §4 order** (`consume_lease_command`):
  (1) token signature + full-claim cross-check
  (`_lease_token_claims`); (2) signed expiry at the kernel layer,
  before the store — expiry also journals `lease_fallback`
  (spec §6); (3) presenter proof, always required (a lease is
  never a bearer artifact), over `lease_proof_payload` binding
  token + command hash + presenter + sequence; (4) exact intent
  binding of the command (action, target, payload digest) and the
  signed sequence floor; (5) the store's locked transition:
  directive status/revocation and window, stored expiry (second
  layer), sequence monotonicity, command-budget check-and-debit.
  Kernel-layer refusals never debit the budget. Every refusal is a
  `lease_rejected` audit record with a distinct reason.
- **Refactor.** `evaluate_with_approval` is now a thin wrapper
  over `_verify_approval`; its checks, record shapes, and denial
  reasons are byte-identical (the full suite is the evidence).

## 2. Authority gained, narrowed, or left unchanged

- **Gained:** none. No new principal, action, or resource class is
  authorized. A lease can only ever be minted for an intent the
  existing policy + directive mandate already allow, through the
  existing approval/ceremony verification where those apply.
- **Narrowed:** the class of artifacts that can authorize physical
  actuation shrinks from "any locally constructed dataclass" to
  "a token signed under the kernel secret, recorded at issuance,
  presented by its named device with a valid proof, inside its
  budget, sequence, and validity bounds, under a live directive."
- **Left unchanged:** every permit behavior (issuance, consume,
  presenter binding, budgets, revocation); directive semantics;
  the presenter registry's posture (construction-injected
  deployment configuration, never policy, never runtime-mutable).
- **Refused rather than widened:** leases under a directive
  carrying an aggregate budget are denied
  (`lease_directive_budget_unsupported`). Lease commands debit the
  lease's command budget and never the directive's cumulative
  ceiling; issuing anyway would let actuation escape the ceiling
  silently. That accounting is a PR 2 reconciliation design
  question, not a PR 1 default.

## 3. Canonical state mutations introduced or exposed

- New audit events, all through the existing signed chain:
  `lease_issued`, `lease_command_consumed`, `lease_rejected`,
  `lease_fallback`. Issuance under an approval also appends the
  existing `approval_verified`; issuance denials append the
  existing `decision` / `directive_denial` shapes.
- New store surface on both backends, behind the kernel only:
  `issue_lease` / `consume_lease_command` on the `KernelState`
  protocol. In-memory: a `_leases` map with counters, mutated only
  under the audit lock. SQLite: one additive table, `leases`
  (created by the existing mutating-open DDL block; a legacy
  read-only open reports no table, treats every lease as not
  issued, and issuance on such an open raises — the established
  fail-loud posture). No existing table, column, or record shape
  changes.
- Governed capability boundary: lease state mutates only through
  `GovernanceKernel.issue_lease*` / `consume_lease_command` (and
  the store transitions they call). The Item 3A honest scope
  applies unchanged: this is discipline + evidence inside one
  process, not process-boundary enforcement (that is the service
  layer's, Item 3B).

## 4. Exact success and adversarial evidence

`tests/test_canonical_lease.py` (20 tests), run at this commit;
full suite 1056 OK, skipped=13 (baseline 1036 + 20, no
regressions). Spec §11 acceptance mapping:

- **Test 1 — forged lease:** a locally assembled `Lease` with
  honestly computed digest and a fabricated token fails at the
  signature step (`lease_signature_invalid`); nothing consumes.
- **Test 2 — replay:** a consumed command presented again, and an
  older sequence after a newer one, are refused by the store
  (`lease_replayed`).
- **Test 4 — expiry:** past the signed expiry the command fails
  (`lease_expired`) and a `lease_fallback` record with cause
  `lease_expired` is journaled.
- **Test 6 — command swap:** a same-length substituted payload
  (different digest) under a genuine lease is refused at intent
  binding (`lease_command_mismatch`).
- **Test 11 — modified signed lease (added on external review):**
  a genuine lease with `max_commands` inflated, and separately
  with its expiry extended, via `dataclasses.replace` — both fail
  at the signature step, because the token authenticates the
  original digest and the altered claims recompute to a different
  one. The genuine lease still spends afterwards.
- **Test 12 — wrong presenter (added on external review):** a
  registered device presenting a valid proof *for its own
  identity* is refused (`lease_presenter_mismatch`); the named
  presenter without a proof is refused
  (`lease_presenter_proof_required`); neither attempt debits the
  budget — the genuine command then spends as command one.
- **Test 13 — positive control (added on external review):** a
  genuine lease presented by its named presenter with exact-match
  commands verifies and consumes through its full budget
  (commands_remaining 2, 1, 0). The boundary admits legitimate
  authority, not only refuses.
- Supporting: issuance gating (inactive directive, mandate
  mismatch, unregistered presenter, missing fallback, budgeted
  directive), TTL clamped by `Policy.max_permit_ttl_ns`,
  approval-action leases mint only via the approval path,
  budget exhaustion journals `lease_fallback`, directive
  revocation blocks consumption (`directive_revoked`), sequence
  floor, signed-audit coverage of lease records, SQLite round
  trip with persistence across reopen, SQLite forgery.

## 5. Boundary the evidence does not prove

- No device executed anything. PR 1 is the kernel-side binding
  and its reference verifier; on-device verification in firmware,
  consumption records, and reconciliation are PR 2, and intake /
  boot attestation / safety composition are PR 3.
- Spec §4 step 5's "revocation as last reconciled" is the offline
  device posture; PR 1's verifier is the kernel itself, so
  revocation is checked live in the store transition. The offline
  reading is neither implemented nor claimed.
- Incident channel: PR 1 records lease refusals in the signed
  audit only. Near-miss derivation for lease events is not wired,
  and issue #375's known gap applies to the lease path in kind —
  a bare `require_approval` lease decision appends a `decision`
  record and derives no near-miss, exactly as on the permit path.
  Named here per spec §10 so the physical layer does not silently
  inherit it; closing it is #375's scope, not this PR's.
- A holder of the raw state handle can call the store's
  `consume_lease_command` directly with a genuine token and skip
  the presenter gate — the Item 3A in-process boundary, unchanged
  and not claimed otherwise.
- Many leases under one budget-less directive are bounded per
  lease, not in aggregate; fleet-wide lease accounting is open
  (PR 2 reconciliation is its natural home).

## 6. Claim classification

- The §1–§4 mechanics and the §4 test outcomes: **Verified** at
  this commit by the executed suite.
- The Autonomous failure shape (§1): **Verified** by the
  2026-11-22 diff check at its pins.
- §5's PR 2 / PR 3 contents: **Proposed** (the adopted spec).
- The #375 applicability statement: **Recorded** (issue #375 is
  open; the lease-path parallel is **Inferred** from the shared
  decision-record mechanism).

## 7. Legacy behavior source used without copying its control path

Autonomous v0.3.0's `OfflineMissionLease` contributed the *claim
shapes* — command budget, disconnected window, mandatory safe
fallback, authority binding tuple — as requirements. No
Autonomous code, constructor, or control path is imported or
copied; every mechanism here is canonical's (v3 token discipline,
presenter registry and proofs, approval verification, directive
gate, locked store transitions, signed audit).

## 8. Temporal-transfer evidence

No temporal replay was run for this PR, and none is claimed.
The reused lessons — authenticate at the kernel layer before the
store (PR #355), bind the presenter in the signed token (Item
4B), clamp lifetimes by policy cap (Item 4) — are not asserted as
reusable on the strength of their historical runs; they are
re-proven at this commit by the lease acceptance tests above and
by the unchanged permit suite passing in the same run. Recording
the boundary explicitly per the SOP: at-commit executable
evidence is the whole of the claim.

## 9. Fix cycle — constitutional-survival CI failure (2026-11-22)

The first CI run on this PR failed the `constitutional-survival`
check (13/14 checks green; the unit suite at the same head was
1056 OK). Diagnosis and fix, all executed locally at the PR head
and at the canonical anchor:

- **Reproduction.** `scripts/run_constitutional_mutations.py` at
  the PR head reported 32 killed, **0 survived, 1 invalid**,
  result fail. The invalid mutation was
  `permit_expiry_check_removed`: "expected one mutation anchor,
  found 2". This PR's lease consume path enforces the signed
  expiry with the same line as the permit path
  (`if now_ns >= expires_at_ns:`), so the harness's unique-anchor
  assumption broke and the proof failed closed.
- **Causation: PR-caused (Verified).** At the canonical anchor
  `2726e59` the anchor line occurs exactly once in
  `pulpo/kernel.py` and the same script reports 33/33 killed,
  0 invalid, result pass.
- **Fix, part 1 — harness.** The permit mutation's anchor now
  carries the permit-only comment line that follows it, keeping
  it unique; a new mutation `lease_expiry_check_removed` anchors
  on the lease occurrence (distinguished by the
  `lease_expired` rejection line that follows it), so the lease
  path's kernel-layer expiry check has its own constitutional
  guard, as the permit path and both store layers already did.
- **Fix, part 2 — the new mutation survived, and that was a real
  finding.** With the kernel-layer lease expiry check disabled,
  acceptance test 4 still passed: the store layer refuses the
  expired lease with the *same* reason (`lease_expired`) and
  journals a `lease_fallback` with the same payload shape, so
  the observable evidence trail was identical whichever layer
  fired. The kernel-layer enforcement claimed by spec §4 step 2
  (signed expiry enforced *before the store is consulted*) was
  therefore not independently provable. Test 4 now also asserts
  the layer: a store-layer refusal carries the store
  transition's markers (`directive_status` / `lease_status`) in
  its rejection payload, and the test asserts both are absent —
  the refusal must be the kernel's. No kernel or store code
  changed; the two layers' behavior is unchanged, and their
  evidence is now distinguishable by test.
- **Final results at the fixed head.** Constitutional mutations:
  34 total, **34 killed, 0 survived, 0 invalid, result pass**.
  Full unit suite: **1056 OK, skipped=13** (unchanged counts;
  the fix strengthened one existing test and the harness).
- **Boundary.** The mutation suite now guards the lease kernel
  expiry check. It does not guard the lease store-layer expiry
  checks with lease-specific mutations; the store layers'
  refusal behavior is covered by the acceptance tests, and a
  store-anchor lease mutation pair (mirroring the permit pair)
  is a candidate for PR 2's reconciliation work, not claimed
  here.

## 10. Fix cycle — Codex review findings P1 and P2 (2026-11-22)

Two unresolved Codex threads on this PR, both verified real
against the code before fixing:

- **P1 — the lease approval bound only the intent.** In
  `issue_lease_with_approval`, the signed envelope authenticated
  `intent_hash`, but an `Intent` carries no payload digest,
  command budget, presenter, or deployment; those
  authority-bearing claims were supplied by the caller after
  approval verification. A caller holding one genuine approval
  could therefore choose an unapproved payload digest, an
  arbitrarily large `max_commands`, or a different deployment
  and still receive a genuine consumable lease. This violated
  the AGENTS.md invariant that approval bind the exact context
  it authorizes.
- **P2 — the store transition ignored the sequence floor.** The
  public `KernelState.consume_lease_command` surface, in both
  backends, enforced only `last_sequence`; a first consume with
  a sequence below the lease entry's `sequence_floor` was
  recorded as consumed, creating canonical consumption evidence
  outside the lease's signed sequence bounds. The kernel funnel
  checked the floor (spec §4 step 4); the store — itself a
  governed capability under the AGENTS.md invariant
  `CANONICAL_STATE_MUTATION == GOVERNED_CAPABILITY` — did not.

**Fix, P1.** A new pure function,
`GovernanceKernel.lease_approval_hash(intent, directive, …)`,
computes the approval context digest for a lease issuance: the
intent hash plus every authority-bearing claim the issued lease
will carry — the governing directive's identity (id, version,
hash, parent hash), the payload digest, the command budget, the
disconnected window, the safe fallback, the deployment, the
bound presenter, the boot counter, the sequence floor, and the
requested TTL (the issued expiry is the admission time plus
that TTL, clamped by the policy cap; the clamp only narrows).
`_verify_approval` gains a keyword-only `approval_digest`
parameter: when supplied, the envelope — and any ceremony
evidence — must bind that digest instead of the bare intent
hash, and every denial and audit record of the verification
speaks about that one approval context. `issue_lease_with_approval`
computes the digest from the exact parameters it was called
with and passes it in. The permit path is untouched
(`approval_digest=None` reproduces the prior behavior exactly).
Kernel-minted claims (nonce, issue time) are not approval
material and are not covered. Authority effect: **narrowed** —
an approval now authorizes one exact lease claim set, nothing
choosable after the fact.

**Fix, P2.** Both backends' `consume_lease_command` transitions
now refuse `sequence < sequence_floor` with reason
`lease_sequence_below_floor` (the kernel layer's reason),
checked after the stored expiry and before the replay check,
inside the same atomic transition; the SQLite backend now also
selects the stored `sequence_floor` column. No debit occurs on
the refusal. Authority effect: none gained; the store surface's
acceptance set is narrowed to the lease's signed bounds.

**Evidence.** New tests in `tests/test_canonical_lease.py`:
`LeaseApprovalBindingTests` — a genuine approval for the exact
claims issues a consumable lease (positive control), and each
single-claim alteration under a genuine approval for the
original claims (budget 2→99, presenter, deployment, payload
digest) is refused with `approval_intent_mismatch` and no lease
issued; the pre-existing approval-path issuance test now also
asserts an envelope binding only the bare intent hash is
refused. `LeaseStoreFloorTests` — calling the store surface
directly with a genuine issued token (floor 5): a first consume
at sequence 3 is rejected with `lease_sequence_below_floor` in
both backends, and a first consume at sequence 5 then succeeds
as command one (the refusal debited nothing). Three new
constitutional mutations guard the fixes —
`lease_approval_claims_binding_removed`,
`lease_store_floor_check_removed_inmemory`,
`lease_store_floor_check_removed_sqlite` — each killed by the
tests above. Final results at the fixed head: full unit suite
**1060 OK, skipped=13**; constitutional mutations **37 total,
37 killed, 0 survived, 0 invalid, result pass**.

**Eight-pass deltas for this cycle.** Flip: the approval holder
is now confined to the claim set the authority signed — the
attack the finding describes is the test. Reverse: every claim
on an issued lease is either approval-bound (all caller-supplied
claims), kernel-minted (nonce, issue time), or policy-clamped
(expiry); no fourth source exists. Invert: a lease issued under
claims no approval bound is a failure by definition, and the
`approval_verified` record now carries the lease approval hash,
so what was approved is provable after the fact. Inside-Out:
computing the digest is public and grants nothing — the
authority remains the external signature over an envelope
binding it, exactly as the intent hash works for permits.
Darken: an authority that signs a digest without inspecting the
claims is a presentation-layer property of the approval
ceremony, identical in kind to permit approvals (which sign an
intent hash); the digest makes the claim set committable and
auditable rather than choosable. Lighten: the permit path is
behavior-identical; the store change only narrows acceptance.
Amplify: no new capability or state mutation is introduced —
the digest is a pure function and the floor check adds a
refusal, not a transition. Negate: leaving the approval bound
to the intent alone is the finding itself.

**Boundary.** The digest binds the claim set as *requested*;
claim validation still happens in `_mint_lease` after
verification (an approval spent on malformed claims is consumed
and the issuance denied — the pre-existing posture, unchanged).
The store floor check is guarded by lease-specific mutations;
the store-layer lease *expiry* checks remain guarded only by
the acceptance tests, as recorded in §9.

**Claim classification.** Both findings and both fixes:
**Verified** (reproduced against the code and pinned by the
tests above at the fixed head).

## Adversarial transformation review (eight passes)

- **Flip.** A hostile device presenter holds a genuine lease and
  its key: it can execute only the exact bound command, at most
  `max_commands` times, inside the TTL, under a live directive —
  the authorized envelope, nothing wider. A hostile caller without
  the key stops at the proof gate. A hostile state writer can
  insert rows, but a row without a kernel-signed token is
  unspendable through the kernel (the #355 layering, inherited).
- **Reverse.** Unauthorized actuation needs one of: a forged or
  altered artifact (signature/digest gate), a stolen token *and*
  presenter key (bounded by budget, expiry, revocation), a replay
  (store sequence), a payload swap (digest binding), an approval
  replay (shared one-use approval store), or issuance under a
  revoked/inactive directive (gate at issuance and at consume).
  The earliest unreachable point is issuance itself: no governed
  record, no artifact.
- **Invert.** A command that actuated without a
  `lease_command_consumed` record is a failure by definition here;
  outcome correctness never launders an unrecorded transition —
  the audit is the success criterion, and PR 2 reconciliation is
  designed against exactly these records.
- **Inside-Out.** The kernel mints and verifies, as with permits;
  nothing in the lease path lets a governed agent register a
  presenter, alter policy, or mint outside the evaluate paths.
  The presenter registry is construction-time deployment
  configuration, as in Item 4B.
- **Darken.** Worst credible bounded case: a compromised presenter
  with a maximum-budget lease repeats the one bound command up to
  its budget inside its TTL. The blast radius is the issued
  envelope — one action, one target, one payload — and revocation
  closes it at the next consume.
- **Lighten.** The change is additive: new dataclasses, two
  issuance verbs, one consume verb, two store methods per backend,
  one new table, new audit events. The single edit to existing
  behavior, the `_verify_approval` extraction, is verified
  behavior-identical by the full suite in the same run.
- **Amplify.** Aggregation is the real risk and is answered in
  §2: aggregate-budgeted directives refuse leases outright, and
  every issuance is itself a governed, audited act (approval
  actions additionally consume a one-use envelope). Per-lease
  budgets under a budget-less directive remain the stated §5
  boundary.
- **Negate.** The smaller alternative — one permit per command —
  cannot express a disconnection window, a command budget, a
  sequence, or a safe fallback, and would leave no device-side
  artifact to verify offline; it also re-mints a bearer artifact
  per command. The lease is the smallest artifact that carries
  the physical semantics, and it reuses the permit machinery
  rather than duplicating it.

Decision: continue. Smallest next proof: PR 2's reconciliation
round-trip — device consumption records reconciled against this
PR's `lease_issued` / `lease_command_consumed` chain.

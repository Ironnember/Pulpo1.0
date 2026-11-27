# Change record addendum — verification-only signer atomicity (Finding 7)

Date: 2026-11-27. Branch: `audit-signer-2026-11-27`. Addendum to
`CHANGE_RECORD_2026-11-27_ED25519_AUDIT_SIGNER.md` (same branch).
Authorization: Austin Irvan, 2026-11-27 11:32 MST ("Authorize fix
passes for all 8"), covering the Codex P1 findings verified in
`~/workspace/goals/pulpo1-0-development/hidden_files/p1-verification-2026-11-27.md`.
Finding 7 is the one addressed here: Codex review comment 4720484606
on `pulpo/state.py`, "Reject writes before using a verification-only
signer."

## 1. Invariant / failure addressed

No canonical state mutation without its signed audit record. A
`CompositeAuditSigner` installed verification-only (verifiers, no
signer) raises `RuntimeError` on every `sign()`. In
`InMemoryKernelState`, each mutating transition recorded its
mutations FIRST and appended the signed audit record LAST, so the
raise landed after the mutation and nothing rolled it back.
Reproduced at the verification head and re-verified at this fix's
starting head (709ec95; `pulpo/state.py` byte-identical between the
two): `consume_permit` raised, yet the permit stayed in `_spent`
(a later consume returned `permit_rejected`), the budget bucket
stayed debited by exactly the binding's cost, and the audit chain
was unchanged — governance state changed with no signed evidence,
irreversibly for the permit.

## 2. Authority gained, narrowed, or left unchanged

Unchanged. The fix narrows no capability and grants none; it removes
a route by which canonical state could change *without* the governed
evidence the transition exists to produce. No signer behavior
changes: a verification-only composite still cannot sign, and every
transition attempted under one still raises the same RuntimeError —
it now raises against an unchanged state.

## 3. Canonical state mutations introduced or exposed

None introduced. The change is confined to `InMemoryKernelState` in
`pulpo/state.py`: one helper, `_require_audit_signing_available()`,
which probes the configured signer (a trial `sign()` whose result is
discarded and recorded nowhere) and lets its refusal raise, called
at the first-mutation point of each of the seven mutating
transitions — `issue_permit`, `bind_permit_to_directive`,
`consume_permit`, `issue_lease`, `consume_lease_command`,
`activate_directive`, `revoke_directive` — inside the same locked
sequence, after the transition's read-only checks and before any
canonical container is written. Signing availability is a property
of the signer's configuration, not of the record: every signer
behind the `AuditSigningKey` seam either signs any record hash or
none, so a signer that passes the probe signs the transition's
appends, and one that cannot sign refuses the transition against an
unchanged state. All non-mutating behavior is preserved exactly:
replay refusals and validation errors return/raise before the probe,
exactly as before.

The alternative mechanism — snapshot the containers on entry and
roll back on failure — was built first and REJECTED on evidence: it
broke `tests/test_directive_parent_activation_race.py`, whose
subject performs a complete, separately-audited `revoke_directive`
nested inside an `activate_directive` that then refuses. A blanket
outer rollback erased the nested transition's mutation AND its
signed audit record — destroying signed evidence is the very failure
this fix exists to prevent. Establishing availability before
mutation has no such interaction: nested transitions probe (or
don't) on their own terms.

`append` / `append_unique` needed no change: they build the signed
record before touching the chain, so a signing raise already leaves
them unmutated.

Sibling-path audit (each mutating path that appends signed records,
checked firsthand):
- In-memory `consume_permit` — SHARED the defect (reproduced);
  fixed.
- In-memory `issue_permit` — SHARED: approval/ceremony replay guards
  and the issued permit were recorded before the signed appends;
  fixed.
- In-memory `bind_permit_to_directive` — SHARED: the binding was
  recorded before its append; fixed.
- In-memory `issue_lease` — SHARED: replay guards and the lease
  entry preceded the appends; fixed.
- In-memory `consume_lease_command` — SHARED: the entry's
  commands_used / last_sequence were debited before the
  `lease_command_consumed` append; fixed.
- In-memory `activate_directive` / `revoke_directive` — SHARED (the
  Codex thread's directive claim, verified firsthand): the directive
  record / revoked flag was written before the append; fixed.
- SQLite backend, all transitions (`consume_permit`, `issue_permit`,
  `bind_permit_to_directive`, `issue_lease`,
  `consume_lease_command`, `activate_directive`, `revoke_directive`)
  — SAFE, not fixed: each runs inside a `BEGIN IMMEDIATE`
  transaction on the connection context manager, so the same signing
  raise rolls every mutation back. Verified by execution for
  `consume_permit` and `issue_permit` (raise, chain unchanged, the
  same consume succeeds once the signer is removed); the remaining
  paths share the identical transaction shape.

Governed capability boundary: unchanged — all mutations remain
behind the same state-backend seam; no second ledger or writer.

## 4. Exact success and adversarial evidence

- Reproduction (`/tmp/repro_finding7.py`, the verification pass's
  script): pre-fix — consume raised, permit in `_spent`, budget
  debited 10, chain 3 → 3, second consume False. Post-fix — consume
  raises the same RuntimeError, permit NOT in `_spent`, budget `{}`,
  chain 3 → 3, and the second consume (signer removed) returns True
  with `permit_consumed` recorded.
- New regression file `tests/test_verification_only_signer_atomicity.py`
  (9 tests): one byte-identical-state test per fixed in-memory
  transition (full canonical-container snapshot compared before and
  after the raising call), plus two SQLite disposition tests. All 7
  in-memory tests FAIL on pre-fix code and PASS after; the 2 SQLite
  tests pass both before and after, pinning the disposition.
- Full suite: see PR description for before/after totals; behavior
  with a working signer is unchanged — every pre-existing test
  passes unmodified.

## 5. Boundary the evidence does not prove

- The probe establishes availability at the transition's first
  mutation. A hypothetical signer whose `sign()` succeeded on the
  probe hash yet failed on a later record hash would still land
  mutations before its append; no signer behind the seam behaves
  that way (failure is configuration-determined — a missing signer
  half — never record-determined), and the regression shape in §4
  pins the actual failure class. Recorded as a boundary, not
  silently generalized past it.
- Atomicity here is refusal-before-mutation, not crash recovery —
  the in-memory backend has no durability to recover to.
- The live gate flip to Ed25519 remains out of scope, exactly as in
  the parent change record.

## 6. Claim classification

Verified (executable evidence at this head): the defect, the fix,
the sibling dispositions, and the regression results in §4.
Recorded: the authorization and the verification report's contents.
Inferred: none relied on.

## 7. Legacy behavior source

The SQLite backend's own transaction discipline (BEGIN IMMEDIATE +
context-manager rollback) is the control path whose semantics the
in-memory fix mirrors; it is matched in behavior, not copied in
mechanism. No other legacy source used.

## 8. Temporal-transfer evidence

No relevant historical checkpoint exists: the defect was introduced
with the signer seam this same branch adds, so there is no earlier
canonical state carrying it to replay against. The pre-fix behavior
is instead pinned directly by the fail-first regression runs in §4.
Recorded explicitly per the repo rule; no temporal proof is
manufactured.

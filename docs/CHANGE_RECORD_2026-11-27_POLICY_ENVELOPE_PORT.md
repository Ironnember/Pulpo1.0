# Change Record — Policy Envelope Port (Door-Two ◆2) — 2026-11-27

## Authorization

Austin Irvan, 2026-11-27: door-two ◆2 ruling "Adopt and port the fork's
envelope now" (~06:32 MST), with his explicit proceed on the flagged fresh
clone (~06:35 MST). Door-two ◆1 (same morning) is a hard bound on this
port: NULL-expiry is rejected everywhere. Signer custody is a separate,
still-open decision and is **out of scope**: every key exercised here is a
clearly-labeled test double; no production or human signer was generated,
chosen, or implied, and no custody semantics changed.

## 1. The invariant / failure addressed

Before this change, a canonical kernel constructed with an older `Policy`
kept governing indefinitely: no authenticated current policy head existed
anywhere in canonical. The signed, versioned `PolicyEnvelope` (schema
`pulpo.policy-envelope.v1`, ported from Pulpo-Preview @ 72bd43a) is that
head: verified at kernel construction against the already-pinned issuer
trust, chained by version + previous policy hash, and recorded in the
canonical audit chain at acceptance (`policy_head_accepted`), so a stale
or forked policy is refused at construction instead of governing.

## 2. Authority gained, narrowed, or left unchanged

- **Narrowed:** a kernel can no longer silently govern under a stale or
  forked policy once envelopes are in force on its state — stale version,
  same-version/different-hash, and broken-chain constructions are refused
  (`PolicyEnvelopeError`).
- **Unchanged:** the envelope carries no authority of its own; it proves
  the pinned issuer issued exactly this policy version. Approval,
  ceremony, presenter, and permit authority paths are untouched. Policies
  that never adopt envelopes construct and hash exactly as before
  (genesis policy hashes are byte-identical; the full pre-existing suite
  passes unmodified).
- **No human signing credential** was created, read, derived, invoked,
  enrolled, exported, or impersonated (repo invariant). Test signers are
  same-process HMAC doubles labeled test-only, the same pattern canonical
  already uses for approval/ceremony fixtures.

## 3. Canonical state mutations introduced or exposed

One new audit event, appended through the existing `KernelState.append`
path with canonical columns only: `policy_head_accepted` (payload:
policy_version, policy_hash, previous_policy_hash, envelope_hash,
authority_id, verifier_id, key_id, deployment_id, trust_hash — never the
signature). No new router, executor, ledger, memory system, audit source,
or authority plane. No state.py change: the recorded head is read back
from the audit chain itself.

## 4. Exact success and adversarial evidence

- Baseline at base commit b1cea2f15870c79cc101537ffadce9285b7a7c47:
  `python -W error -m unittest discover -s tests` → **Ran 1166 tests, OK
  (skipped=13)**.
- After the port: **Ran 1189 tests, OK (skipped=13)** — 23 new tests in
  `tests/test_policy_envelope.py`, zero regressions.
- New tests cover: valid envelope accepted and governing (permit binds to
  the versioned hash, single-use consume); head recorded in the audit
  chain; bad/missing signature refused; wrong version, previous hash,
  policy hash, and trust binding refused; envelope without pinned trust
  refused; envelope without an approval verifier refused; missing envelope
  refused for a versioned policy and once a head is recorded; stale
  refused after the head advances; broken chain refused; same-version/
  different-policy refused as a fork; identical-head reopen is a restart,
  not a fork; ceremony path passes under a signed policy; replayed
  ceremony evidence refused; ceremony key equal to the authority key
  refused at policy construction; no-expiry forms refused (◆1).

## 5. The boundary the evidence does not prove

- Verification is proven against HMAC test doubles and the repo's
  Ed25519/P-256 verifier interfaces, **not** against a production issuer:
  no real policy envelope has ever been issued, because signer custody is
  undecided. Nothing here proves a deployment will adopt envelopes, only
  that adoption is mechanical and refusal is fail-closed once claimed.
- The gate (Phase 2) demonstrates envelope verification with labeled TEST
  envelopes; production policy at the gate remains configuration until
  Austin's custody decision.

## 6. Claim classification

- Port completeness, test counts, and refusal behavior at the branch
  commit: **Verified** (executed at the exact commit).
- Fork behavior at 72bd43a as the port source: **Recorded** (read from
  the fork tree; its own suite was not re-run for this change).
- Production readiness of signed policy: **Proposed** (awaits custody).

## 7. Legacy behavior source used without copying its control path

Pulpo-Preview (Diegel's fork) is the behavior source for the envelope
mechanism. Its `PolicyEnvelope` dataclass and the kernel verification /
head-acceptance logic were ported and reconciled (below); the fork's
`policy_hash_for`, state backend, and control paths were not copied —
canonical's own hash construction, state layer, and ceremony gate carry
the mechanism here.

## 8. Temporal-transfer evidence

No historical-checkpoint replay was performed: the change is additive
mechanism, and the applicable historical evidence is the unchanged
genesis-hash guarantee, proven by the unmodified pre-existing suite
(1,166 tests) passing at the branch commit. No lesson is claimed as
generally reusable beyond this statement.

## Reconciliation table — fork vs canonical → decision

| # | Point | Fork (Preview .5) | Canonical before port | Decision |
|---|-------|-------------------|------------------------|----------|
| 1 | Envelope required when | Pinned trust + approval verifier coexist → envelope mandatory | No envelope concept | **Neither verbatim.** Required exactly where a chain is claimed or exists: versioned policy (v>1) or a head already recorded in state; any supplied envelope is fully verified. Genesis + no recorded head keeps legacy construction, so existing deployments (incl. the merge gate, whose production policy source is still config pending the custody decision) adopt by an explicit act and cannot then silently drop it. |
| 2 | Policy version fields | `Policy.version`, `Policy.previous_policy_hash` | Absent | **Fork mechanism, canonical defaults:** fields added with genesis defaults (1 / None) + chain-shape validation in `__post_init__`. |
| 3 | Policy hash construction | `policy_hash_for()` binds `permit_ttl_ns` unconditionally, version above genesis | Kernel property; binds `max_permit_ttl_ns` only when non-default; no version binding | **Canonical won on TTL** (its hash inputs unchanged); **fork won on version binding** (version + previous hash bind only above genesis, preserving genesis hashes byte-for-byte). Property extracted to `policy_hash_for(policy)` with identical payload construction. |
| 4 | TTL field | `permit_ttl_ns`, default 5 min, no ceiling | `max_permit_ttl_ns`, default 4 h, hard ceiling (`PERMIT_TTL_CEILING_NS`) | **Canonical won; not ported.** Canonical's ceiling is the ◆1-congruent form: expiry is mandatory and bounded. |
| 5 | NULL / no-expiry semantics | NULL `expires_at_ns` = never expires (fork kernel line 1279) | No NULL-expiry semantics anywhere | **Canonical won (◆1 hard bound).** Nothing with no-expiry semantics crossed over; every lifetime in the ported regime is a mandatory positive integer, and the ported tests assert the no-expiry forms are unrepresentable/refused. |
| 6 | Ceremony gate | `CeremonyEvidence` + separate-key check in fork ceremony.py (275 lines) | Canonical ceremony.py (359 lines) is field-identical for evidence and stricter in validation; replay via `ceremony_replay_reason` | **Canonical already congruent; nothing ported.** The port only proves the existing canonical gate operates under a signed policy (test) and that ceremony key == authority key is refused. |
| 7 | Recorded head storage | Audit-chain event via existing `append` | n/a | **Fork won** — same design adopted; no state.py change needed in canonical either. |
| 8 | Digest helper | `_is_sha256` in fork kernel | `_is_digest` in canonical kernel | **Canonical won** (existing helper reused). |
| 9 | Provenance-required actions | `Policy.provenance_required_actions` exists in fork Policy | Absent | **Not ported** — outside the ◆2 mechanism list; noted as a remaining fork divergence for the reconciliation agenda. |
| 10 | Policy head in audit payload | Records trust bindings, not the signature | n/a | **Fork won** — signature never enters the audit chain. |

## Files

- `pulpo/authority.py` — `PolicyEnvelope` dataclass added (schema
  `pulpo.policy-envelope.v1`).
- `pulpo/kernel.py` — `Policy.version` / `previous_policy_hash`;
  `policy_hash_for()`; `PolicyEnvelopeError`; `policy_envelope`
  construction parameter with verification + head acceptance;
  `policy_head` property.
- `pulpo/__init__.py` — exports `PolicyEnvelope`, `PolicyEnvelopeError`.
- `tests/authority_support.py` — `signed_policy_envelope` test helper.
- `tests/test_policy_envelope.py` — 23 tests (new).

## Addendum — service-boundary presenter wiring (door-two ◆4), same branch

Austin's ◆4 ruling (2026-11-27 ~06:34 MST): "Binding-required is the
default — wire the gate as v2 with the envelope port." The canonical half
of that wiring is in this branch; the gate deployment half lives in
`~/workspace/pulpo-gate/` (uncommitted deployment directory) and is
reported with it.

- `pulpo/service.py`: the evaluate / evaluate_with_approval /
  evaluate_locked_target verbs accept an optional `presenter`; the
  consume verb accepts optional `presenter` + `presenter_proof`; the
  client mirrors all four. Omitted fields reproduce the exact pre-binding
  protocol (proven by test against a policy without binding required).
  The presenter a request asserts is now a **claimed principal**
  (`_claimed_principals`), so a credential cannot assert a presenter
  outside its bound principal set — refused at the boundary, before the
  kernel.
- This retires the shipped 3B bound recorded in the gate README ("the
  consume verb carries no presenter fields — addendum A5"), which was
  the reason `require_presenter_binding` could not be enabled behind
  the service boundary.
- New tests: `tests/test_service_presenter_binding.py` (6 tests) —
  bound issue + proven consume over the loopback boundary, replay
  refused, unbound issuance refused, unproven consumption refused,
  wrong-key proof refused (and the permit unburned), foreign presenter
  refused at the boundary, legacy bearer flow unchanged when binding
  is not required.

# Change Record — Envelope Schema v2: Dual Control + Veto Registry — 2026-11-27

## Authorization

Austin Irvan, 2026-11-27: signer-custody decision (~07:08 MST) and its
fallback-clause amendment (~07:13 MST), recorded in the "SIGNER CUSTODY —
DECIDED" section of
`~/workspace/goals/pulpo1-0-development/files/door-two-briefing-2026-11-26.md`.
This branch is stacked on PR #418 (branch `envelope-port-2026-11-27`,
head `97b666bcdacafd3321ad20253419f6d015b9f7d3`) and extends its v1 port;
#418 itself is undisturbed. Door-two ◆1 is a hard bound throughout: no
NULL/no-expiry semantics anywhere, including the veto. Every key exercised
here is a clearly-labeled test double; **no production or human key was
generated, chosen, or implied**, and the genesis ceremony that enrolls the
real human keys is a production step this build prepares but does not
perform (repo invariant: no governed agent may create, read, derive,
invoke, enroll, export, or impersonate a human signing credential — the
enrollment *bindings* here are public key ids and fingerprints only).

## 1. The invariant / failure addressed

Under #418's v1 envelope, one issuer key advances policy: whoever holds
that key — or compromises it — rewrites the rulebook alone, and no one
holds a governed halt. The custody decision replaces that shape: policy
authority is held jointly and can be stopped. Envelope schema v2
(`pulpo.policy-envelope.v2`) requires signatures from **two distinct
enrolled signer keys**; a third distinct key holds a **policy-layer
veto** (targeted kills, permanent and non-delegable; a standing halt with
a mandatory expiry, renewable); a fourth distinct key, the Operations
Manager **fallback**, may perform standing acts only behind a chained
24-hour silence trigger. A chain's era is explicit: the first recorded
head fixes v1 or v2 rules for that chain, and cross-era construction is
refused, so a v2 chain can never silently downgrade to v1 single-signer.

## 2. Authority gained, narrowed, or left unchanged

- **Narrowed (the point of the change):** policy-advance authority drops
  from one signer (v1) to **two-of-two enrolled signers, subject to a
  veto neither signer holds**. Neither signer alone can advance policy;
  a stolen signer key alone is insufficient; the signers jointly cannot
  route around a live veto — an advance that would alter the veto
  arrangement is refused while any applicable veto stands, and the only
  exits are the veto key lifting/letting it lapse or re-genesis (out of
  scope here).
- **Gained (bounded, attributed):** the veto key gains a halt-only
  capability — it can refuse policy movement, never enact it. The
  fallback key gains a *timed, standing-only* share of that halt:
  set/renew/lift after a chained request plus 24 hours without a
  veto-holder act. Targeted kills never delegate, and the veto holder's
  acts supersede fallback acts whenever they land (registry state is
  derived in chain order; the latest standing act is the state).
- **Unchanged:** approval, ceremony, presenter, and permit authority
  paths; v1 envelope verification and head acceptance for v1-era chains
  (the pre-existing suite passes unmodified); policies that never enroll
  a dual-control trust keep their exact pre-v2 policy hash (the trust
  binds into the hash only when present, the established opt-in pattern).

## 3. Canonical state mutations introduced or exposed

All mutations go through the existing `KernelState.append` audit path
with canonical columns only; no new router, executor, ledger, memory
system, audit source, or authority plane. Signatures never enter the
chain.

- `policy_head_accepted` (v2 form): additionally records `schema`,
  `signer_key_ids`, `veto_key_id`, `fallback_key_id`. The `schema` field
  is the era marker the cross-era refusals read; v1 payloads carry no
  `schema` key and are read as v1.
- Five veto-registry events, appended only by the governed intake
  `GovernanceKernel.record_policy_veto` (signature verified against the
  actor's enrolled verifier before append; replayed records and
  nonces refused; the registry state machine enforced at intake):
  `policy_veto_targeted`, `policy_veto_standing_set`,
  `policy_veto_standing_renewed`, `policy_veto_standing_lifted`,
  `policy_veto_fallback_requested`. Payloads record the actor's key id,
  so every fallback act is chained and attributed to the fallback key.
- Registry state is *derived* from the chain in order on every read
  (`_policy_veto_state`), never stored separately: there is no second
  source of truth to substitute.

Governed capability boundary: `record_policy_veto` is the sole write
route into the registry, and envelope acceptance
(`_accept_policy_head_v2`) is the sole point where the registry is
consulted — an advancing head is refused there if its exact hash is
targeted or a standing veto is active. Reopening an identical head
appends nothing and is a restart, not an advance; the veto halts
advances, not governance under an already-accepted head.

## 4. Exact success and adversarial evidence

- Baseline at #418 head `97b666bcdacafd3321ad20253419f6d015b9f7d3`:
  `python -W error -m unittest discover -s tests` → **Ran 1195 tests,
  OK (skipped=13)**.
- After this change: **Ran 1230 tests, OK (skipped=13)** — 35 new tests
  in `tests/test_policy_envelope_v2.py`, zero regressions; the #418 v1
  tests pass unmodified (v1 chains verify under their era).
- Dual control: dual-signed genesis accepted and governing; dual-signed
  advance advances the head; single-signature envelope refused; same key
  signing twice refused at envelope construction; unenrolled third key
  refused; one bad signature of the two refused; missing v2 envelope
  refused for a versioned dual-control policy and once a head is
  recorded; v1 envelope offered to a dual-control policy refused as an
  era mismatch, and vice versa on recorded chains in both directions.
- Targeted veto: dual-signed advance refused once its hash is targeted,
  and still refused after a standing veto is set and lapses (permanence);
  intake refuses bad signatures, replays, and duplicate targets.
- Standing veto: blocks all advances, including one recorded before
  genesis acceptance; an expired standing veto no longer blocks;
  renewal extends (advance refused inside the renewed window, accepted
  after it); the veto key's lift clears it; an advance that changes the
  enrolled veto key is refused while the veto stands and accepted once
  lifted; a standing veto without a positive TTL is unrepresentable
  (◆1); the intake state machine refuses double sets, renewals of
  nothing, renewals that do not extend, and lifts of nothing.
- Fallback: lift attempted at 23h of chained silence refused and chains
  nothing; lift at 25h accepted, attributed to the fallback key, and the
  advance proceeds; an act with no chained request refused; an act after
  the veto holder acted post-request refused (her act kills the
  trigger); fallback attempt to set a targeted veto refused outright;
  the fallback machinery (request, standing freeze, lapse) never touches
  a targeted kill; the veto holder's re-set supersedes a fallback lift,
  and her lift supersedes a fallback set.
- Genesis separation: veto key equal to a signer (by id or by
  fingerprint under another id) refused; fallback colliding with a
  signer or the veto refused; the two signers colliding refused; a
  ceremony key colliding with any dual-control key refused at policy
  construction.

## 5. The boundary the evidence does not prove

- Verification is proven against HMAC test doubles implementing the
  repo's verifier protocol, **not** against the production human keys:
  no real envelope has been dual-signed, no real veto has been cast, and
  the genesis ceremony (four human-held hardware keys, recovery-key
  enrollment cross-sealed) has not been performed. This build proves the
  mechanism and its refusals, not an enrollment.
- The fallback trigger judges silence by chained timestamps from the
  kernel's trusted clock at intake; it proves 24 hours of *chain time*
  with no veto-holder act chained, not that the veto holder was in fact
  unreachable — unreachability is exactly what the record deliberately
  refuses to self-certify.
- The 72-hour standing-veto TTL named in the custody decision is a
  genesis-time policy choice for the humans; the mechanism enforces any
  mandatory positive TTL and does not itself pick the number.
- Service-boundary carriage of v2 envelopes and veto records (the gate)
  is not in this change; the kernel mechanism lands first, as the v1
  port did before its ◆4 wiring.

## 6. Claim classification

- Mechanism behavior, test counts, and refusal evidence at the branch
  commit: **Verified** (executed at the exact commit).
- The custody decision and fallback clause as the design authority:
  **Recorded** (Austin's rulings of 2026-11-27, filed in the door-two
  briefing).
- Production readiness of dual-control policy: **Proposed** (awaits the
  human genesis ceremony and gate wiring).

## 7. Legacy behavior source used without copying its control path

The v1 envelope port (#418) is the direct base: its verification,
head-acceptance, and audit-recording shapes are extended, not replaced,
and its reconciliation posture (an envelope is required exactly where a
chain is claimed or exists, now judged with both signer verifiers
configured) is preserved for the v2 era. No fork control path was
copied; the dual-control and veto semantics have no fork source — they
are the custody decision's own design.

## 8. Temporal-transfer evidence

No historical-checkpoint replay was performed: the change is additive
mechanism on a branch whose base is itself unmerged, and the applicable
historical evidence is the era guarantee — v1 chains constructed at the
#418 head verify identically at this commit, proven by the unmodified
pre-existing suite (1,195 tests) passing alongside the new tests. No
lesson is claimed as generally reusable beyond this statement.

## Files

- `pulpo/authority.py` — `EnrolledKeyTrust`, `DualControlTrust`,
  `EnvelopeSignature`, `PolicyEnvelopeV2`, `PolicyVeto` added.
- `pulpo/kernel.py` — `Policy.dual_control_trust` (hash-bound when
  enrolled; ceremony-vs-dual distinctness at policy construction);
  constructor parameters `policy_envelope_v2`,
  `policy_signer_verifiers`, `veto_verifier`, `fallback_verifier` with
  enrolled-binding match checks; `_verify_policy_envelope_v2`;
  `_accept_policy_head_v2` / `_append_policy_head_v2`; cross-era guards
  in both accept paths; the veto registry (`_policy_veto_state`,
  `_refuse_if_vetoed`, `_fallback_trigger_satisfied`,
  `_veto_record_authorized` as the single authority seam,
  `record_policy_veto`); `PolicyVetoError`; `FALLBACK_SILENCE_NS`.
- `pulpo/__init__.py` — exports for the new types and `PolicyVetoError`.
- `tests/authority_support.py` — `EnrolledHmacTestVerifier`,
  `dual_trust_for`, `dual_signed_policy_envelope`, `signed_policy_veto`
  test helpers.
- `tests/test_policy_envelope_v2.py` — 35 tests (new).

## Addendum — stack update + Codex P1 fix pass (PR #421), 2026-11-27

Authorized by Austin in words, 2026-11-27 11:32 MST: "Authorize fix
passes for all 8." Findings verified firsthand in
`~/workspace/goals/pulpo1-0-development/hidden_files/p1-verification-2026-11-27.md`
(PR #421 section; repro at verification time: /tmp/repro_421_f456.py).

**Stack update first.** PR #418's fix pass advanced
`envelope-port-2026-11-27` to `57f51e1e61eee7fc8e8e9b84dc862786761a72ea`
(Findings 1–3: execution-time policy-head revalidation, atomic
`append_unique` policy-head admission, missing-envelope refusal without
an approval verifier, and the read-only `latest_record` state
primitive). That branch was merged into this branch (merge commit,
merge-only, no rebase). One textual conflict, in `pulpo/kernel.py`'s
construction-time missing-envelope chain: this branch's dual-control v2
refusal and #418's generalized refusal both rewrote the same `elif`
chain. Resolved by composing them — the era-specific dual-control
branch first, #418's generalized branch second — so neither regime has
a gap the other was written to close. One semantic composition follow-up
was also required: #418's `_require_current_policy_head()` consulted
only the v1 envelope slot, so every v2 kernel refused its own governed
actions once its v2 head was recorded (1 suite error,
`test_dual_signed_genesis_is_accepted_and_governs`); the revalidation
now compares the recorded head against whichever envelope era the
kernel holds. Suite after the stack merge + composition: **Ran 1257
tests, OK (skipped=13)** (pre-stack baseline on this branch: Ran 1230,
OK, skipped=13).

**Finding 4 — missing signer enforcement (thread
PRRT_kwDOUBywws680jv2, `pulpo/kernel.py`).** The mandatory v2-envelope
refusal was gated on `len(self._policy_signer_verifiers) == 2`, so with
0 or 1 signer verifiers a version-2 dual-control policy constructed
with `policy_head=None` and `evaluate()` issued permits under the
unsigned policy. Fix: dual control is mandatory, not a count
coincidence — the refusal now fires wherever a dual-control policy is
versioned (`version > 1`) or a head is recorded, regardless of how many
signer verifiers are configured; under-configuration fails closed at
construction. It composes with #418's generalized refusal (this branch
is checked first for dual-control policies; no double refusal, no gap).

**Finding 5 — noncanonical envelope identity / targeted-veto evasion
(thread PRRT_kwDOUBywws680jv6, `pulpo/authority.py`).**
`PolicyEnvelopeV2.envelope_hash` hashed the raw dataclass with
signatures in tuple order, while the signing payload sorts signer key
IDs and verification compares signatures as a set — so reversing the
two valid signatures produced a different envelope identity, and a
targeted veto recorded against the original ordering did not bind the
reversed presentation (verified end-to-end evasion). Fix:
`envelope_hash` is computed over a canonical serialization that sorts
the signatures by signer key ID, the same normalization the signing
payload uses. Hash-change scope: an already-canonical (sorted)
presentation keeps its exact pre-fix hash (verified by direct
comparison); only non-canonical orderings change identity, and they
change to the canonical one.

**Finding 6 — fallback authority inheritance (thread
PRRT_kwDOUBywws680jv-, `pulpo/kernel.py`).** `_policy_veto_state`
projected a chained fallback request down to its timestamp alone,
discarding the `key_id` and `trust_hash` the chained payload carries,
so after a trust rotation enrolled a replacement fallback key F2, F2
could act on F1's matured 24-hour wait with no request of its own.
Fix: the projection retains `key_id` and `trust_hash`, and
`_fallback_trigger_satisfied` additionally requires the operative
request to be the currently enrolled fallback key's own request under
the current dual-control trust. A replacement key starts its own 24h
clock; the current key acting on its own matured request under the
current trust is unchanged (the pre-existing fallback tests are the
evidence).

**Regression evidence.** New class `PolicyEnvelopeV2P1RegressionTests`
in `tests/test_policy_envelope_v2.py` (4 tests): under-configured
signer verifiers (0 and 1) refused for a versioned dual-control policy;
envelope hash identical across signature orderings; the end-to-end
targeted-veto evasion scenario (reversed presentation now refused by
the same targeted veto); replacement fallback key refused on the
predecessor's wait, then accepted on its own matured request. All 4
tests (5 failures counting both Finding-4 subtests) FAIL on the
post-stack pre-fix tree and PASS after the fix. Final suite: **Ran
1261 tests, OK (skipped=13)**. Behavior for correctly configured
dual-control operation (2 verifiers, canonical signature order, own
matured fallback request) is unchanged — the pre-existing v2 tests
pass unmodified.

**Authority / boundary.** Authority is narrowed only (three fail-open
gaps closed); no new canonical state mutation, event, or authority
plane is introduced — the Finding 6 change reads payload fields the
chain already records. Claim classification: fix behavior and counts
**Verified** (executed at the branch commits); the findings themselves
**Recorded** (Codex threads + the verification report above). No
temporal replay: the applicable historical evidence is the
pre-existing suite passing unmodified alongside the new regressions.

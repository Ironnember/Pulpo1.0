# Decision: v9.1 policy-head corrections do not apply to canonical; they gate any #115–#117 port

Status date: 2026-11-11
Canonical inspection point: `6120f1bc88d314a7e3b9915814d8bd98f9bba6d1` (main)
Classification of this record: **Verified** where it cites source inspection and
test/probe runs executed at the inspection point; **Recorded** where it relies
on the Atomic Head packet verification record; **Inferred** where marked.

## The question

The v9.1 work produced two corrections against the Preview line's PR #117
(signed, versioned policy envelopes with a recorded policy head):

1. a **stale-kernel guard** — a kernel must re-check the live recorded policy
   head at permit issuance, consumption, and revalidation, not only at kernel
   construction; and
2. **atomic policy-head admission** — recording a new policy head must
   validate the expected previous head and append atomically under the state
   backend's lock/transaction, so two conflicting heads at the same version
   cannot both be admitted.

Both defects were reproduced on the Preview parent `3dcefdb`, and the
corrections were independently verified as scoped on that parent (27/27
patched; the same set fails exactly the five load-bearing tests on the
unpatched parent, both backends) — **Recorded**:
`validation record, Atomic Head packet, 2026-11-10`.

Step 0 asked whether these corrections apply to canonical Pulpo1.0 as it
stands, ahead of any decision to port Preview PRs #115–#117.

## Ruling

**The corrections do not apply to canonical's current code. There is nothing
to patch, and no canonical candidate branch is created from them.**

Canonical does not contain the mechanism the defects attack. The ruling is
therefore a **gating condition on the future #115–#117 port** (below), not a
code change.

## Evidence

### 1. The #117 mechanism is absent from canonical — Verified

Every element of the Preview mechanism surface was checked against canonical
at the inspection point (`pulpo/kernel.py` blob `7109819a…`,
`pulpo/state.py` blob `0eb39c7a…`). **0 of 12 are present:**

- `pulpo.authority.PolicyEnvelope` — absent (canonical's `ApprovalEnvelope`
  is the approval artifact of the pre-existing authority path, a different
  type; canonical has no signed *policy* envelope)
- `pulpo.PolicyEnvelope` export; `pulpo.kernel.PolicyEnvelopeError`;
  `pulpo.kernel.policy_hash_for` — absent
- `GovernanceKernel.__init__` parameter `policy_envelope`;
  `GovernanceKernel._verify_policy_envelope`, `_recorded_policy_head`,
  `_accept_policy_head`, `policy_head` property — absent
- `append_policy_head_atomic` on both state backends (the corrections' own
  API) — absent
- `tests.authority_support.signed_policy_envelope` — absent

Structural absences, from full reads of canonical `kernel.py` and `state.py`:

- Canonical `GovernanceKernel` takes its `Policy` as a frozen
  constructor-injected object. `policy_hash` is a computed property of that
  in-memory object. No policy is ever read from, or written to, state.
- Canonical state has **no policy table and no policy-admission event**
  (SQLite schema: `permits`, `approvals`, `ceremony_evidence`, `directives`,
  `permit_directives`, `audit`; audit events contain no `policy_head_accepted`
  or any policy record). Nothing can advance a "current policy" inside
  canonical state, so there is no recorded head for a kernel to be stale
  against, and no admission path in which conflicting heads could race.

### 2. The packet's discriminating tests cannot run on canonical — Verified

`tests/test_v91_atomic_policy_head.py` and `tests/test_v91_live_head_guard.py`
from the packet fail at import against canonical at the inspection point:

- `ImportError: cannot import name 'PolicyEnvelopeError' from 'pulpo'`
- `ImportError: cannot import name 'policy_hash_for' from 'pulpo.kernel'`

The tests do not fail on canonical; they are **inexpressible** on canonical,
because the mechanism they discriminate does not exist here.

### 3. Canonical's analogue already revalidates at consequence time — Verified

Canonical's runtime authority-transition mechanism is the **directive**
system (versioned, parent-chained, revocable). Probes executed at the
inspection point, both backends:

- A permit bound to a directive consumes while the directive is active and
  is **denied after revocation** (`consume_permit` re-checks directive
  status, parent status, and time window live at consume). The
  stale-authority outcome the guard corrects on Preview does not occur on
  this path.
- Conflicting concurrent admission of the same `(directive_id, version)`
  with two different hashes: 300 barrier-synchronized rounds (in-memory),
  2,000 rounds under a forced 1µs thread-switch interval (in-memory), and
  100 rounds over two SQLite connections to one file — **zero** conflicting
  admissions; on SQLite exactly one activation succeeded per round and the
  loser raised. Canonical state holds exactly one hash per
  `(directive_id, version)`, so a displaced hash reads back as a version
  mismatch and fails closed; there is no state shape in which two live
  heads coexist.

For completeness, the transplanted stale-kernel pattern (two kernels with
different `Policy` objects over one shared state) was also probed: the
second kernel consumes the first kernel's permit and the first keeps
issuing, and no policy event exists in the audit to contradict either —
because canonical `Policy` is per-kernel construction configuration, not
admitted state. **Inferred:** sharing one state backend across kernels with
different policies is not a supported deployment shape on canonical
(`state.py`: the backend "is storage for that kernel"), and no canonical
invariant is stated over it; the Preview defect violated an invariant that
#117 itself created and canonical never adopted.

### 4. Baseline at the inspection point — Verified

Full canonical suite at `6120f1b`: **463 tests run, OK (1 skipped)**, in a
clean clone.

## Gating condition (the operative decision)

Any future port of Preview PRs #115–#117 — signed policy envelopes and the
recorded policy-head mechanism — into canonical:

1. **must land together with the Atomic Head corrections** (live-head
   re-check at issuance/consumption/revalidation, and atomic
   expected-previous-head admission), never before them and never without
   them. Porting unpatched #117 imports two reproduced defects into
   canonical main: the stale-kernel bypass and the concurrent
   conflicting-head admission, both reproduced on the Preview parent with
   the audit chain left valid.
2. must re-verify on the ported tree: the packet's discriminating tests
   must fail against the ported-but-uncorrected tree and pass against the
   corrected tree, on both state backends, with the full canonical suite
   green.
3. carries its own change record under `AGENTS.md`, including the boundary
   the evidence does not prove (below).

## What the corrections do not close

The **direct-writer bypass class** is untouched by these corrections, on
Preview and on canonical alike. A writer with raw access to canonical state
storage can still alter the records `consume_permit` trusts; the corrections
govern kernel-mediated admission only, and neither they nor canonical main
at the inspection point perform audit-chain reconciliation of backend state
at consumption. Independent writer/issuer custody — who may hold a
state-writer capability at all, per the `CANONICAL_STATE_MUTATION ==
GOVERNED_CAPABILITY` and `NO_WRITE_ROUTE != NO_WRITE_CAPABILITY`
invariants — remains an open, separate roadmap item. This decision must not
be cited as closing it.

## Adjacent candidate, not ruled on here

A canonical-native candidate exists locally (unpushed) at
`candidate/v9.1-policy-epoch` (`fa9cfa1`, based on `f084863`, whose
kernel/state blobs are byte-identical to the inspection point's). It
addresses a different, canonical-shaped requirement set — audit-chain-
reconciled consumption, chain-held time, a lifetime trust pin, and a
consequence-time recheck at dispatch (`recheck_permit` /
`permit_governing_status`). Its reported 460-test pass is **Recorded**, not
re-verified here. This decision neither admits nor rejects it; advancing it
requires its own evaluation at the current canonical head.

## Change record (per AGENTS.md)

1. **Invariant/failure addressed:** none in code. This record prevents a
   future port from importing two reproduced authority defects (stale
   policy-head use; conflicting policy-head admission) by making their
   corrections a precondition of the port.
2. **Authority gained, narrowed, or left unchanged:** unchanged. This
   record grants no capability and admits no code.
3. **Canonical state mutations introduced or exposed:** none. Documentation
   only.
4. **Exact success and adversarial evidence:** sections 1–4 above (symbol
   absence enumeration 0/12; packet-test import failures at the inspection
   point; consume-time revalidation and admission-atomicity probes, both
   backends; full suite 463 OK, 1 skipped).
5. **Boundary the evidence does not prove:** behavior of any future ported
   tree; the fa9cfa1 candidate's claims (Recorded only); concurrent
   in-memory directive admission beyond the probed schedules; any
   deployment that shares one state backend across differently-configured
   kernels.
6. **Claim classification:** Verified (canonical source, probes, suite at
   the inspection point); Recorded (packet verification on Preview;
   candidate results); Inferred (unsupported deployment shape, marked
   above); Proposed (the gating condition as policy going forward);
   Unknown (none material left open by this ruling).
7. **Legacy behavior source used without copying its control path:** the
   Preview Atomic Head packet was used as evidence input only; no Preview
   code or control path is copied by this record.
8. **Temporal-transfer evidence:** no relevant historical checkpoint
   exists — the #117 mechanism never existed at any canonical commit, so
   there is no canonical checkpoint against which the corrections could be
   replayed. This absence is itself the core evidence of section 1.

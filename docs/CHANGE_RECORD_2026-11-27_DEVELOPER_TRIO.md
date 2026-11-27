# Change record — 2026-11-27 — Developer trio: integration prompt, permit gate, evidence verification

Branch `dev-trio-2026-11-27` (local; not pushed). Three additions:
`pulpo/permit_gate.py` (+ exports), `docs/INTEGRATION_PROMPT.md`,
`docs/AI_ASSISTANT_INTEGRATION.md`, `docs/evidence-and-audit.md`,
`tests/test_permit_gate.py`, `tests/test_evidence_verification.py`.

## 1. Invariant or failure addressed

Two integration-layer failures, neither in the kernel:

- **Refusal-routing at the call site.** Nothing in the package gave a
  developer (or an AI coding assistant writing the integration) a
  single fail-closed gate, so each integration re-decided what a
  denial, an error, or a missing permit meant — the exact places where
  approval gets inferred from the absence of an error and refusals get
  retried around. The gate makes one behavior canonical: the action
  runs only after a literal `allow` with a permit AND a literal `True`
  consume, and everything else raises.
- **Undocumented evidence path.** The audit chain, its signing
  coverage, and its offline verification existed as mechanisms but not
  as one accurate third-party description; the gap invites both
  under-claiming (verification needs the vendor — it does not) and
  over-claiming (a published verification key — none exists, because
  the signer is symmetric HMAC). `docs/evidence-and-audit.md` states
  both sides with the boundary named.

## 2. Authority gained, narrowed, or left unchanged

**Unchanged.** The gate mints nothing, holds no signing material,
alters no policy, and grants no capability. It calls the kernel's
existing `evaluate` / `consume` and raises on every non-allow outcome.
Presenter proofs are produced by a caller-supplied callback; the
presenter's key never enters the gate.

## 3. Canonical state mutations introduced or exposed

**None new.** The gate's calls append exactly the records the kernel
already appends for direct `evaluate` / `consume` callers
(`decision`, `permit_consumed`, `permit_rejected`). No new writer, no
new route, no new ledger, no state-backend change. The evidence
snippets are read-only against snapshot copies.

## 4. Exact success and adversarial evidence

- `tests/test_permit_gate.py` (17 tests): allow path executes and
  consumes exactly once; policy denial and disallowed action raise
  with the action unrun; `require_approval` outcome raises (the gate
  does not mint approval-path permits); expired permit raises with
  `permit_expired` in the audit; wrong-intent spend raises and does
  not burn the permit; second use of the same permit raises;
  evaluate/consume backend errors raise as `kernel_error`; a consume
  returning `False` raises; an `allow` decision carrying no permit
  raises (approval is never inferred); presenter-bound allow path
  executes; wrong presenter proof raises; a presenter configured
  without a proof provider refuses locally.
- `tests/test_evidence_verification.py` (8 tests): both published
  snippets executed against real kernel artifacts — snapshot
  verification passes with correct record counts; a tampered payload
  fails closed (`StateIntegrityError`); chain recomputation passes on
  real records and detects a payload edit and a mid-chain removal; a
  signed chain verifies with the deployment's signer
  (`signed_records == total_records`) and fails closed with a wrong
  secret or with no signer.
- Full suite at this branch (`python -W error -m unittest discover
  -s tests`): **Ran 1191 tests — OK (skipped=13)**, against the
  b1cea2f baseline of 1166 OK (skipped=13). The 25 new tests are the
  two files above; no pre-existing test changed result.

## 5. Boundary the evidence does not prove

- The tests prove the gate's behavior against the in-process kernel
  API and test doubles for backend failure. They do not prove any
  production deployment routes its consequences through the gate — a
  control not on the execution path governs nothing.
- The integration prompt's effect on any given assistant session is
  unproven; assistant-written code still requires the standard
  adversarial review.
- Offline verification proves internal consistency (and, with the
  deployment's secret, signature validity) of the records shown. It
  does not prove completeness without independently held anchors, and
  it does not prove any decision was wise.

## 6. Claim classification

- Gate and verification mechanisms: **Verified** at this commit, as
  scoped by the tests above.
- Integration prompt and guide: **Proposed** guidance relying on
  Verified kernel behavior.
- Well-known verification-key location
  (`/.well-known/pulpo-evidence.json`): **Proposed, not implemented** —
  no code serves or consumes it, and no public key exists to publish
  while the audit signer is symmetric HMAC.

## 7. Legacy behavior source

The *shape* of two patterns came from outside this repo, with no code
copied and no control path adopted: A2SPA's published
`require_authorized_result` helper (an allow-check that throws unless
explicitly authorized) and its copy-paste "prompt for your AI coding
assistant" integration page — both identified in the 2026-11-27
competitive research on AI Modularity / A2SPA. The gate's semantics
are Pulpo's own (permit + consume through the canonical kernel), and
Snippet 1 of the evidence doc reuses this repository's existing
snapshot-verification pattern from
`examples/wire_authorization/check_evidence.py`.

## 8. Temporal-transfer evidence

No relevant historical checkpoint exists for these surfaces: the gate,
the prompt, and the evidence document are new at this commit, and no
historical Git state contains an earlier version of them whose
behavior a lesson could transfer from or regress against. The gate
wraps the kernel API as it exists at this commit only; nothing about
it is claimed to transfer to historical kernel states.

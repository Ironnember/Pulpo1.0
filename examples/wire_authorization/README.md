# Wire authorization — reference deployment

A reference integration that puts a payment-shaped consequence — a wire
transfer — behind the canonical Pulpo governance kernel, end to end:
proposal, verified approval, one-use permit, consumption, effect, and an
evidence checker that reconciles the effect record against the audit
trail from the artifacts alone.

**Claim classification: Verified, as scoped** — the scenario tests in
`tests/test_wire_authorization_example.py` are executable evidence at
this commit for the behaviors they assert, against the kernel API at
this commit. Everything about real-world deployment in this document is
**Proposed** unless a test asserts it.

Counterparties and amounts in the tests are illustrative
(`operator:treasury` paying `acme-corp` $250.00, and similar).

## ⚠️ Mock rail warning

The "rail" in this example (`rail.py`, `MockPaymentRail`) is a **mock**.
It moves no money, holds no account, talks to no bank or network, and
cannot pay anyone in any configuration. All it does is append one JSON
line — marked `"rail": "MOCK-NO-REAL-FUNDS", "mock": true` — to a local
file. If you are looking for a payment integration, this is not one, and
adapting the mock into one is out of scope for this example: a real rail
is a separate, consequential integration with its own custody, limits,
and reconciliation obligations.

## The governed flow

```
propose ──► Intent(action="initiate_wire", resource="wire:<payee>",
                   cost=<amount_cents>, principal, session)
                │  intent_hash binds every field exactly
                ▼
execute(intent, envelope)
                │  GovernanceKernel.evaluate_with_approval:
                │  policy check, then envelope verified against the
                │  pinned authority trust (authority / verifier / key /
                │  deployment / trust hash, principal, session, intent
                │  hash, policy hash, TTL, replay, signature)
                ├── any denial ──► WireResult(deny, …), rail untouched
                ▼ allow + one-use permit
          GovernanceKernel.consume(permit, intent)
                │  re-checks the exact intent binding at consequence
                │  time — and, for directive-bound permits, the live
                │  directive status
                ├── False ──► WireResult(deny, …), rail untouched
                ▼ True
          MockPaymentRail.transfer(transfer_id = "wire-" + intent_hash)
                ▼
          anchor seam (WS1): witness the settled audit head, if built
```

Two entry points share the consume-then-effect tail:

- `WireAuthorizationService.execute(intent, envelope)` — the primary
  path, for approval-minted permits.
- `WireAuthorizationService.execute_with_permit(intent, permit)` — for
  permits issued outside the call, in this example permits minted
  through `GovernedDirectiveProjection` under a standing directive and
  bound to it at issue. A directive revoked between issuance and
  execution kills the permit at consume time; the revocation scenario
  in the tests exercises exactly that path.

The service holds the rail privately and exposes no public route to it,
so within this example's public API a transfer is reachable only
through the governed path. Code that holds the rail object, the ledger
file, or the state backend directly is the known direct-writer class —
outside the governed path, as with every Pulpo deployment — and the
evidence checker below is the reconciliation for the artifacts such a
writer would leave inconsistent.

The kernel audit trail is the canonical evidence. The mock ledger is
the *external effect record* (what the outside world says happened),
not a second governance ledger; the checker's job is to prove the two
agree, exactly.

### Policy used by the scenario tests

- `allowed_actions = {"initiate_wire", "activate_directive", "revoke_directive"}`
- `approval_actions` = the same set, under a pinned `AuthorityTrust`
- `max_cost = 100_000_00` ($100,000.00) — a policy ceiling, not a
  payment limit product feature

Approvals in the tests are minted with the test-only HMAC verifier in
`tests/authority_support.py`. That material is a test double, never a
deployment credential.

## Running the scenario tests

From the repository root:

```sh
python -W error -m unittest tests.test_wire_authorization_example -v
# full suite:
python -W error -m unittest discover -s tests
```

Scenarios: happy path (with the evidence checker run against the
produced artifacts); unauthorized payee (approval for payee A spent on
payee B); amount substitution ($100.00 approved, $999.00 attempted);
replay (same envelope twice, and direct permit re-consumption);
revocation before execution (directive-bound permit, directive revoked,
execution denied); and a negative control in which an intent-blind
state double *does* let the amount-substituted execution transfer —
proving the denials come from the kernel's binding, not the harness.

## Running the evidence checker

The service writes two artifacts: the kernel's SQLite state file and
the mock rail's JSON-lines ledger (their paths are chosen by whoever
constructs `SQLiteKernelState` and `MockPaymentRail`; the scenario
tests create both in a temporary directory). Point the checker at any
such pair:

```sh
python -m examples.wire_authorization.check_evidence \
    --state /path/to/state.db --ledger /path/to/ledger.jsonl
# optionally, when WS1 anchors exist:
python -m examples.wire_authorization.check_evidence \
    --state /path/to/state.db --ledger /path/to/ledger.jsonl \
    --anchors /path/to/anchors.jsonl
# if the deployment used a different principal / session:
    --principal operator:treasury --session-id default   # (the defaults)
```

The checker loads the audit from the state file, verifies the chain by
reusing `GovernanceKernel.verify_audit`, reconstructs each transfer's
exact intent (payee and amount from the ledger; principal and session
from the flags above, which default to this example's values), and
requires an exact 1:1:1 correspondence between ledger transfers,
`permit_consumed` records, and authorization evidence — an
`approval_verified` record for approval-minted permits, or the complete
directive authorization chain (activation, permit binding, and a
consumption recording the directive live) for directive-issued ones —
in both directions, so a transfer with no governed consumption *and* a
governed consumption with no transfer (a phantom effect) both fail.
The checker never opens the state file writable: it probes it
read-only, fails files that are not kernel state databases at all, and
verifies a snapshot copy, leaving the artifact byte-identical. It prints a
JSON verdict — `{ok, failures, transfers_checked, anchored}` — and
exits 0 iff `ok`. See the module docstring in `check_evidence.py` for
the full method, the closed-world classification it uses, and its
stated boundary.

## Anchor seam (WS1)

Sibling PR #352 (`feat/audit-anchor`) adds `pulpo.anchor` with
`anchor_state(state, store, *, clock=None, signer=None)` and
`FileAnchorStore`: an external witness that pins the audit chain's head
hash and record count outside the kernel, closing the documented
tail-truncation / delete-and-rehash gap in the unkeyed audit chain.

This example does **not** copy that module. `WireAuthorizationService`
accepts optional `anchor_store` / `anchor_signer` arguments and, after
a settled transfer, attempts the anchor call behind
`try/except ImportError`:

- **In this build** `pulpo.anchor` is absent, so settled results record
  `anchoring: "unavailable-in-this-build"`, and the checker's
  `anchored` verdict field is `"unavailable"` when no anchors file is
  supplied (supplying one is a failure — this build cannot verify it).
- When #352 lands, the same code records `"anchored"` after a
  successful witness (or `"not_configured"` if no store was supplied,
  `"anchor_failed"` if the witness call raised — recorded, never
  silently dropped, and never undoing the settled transfer: anchoring
  is observation, not governance).

## Audit growth on denials

A denial is not "nothing happened" (`NO_PERMIT != NO_GOVERNED_EFFECT`).
A denied `evaluate_with_approval` appends its `approval_rejected` and
`decision` records; a denied consume appends `permit_rejected`. That
growth is a governed effect — evidence production — append-only, with
no authority change and no capability accumulation, and it is what lets
the checker (and an incident review) account for every attempt. It is
classified separately from governed external consequences (mock
transfers) throughout the tests.

## Non-goals

- **Not a payment product.** No real rails, no bank connectivity, no
  money movement, no payment operations of any kind.
- **No production key custody.** Test approvals use a test-only HMAC
  double; nothing here enrolls, stores, or handles a real signing key,
  and no governed agent may create or impersonate a human signing
  credential.
- **No new authority plane.** This example adds no router, executor,
  policy engine, or ledger of its own; the canonical kernel, its state
  backends, and its audit trail remain the only governance truth, and
  the mock ledger is an external effect record reconciled against them.
- **No deployment claim.** Nothing here proves a production system is
  governed unless that system actually routes its consequences through
  this kernel path — a control not on the execution path governs
  nothing.

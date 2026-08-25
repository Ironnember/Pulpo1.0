# Pulpo Current State

Status date: 2026-08-24

## Canonical source

`Ironnember/Pulpo1.0` on `main` is the sole source of truth for current Pulpo code, tests, architecture, governance, and forward development.

`Iron-Ember/pulpo` and other earlier Pulpo artifacts remain historical evidence and pattern sources. Documents dated before this canonicalization may accurately describe the source of truth at that earlier time, but they do not override this file for current status.

## Proven in this repository

The dependency-free kernel and its executable tests currently prove these in-process semantics:

- incomplete intents fail closed;
- unknown actions fail closed;
- negative or above-policy declared cost fails closed;
- configured high-impact actions return `require_approval` unless the external
  verifier path validates a signed approval envelope;
- allowed intents receive permits bound to the exact intent;
- a permit can be consumed successfully only once, including after reopening a
  configured SQLite state database;
- using a permit for a different intent fails;
- mutation of an in-memory audit record is detected by audit-chain verification;
- approval IDs, approval nonces, issued and spent permits, and audit records are
  atomically persisted by the optional SQLite kernel-state backend;
- persisted audit-chain tampering blocks kernel bootstrap.

The standard verification command is:

```bash
python -m unittest discover -s tests -v
```

Passing CI is evidence only for the commit and environment identified by that workflow run.

The bounded-commerce tests additionally prove in-process semantics for exact
domain/registrar/owner/privacy/upsell/price/renewal constraints, a USD 30 pilot
ceiling, complete request-and-quote hash binding, in-memory budget reservation,
one attempted execution per order, charge reconciliation, and separation of
authorization, payment, delivery, acceptance, and continuing value.

The authority tests prove a configured external-verifier path whose signed
envelope binds authority, approval, session, principal, exact intent, exact
policy, nonce, and expiry. The caller approval boolean is absent for every
kernel; session is part of the intent; and the authorization caller cannot
override the kernel time used for expiry. Invalid signatures, malformed
envelopes, binding mismatch, expiry, replay, missing verifier, and verifier
failure deny. The restart proof shows approval-ID, nonce, and spent-permit replay
remain denied after the original process closes and a new kernel opens the same
SQLite state.

## Trust boundary

The current kernel is an in-process governance semantics proof. It does not yet prove:

- independently authenticated human approval—the envelope verifier contract is
  implemented, but no production signer/passkey service or isolated authority
  principal is deployed;
- durable commerce budget reservations across restart;
- OS-enforced filesystem, network, process, or secret isolation;
- hostile-code containment;
- cumulative or metered billing enforcement;
- durable budget reservation or payment-rail enforcement—the commerce budget
  account is in memory and the registrar adapter remains a protocol/test double;
- distributed identity or multi-principal signer separation;
- protection of the SQLite state file from a hostile worker, host compromise,
  rollback to an older valid snapshot, disk failure, or unproven backup/restore;
- an external production workload, independent evaluation, or customer outcome;
- production readiness.

External language may say **governance kernel with local restart-safe replay
state**, **external-verifier approval-envelope contract**, **one-use durable
permit with SQLite configured**, and **restart-verified tamper-evident audit
chain**. It must not claim independent human authority or protected storage
until signer, verifier, clock, trust bootstrap, and host isolation are deployed
and tested. Stronger claims require separate implementation and evidence.

## Forward-development rule

Legacy mechanisms may enter this repository only one behavior at a time. Each must be rewritten behind the current interface, supplied with adversarial tests, and documented with the boundary the tests do not cover.

Do not bulk-import the legacy repository, generated evidence, local runtime state, machine-specific scripts, task backlogs, simulated UI state, or CI workarounds.

## Priority proof sequence

1. Keep the minimal kernel and dependency-free CI reproducible.
2. Deploy independently authenticated authority, trusted time, and verifier
   bootstrap outside the governed worker boundary.
3. Extend the now-proven kernel replay persistence to durable commerce budget
   reservation without creating another ledger.
4. Enforce host filesystem, network, process, and secret boundaries.
5. Run one external workload through the complete Pulpo sequence and publish an inspectable evidence bundle.

Pulpo earns broader authority only after the preceding boundary is supported by executable denial and success evidence.

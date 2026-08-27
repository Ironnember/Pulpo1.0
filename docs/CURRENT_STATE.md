# Pulpo Current State

Status date: 2026-08-26

## Canonical source

`Ironnember/Pulpo1.0` on `main` is the sole source of truth for current Pulpo code, tests, architecture, governance, and forward development.

`Iron-Ember/pulpo` and other earlier Pulpo artifacts remain historical evidence and pattern sources. Documents dated before this canonicalization may accurately describe the source of truth at that earlier time, but they do not override this file for current status.

## Proven in this repository

The dependency-free kernel and its executable tests currently prove these in-process semantics:

- incomplete intents fail closed;
- unknown actions fail closed;
- negative or above-policy declared cost fails closed;
- configured high-impact actions return `require_approval` unless the external
  verifier path matches policy-pinned public trust and validates a signed v2
  approval envelope;
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
ceiling, complete request-and-quote hash binding, budget reservation, one
attempted execution per order, charge reconciliation, and separation of
authorization, payment, delivery, acceptance, and continuing value. An optional
transactional SQLite budget store preserves reservation, attempted-order,
reconciliation, receipt-hash, and spent state across restart and prevents two
workers from over-reserving the same pilot ceiling.

The authority tests prove a configured external-verifier path whose signed
envelope binds authority, verifier, key, deployment, trust configuration,
approval, session, principal, exact intent, exact policy, nonce, issue time, and
expiry. Policy binds the public-key fingerprint, algorithm, and maximum approval
lifetime. The caller approval boolean is absent for every kernel; session is
part of the intent; and the authorization caller cannot override kernel time.
Invalid signatures, malformed envelopes, key or deployment substitution, future
issue time, excessive lifetime, expiry, clock rollback, replay, missing or
untrusted verifier, and verifier failure deny. A reviewed optional Ed25519
verifier contains public material only. The restart proof shows approval-ID,
nonce, and spent-permit replay remain denied after the original process closes
and a new kernel opens the same SQLite state.

The authority deployment architecture is now owner-authorized and recorded:
one founder-controlled single-device hardware WebAuthn credential, a separate
offline recovery-only hardware credential, an external authority service,
service-owned time and protected monotonic state, privacy-minimized Pulpo audit
hashes, and separate full signature bundles. This is a selected architecture,
not evidence that the boundary has been deployed.

The repository now contains a separately packaged executable authority-service
reference and a worker request/poll client. Their deterministic and HTTP-level
acceptance tests are **Verified**. The reference uses only test/in-memory state,
evidence, signer, and WebAuthn fixtures; no production RP, credential, service
key, protected state, or external evidence store exists. Independent deployed
human authority therefore remains **Blocked**. See
[the authority service proof](AUTHORITY_SERVICE_PROOF.md).

## Trust boundary

The current kernel is an in-process governance semantics proof. It does not yet prove:

- independently authenticated human approval—the pinned asymmetric verifier
  contract is implemented, but no production signer/passkey service, protected
  bootstrap, or isolated authority principal is deployed;
- OS-enforced filesystem, network, process, or secret isolation;
- hostile-code containment;
- cumulative or metered billing enforcement;
- payment-rail enforcement—the registrar adapter remains a protocol/test double;
- rollback-resistant commerce storage—the SQLite budget database is durable
  across ordinary restart but is not protected from a worker that can delete,
  replace, write, or roll it back;
- distributed identity or multi-principal signer separation;
- protection of the SQLite state file from a hostile worker, host compromise,
  rollback to an older valid snapshot, disk failure, or unproven backup/restore;
- an external production workload, independent evaluation, or customer outcome;
- production readiness.

External language may say **governance kernel with local restart-safe replay
state**, **pinned asymmetric approval-envelope contract**, **one-use durable
permit with SQLite configured**, and **restart-verified tamper-evident audit
chain**. It must not claim independent human authority or protected storage
until signer, verifier, clock, trust bootstrap, and host isolation are deployed
and tested. Stronger claims require separate implementation and evidence.

## Forward-development rule

Legacy mechanisms may enter this repository only one behavior at a time. Each must be rewritten behind the current interface, supplied with adversarial tests, and documented with the boundary the tests do not cover.

Do not bulk-import the legacy repository, generated evidence, local runtime state, machine-specific scripts, task backlogs, simulated UI state, or CI workarounds.

## Priority proof sequence

1. Keep the minimal kernel and dependency-free CI reproducible.
2. Implement and deploy the selected independently authenticated authority,
   trusted time, monotonic state, and verifier bootstrap outside the governed
   worker boundary.
3. Protect the now-proven kernel and commerce SQLite state from worker mutation,
   host rollback, and unproven backup or recovery behavior.
4. Enforce host filesystem, network, process, and secret boundaries.
5. Run one external workload through the complete Pulpo sequence and publish an inspectable evidence bundle.

Pulpo earns broader authority only after the preceding boundary is supported by executable denial and success evidence.

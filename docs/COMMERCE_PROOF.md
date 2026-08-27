# Bounded Autonomous Commerce Proof

## Decision

Pulpo's first external-consequence demonstration will be one low-risk digital
procurement transaction: an approved domain purchase under a hard $30 ceiling.

The proof sequence is:

```text
request -> discover -> quote -> authorize -> execute -> verify -> reconcile -> learn
```

Healthcare, governed science, quantum resources, and physical execution remain
later consequence tiers. Commerce is first because it combines real money,
credentials, a counterparty, changing external state, measurable delivery, and
bounded failure in one understandable transaction.

## Implemented contract proof

`pulpo/commerce.py` now provides a dependency-free domain-purchase contract that
is subordinate to the canonical `GovernanceKernel`:

- a request fixes acceptable domains, purchase and renewal ceilings, registrar,
  owner reference, privacy, prohibited upsells, expiration, and principal;
- the pilot ceiling cannot exceed 3,000 cents;
- a quote is assessed deterministically with a distinct denial reason;
- the exact resulting order is hashed into the normal Pulpo intent resource;
- the order binds SHA-256 hashes of the complete request and complete quote;
- a budget account reserves the exact quoted amount before permit use;
- an optional transactional SQLite implementation preserves reservation,
  attempted-order, reconciliation, receipt-hash, and spend state across restart;
- concurrent workers sharing that database cannot over-reserve the pilot ceiling;
- the normal kernel issues and consumes the one-use permit;
- the executor marks the order attempted before the external call so an
  uncertain result must be reconciled instead of blindly retried;
- credentials are opaque references, never credential material;
- a registrar adapter must receive and enforce the exact maximum charge;
- payment, delivery, independent verification, acceptance, and continuing value
  remain separate evidence fields;
- reconciliation consumes an attempted reservation, validates a SHA-256 receipt
  identifier, rejects overcharge, and releases any unspent amount;
- the proof bundle projects the existing kernel audit tip and validity rather
  than creating a second ledger.

The executable tests cover $30.01, unapproved domains and registrars, excessive
renewal price, prohibited upsells, expiration, owner substitution, missing
privacy, invalid credential references, order substitution, permit reuse,
duplicate execution, excessive provider charge, incomplete delivery, and the
separation of authorization, payment, delivery, acceptance, and value.

## Invariant

```text
AUTHORIZED != PAID != DELIVERED != ACCEPTED != VALUABLE
```

A receipt can prove payment without delivery. Registrar output can identify a
registration without independently proving ownership or configuration.
Independent ownership, duration, privacy, and DNS verification can prove
acceptance without proving continuing value.

## Live transaction gate

No live registrar adapter, account credential, or payment method belongs in this
repository yet. The commerce tests use the configured external-verifier
envelope path. Boolean approval has been removed, the session is derived from
the request, and expiry uses the kernel's bootstrapped clock. The test verifier
is not independently authenticated human authority.

The first real purchase remains blocked until all of these are present:

1. a human approval envelope generated outside the governed worker boundary and
   bound to the exact order hash, policy hash, principal, expiry, and nonce;
2. a registrar-scoped credential unavailable to the planning and building
   principals;
3. a payment rail or virtual card that enforces the exact transaction ceiling,
   rather than merely detecting an overcharge after payment;
4. an adapter with discovery/quote and purchase operations separated;
5. an independent ownership, registration-period, privacy, and DNS verifier;
6. durable permit state that prevents replay across restart;
7. an evidence bundle signed or checkpointed by an independent verifier.

Until these gates pass, this tranche proves the commerce contract and denial
semantics in process. It does not claim a completed autonomous purchase.
Quote assessments are not yet durable denial receipts; they must be written
through Pulpo's canonical evidence ledger before the live pilot. Permit
consumption remains in process. `SQLiteBudgetAccount` proves restart-durable
reservation, attempted-order, reconciliation, receipt-hash, and spend state
only when its database path is trusted and protected. It is not a bank, card
network, payment rail, rollback-proof financial ledger, or evidence ledger.

## name.com CORE adapter boundary

The optional `NameComCoreAdapter` binds discovery to CORE v1's literal
`domains:checkAvailability` registration path, rejects premium and acquisition
types, converts USD prices to exact cents, pins the production and sandbox
origins, keeps API secrets behind an injected credential-owning transport, and
uses the exact order hash as the provider idempotency key.

The sandbox path can exercise Create Domain without real charges and converts
the returned order and `totalPaid` object into registrar evidence. Production
fails closed before Create Domain. CORE v1 exposes no per-request maximum-charge
field; for standard non-premium registrations its documentation instructs the
client to omit `purchasePrice`, and `totalPaid` can include VAT. Observing an
overcharge afterward is reconciliation, not hard payment-rail enforcement.
Production therefore remains blocked until name.com or a separately governed
payment surface can enforce the exact authorized maximum before charge.

Recorded API basis: [CORE overview](https://docs.name.com/api/v1/overview),
[Check Availability](https://docs.name.com/api/v1/reference/domains/check-availability),
[Create Domain](https://docs.name.com/api/v1/reference/domains/create-domain),
and [Get Order](https://docs.name.com/api/v1/reference/orders/get-order).

## First live acceptance standard

The initial transaction is successful only if the exact approved domain is
registered at the approved registrar, the actual charge and renewal terms stay
within policy, the required owner receives the asset, privacy is enabled, DNS is
in an accepted state, the capability cannot be reused, the charge reconciles,
and an independent verifier can reproduce the proof bundle.

Failure at any step must remain visible as failure. Payment alone must never be
promoted to delivery, acceptance, or value.

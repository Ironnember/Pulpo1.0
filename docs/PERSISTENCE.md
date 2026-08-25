# Restart-safe kernel state

## Implemented proof

`SQLiteKernelState` is a storage backend for the existing `GovernanceKernel`.
It does not evaluate policy, issue independent authority, route execution, or
maintain a second evidence history.

One SQLite transaction records a verified approval ID and nonce, its issued
permit, the `approval_verified` record, and the allow decision. Permit
consumption atomically marks that permit spent and appends the corresponding
audit record. Every other decision continues to append to the same canonical
hash chain.

At bootstrap, `GovernanceKernel` verifies every persisted audit link and record
hash. Invalid persisted evidence raises `StateIntegrityError` before the kernel
can evaluate or authorize an intent.

## Executable restart evidence

`tests/test_persistence.py` closes the first SQLite connection, constructs a new
state backend and kernel over the same database, and proves:

- the consumed approval ID is rejected;
- a new approval ID with the consumed nonce is rejected;
- the reopened unspent permit rejects a substituted intent, succeeds once for
  its exact intent, and remains unusable after another restart;
- the canonical audit chain continues from its pre-restart head;
- modified persisted audit payload fails closed at the next bootstrap;
- approval consumption, permit issuance, and their audit evidence commit in one
  database transaction.

Run the complete proof with:

```bash
python -W error -m unittest discover -s tests -v
```

## Boundary still open

This is a local process-restart and transaction proof. It does not prove that
the database file is unavailable to a hostile worker, protected from rollback
to an older internally valid snapshot, replicated, backed up, recoverable after
disk failure, or operated by an independent trust domain. The commerce budget
account remains in memory. Signer identity, verifier/bootstrap integrity, and
host isolation remain separate unproven boundaries.

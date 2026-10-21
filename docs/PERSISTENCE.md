# Restart-safe kernel state

## Implemented proof

`SQLiteKernelState` is a storage backend for the existing `GovernanceKernel`.
It does not evaluate policy, issue independent authority, route execution, or
maintain a second evidence history.

One SQLite transaction records a verified approval ID and nonce, its issued
permit, the `approval_verified` record, and the allow decision. Permit
consumption atomically marks that permit spent and appends the corresponding
audit record. Every other decision acquires the same immediate SQLite write
lock before reading the audit tip, so overlapping local connections cannot fork
the canonical hash chain.

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
- malformed persisted evidence raises `StateIntegrityError` at bootstrap;
- approval consumption, permit issuance, and their audit evidence commit in one
  database transaction;
- a failed permit-consumption audit write rolls back the spent marker;
- overlapping SQLite connections serialize audit-tip selection.

Run the complete proof with:

```bash
python3 -W error -m unittest discover -s tests -v
```

## Boundary still open

This is a local process-restart and transaction proof. It does not prove that
the database file is unavailable to a hostile worker, protected from rollback
to an older internally valid snapshot, replicated, backed up, recoverable after
disk failure, or operated by an independent trust domain. The commerce budget
account remains in memory. Signer identity, verifier/bootstrap integrity, and
host isolation remain separate unproven boundaries.

## Conservative SQLite performance changes

Approval issuance selects the canonical audit tip once, builds the approval and
allow records in order, and inserts both within the existing `BEGIN IMMEDIATE`
transaction. The tip is local to that transaction; it is never reused after
commit. Each governed transition still commits independently with
`synchronous=FULL`. No journal mode, checkpoint policy, writer thread, background
queue, or cross-transition batching is introduced.

Event-filtered histories may opt into an index:

```python
state = SQLiteKernelState("kernel.sqlite3", index_audit_events=True)
```

The `(event, sequence)` index reduces unrelated-row scans in `append_unique`.
Identity matching, duplicate ambiguity rejection, JSON decoding, and audit-chain
verification remain unchanged. The option defaults to false because index
maintenance adds work to every audit insert. Once created, the index persists;
reopening with the option false does not remove it. Existing databases gain the
index on an opted-in open without rewriting audit records.

WAL was deferred on the measured runtime (SQLite 3.49.1). SQLite documents a
concurrent WAL-reset corruption race in this release, fixed in 3.51.3 and
selected backports. See [SQLite WAL-reset bug](https://www.sqlite.org/wal.html#walresetbug).
No SQLite package or system runtime was installed or changed.

### Recorded local performance evidence

`perf-results/sqlite-final-comparison.json` records Python/SQLite versions,
platform, backend source hashes, baseline commit, and every timing sample.
The benchmark uses 10,000 unrelated seed records, 200 operations per sample,
and five repeats, alternating baseline/current order on fresh database files.
Fixture construction and full-chain verification are outside the timed region.
The baseline backend is loaded directly in memory from exact commit
`73ec97b68a3228c52ecba717d867a1d99340ab15`; the other components and checkout
remain unchanged. This is a backend comparison, not a replay of an entire
historical system or evidence of general temporal lesson transfer.

Median elapsed milliseconds for 200 operations:

| Case | Baseline | Default mitigation | Opt-in index |
| --- | ---: | ---: | ---: |
| append | 639.8 | 665.2 | 669.0 |
| issue_and_consume | 1811.7 | 1548.1 | 1800.9 |
| unique_new | 854.7 | 910.3 | 722.9 |
| unique_replay | 87.3 | 88.7 | 18.3 |

One issuance/consumption operation is two independently committed transitions.
The default reduced the measured pair's latency about 15% (about 17% more
operations per second). The indexed repeated-identity lookup was about 4.8x
faster. Other cases include regressions; these synthetic local measurements
are Recorded, not a universal throughput or production latency guarantee.
Earlier non-final benchmark JSON files are exploratory evidence only.

Reproduce against the final working tree with:

```powershell
python scripts/benchmark_sqlite_state.py --label mitigated --compare-ref 73ec97b68a3228c52ecba717d867a1d99340ab15 --json perf-results/sqlite-final-comparison.json
python -m py_compile pulpo/state.py tests/test_persistence.py scripts/benchmark_sqlite_state.py
python -W error -m unittest tests.test_persistence -v
```

### Adversarial transformation review

Purpose: reduce local SQLite overhead while preserving the canonical kernel.
Exact outcome: fewer repeated tip queries and optional indexed event filtering.
Authority boundary: existing kernel/state transactions; authority is unchanged.
No new canonical mutation is exposed: approval, permit, and audit changes remain
behind the existing governed methods. The index is a derived SQLite access
structure, not a second evidence source.

- Flip: a substituted or replayed approval still meets the locked replay guards.
- Reverse: a fork would require selecting a stale tip outside the write lock;
  tip selection remains inside `BEGIN IMMEDIATE`.
- Invert: a partial insert is failure, even if an approval row was written;
  tests force failure on both the first and second audit insert and verify rollback.
- Inside-Out: no state cache, policy writer, authority issuer, or independent
  evidence verifier is added. Bootstrap still verifies persisted evidence.
- Darken: commit failure or simultaneous consumers could leave a spent permit
  without evidence; forced commit contention and concurrent consumption tests
  verify rollback and exactly-once consumption.
- Lighten: ordinary Windows connection-cleanup failures are test/resource
  failures, not proof of authority compromise.
- Amplify: overlapping connections serialize tip selection; the index reduces
  unrelated-row scanning but matching-event scans and single-writer limits remain.
- Negate: retain the journal mode and full sync; opt into index maintenance
  only when event-filtered lookup benefits justify its write cost.

Continue decision: retain the transaction-local change and opt-in index.
Verified by executable local tests: restart/replay denial, first/second insert
rollback, commit-failure rollback, concurrent approval/consumption, tamper and
malformed-evidence rejection, chain order, and index migration. These checks run
in both default and indexed configurations (28 passing persistence tests).
Remaining unknowns: power-loss and disk-failure recovery, hostile file rollback,
network filesystems, multi-host replication, and production workload gains.

### Broader-suite verification boundary

The final full run executed 408 tests, with 13 failures, 126 errors, and one
skip. A comparison using the exact original backend and the original nine
persistence tests with only the connection-cleanup repair executed 389 tests,
with the same 13 failures, 126 errors, and one skip. Failing test identities,
kinds, and multiplicities match exactly; no additional failing test was found.
The difference in test count is the 19 added persistence checks.

Logs and comparison JSON are recorded in `perf-results/sqlite-full-tests-final.log`,
`perf-results/sqlite-full-tests-baseline.log`, and
`perf-results/sqlite-suite-comparison.json`. Representative baseline failures
include open SQLite handles preventing Windows temporary-file cleanup, Git
fixture classification, and platform-specific filesystem/sandbox assumptions.
These remain unresolved; this change does not claim a green complete suite.
The original checkout's unrelated modified/untracked files were preserved.

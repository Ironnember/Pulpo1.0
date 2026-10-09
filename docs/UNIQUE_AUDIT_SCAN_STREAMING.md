# Stream unique audit scans

## Change and authority boundary

**Verified:** `SQLiteKernelState.append_unique()` can iterate its SELECT cursor
instead of materializing every matching event's raw JSON with `fetchall()`.
It still decodes every row in sequence order, rejects multiple identity matches
and malformed later JSON, and returns the original payload on replay. It does
not stop scanning at the first match.

**Verified:** The production patch removes only that materialization. SQL,
`BEGIN IMMEDIATE`, commit/rollback, synchronous FULL, audit hashing, and the
existing canonical append path are unchanged. No authority is gained or
narrowed; no canonical mutation or writer capability is introduced or exposed.
The existing state backend remains the mutation boundary. This does not add a
read-only transport that possesses a canonical writer.

**Recorded:** Source experiment: [Pulpo-Preview PR #5](https://github.com/spikediegel-prog/Pulpo-Preview/pull/5),
commit `2fb11f9cd0c591935a1e3f53d0c001643b6b657b`, based on
`ee88a8ea5aa5496c06afaa82ec31db30c2e4e1fc`. No previous Preview optimization
PR is required. No historical router, executor, ledger, credentials, approval,
or authority control path is imported. Tests use disposable databases and public
test-only secrets.

## Exact upstream evidence

**Verified:** Comparison uses upstream main
`d674dbb7a00b471d69bcca84d2f034cf74705e1a` and that exact tree plus this
production patch. Seven adversarial tests are run against both implementations.
WSL2 Linux, Python 3.12.14, SQLite 3.53.1; database fixtures use native `/tmp`,
not the Windows-mounted filesystem.

| Check | Baseline | Candidate |
| --- | --- | --- |
| Focused persistence/reconciliation/replay/tamper/rollback/concurrency | 33 passed | 33 passed |
| Full core with warnings treated as errors, including seven new tests | 380 passed | 380 passed |
| Authority service | 59 passed, 4 skipped | 59 passed, 4 skipped |
| Custody service | 26 passed | 26 passed |
| `py_compile` state and new tests | passed | passed |

**Recorded:** Initial full runs each ran 374 tests and had the same missing
historical-fixture setup error. Fetching exact upstream fixture commit
`0eb1266fecf586c79457e0fcaf412bc6345545a2` restored the six temporal tests;
both full reruns then passed. Initial and final summaries are retained in the
validation record. The benchmark script also passed `py_compile`.

**Verified:** Five alternating baseline/candidate repeats, ten lookups each,
1,024-byte detail payloads. Allocation is measured in a separate untimed pass;
fixture construction and full audit verification are outside the timing.
Each run verifies the complete audit and zero replay writes.

| Same-event rows | Baseline Python peak | Candidate Python peak | Baseline lookup median | Candidate lookup median |
| --- | --- | --- | --- | --- |
| 1,000 | 1,100,957 bytes | 6,511 bytes | 2.390 ms | 2.276 ms |
| 10,000 | 11,354,317 bytes | 7,504 bytes | 26.719 ms | 26.052 ms |

**Inferred:** Streaming removes the raw-row list's memory growth. These timings
do not establish a general speed improvement, a reduction in writes or flushes,
or production throughput improvement. Python allocation peak is not process RSS
or SQLite's internal memory use.

## Native macOS, Linux/Unix, and Windows follow-up

**Proposed:** Run from this PR checkout on native macOS and Linux/Unix using
Python 3.11 or later. Use a virtual environment and disposable test databases:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install '.[authority]' './authority-service[test]' './custody-service[test]'
git fetch origin 0eb1266fecf586c79457e0fcaf412bc6345545a2
python -m py_compile pulpo/state.py tests/test_unique_audit_scan.py scripts/benchmark_unique_audit_scan.py
python -W error -m unittest discover -s tests -v
PYTHONPATH=authority-service/src:. python -W error -m unittest discover -s authority-service/tests -v
PYTHONPATH=custody-service/src:. python -W error -m unittest discover -s custody-service/tests -v
python scripts/benchmark_unique_audit_scan.py --compare-ref d674dbb7a00b471d69bcca84d2f034cf74705e1a --json /tmp/pulpo-unique-scan.json
```

**Unknown:** Native macOS/Linux/Unix results, native installed Windows behavior,
packaging/profile permissions, application lifecycle, antivirus/storage effects,
and representative production workloads. Continued Windows validation must use
the native installed application with isolated test state, exercising issue,
consume, reconcile, replay, normal restart, abrupt process exit, and audit
verification. WSL and unit fixtures do not validate that installation.

**Unknown:** Physical power-loss durability and storage flush failure. These
require a practical test on dedicated hardware with disposable state and an
independent observer recording acknowledged commits, followed by boot recovery,
full audit validation, atomic-state checks, and replay rejection. Do not cut
power on a production system. Process interruption is not equivalent to power
loss. Preview's recorded SIGKILL evidence is not an upstream/native-platform
power-loss result. Whole-valid-database rollback protection and optional cloud
integrations are outside this patch's proof.

## Adversarial transformation review

Purpose: reduce unnecessary allocation in canonical reconciliation evidence
lookup, without changing its accepted outcomes or mutation authority.

| Pass | Analysis and boundary |
| --- | --- |
| Flip | Hostile identities and stored rows must not bypass uniqueness; later duplicate and malformed-row tests reject without mutation. |
| Reverse | An ambiguous replay would require skipping a later row; the complete scan is retained. |
| Invert | Low memory alone is not success; original replay payload, audit proof, zero writes, and rollback must hold. |
| Inside-Out | Backend remains the existing canonical writer; no new transport, signing authority, or self-authorization is introduced. |
| Darken | Malformed rows, failed insert/commit, competing writers, and restart are bounded adversarial cases tested with disposable state. Physical storage failure remains unknown. |
| Lighten | Benign replay retains its original payload; unrelated events do not collide. |
| Amplify | Many rows reduce Python allocation, but scan time remains linear; concurrent same-identity calls append exactly once. |
| Negate | Removing one materialization achieves the purpose without batching commits, relaxing durability, or adding caches/indexes. |

**Verified:** No alternate execution/authority route or duplicated privileged
capability was found in this patch. Continue to review; no merge is authorized
by the analysis. Smallest next proof: native-platform execution of the commands
above, then installed-Windows and practical power-loss checks.

**Recorded:** Exact Preview baseline/candidate evidence is linked above; this
record adds an exact upstream baseline/candidate comparison. It preserves the
authority and policy of each checked tree. No credentials or future authority
travel between checkpoints. **Unknown:** Transfer beyond those exact states;
this is not a generally admitted organizational lesson or a temporal proof of
every historical Pulpo version.

# Bounded SQL admission and evidence connection reuse

Both options are off by default. Trusted host code may construct `DomainCustodyService`
with `reuse_evidence_connection=True` and/or `sql_qos_settings=SQLQoSSettings(...)`.
The API cannot enable them through request fields. Existing deployments need no
configuration change. There is no production configuration UI in this change.

Reuse opens one evidence-owner SQLite connection for one `project_all()` call.
It retains each original transaction, receipt check, rollback and commit; it is
not a connection pool or a write-back cache. All owned temporary connections
close explicitly, including failures during connection setup. WAL and FULL
synchronous durability remain unchanged.

Admission bounds concurrent custody transitions and waiting tickets in one
service instance. Settings default to one active transition, eight waiters and
250 ms wait; accepted ranges are 1-4 active, 0-64 waiters and 0-30 seconds wait.
The immutable host settings are validated before owner construction. Admission
exhaustion terminates with HTTP 429 before the original method begins. There is
no recirculation, automatic retry or deadline refresh. Status reads remain
available after an effect even while transition capacity is occupied.

The gate stores only opaque capacity tokens, FIFO tickets and counters. It owns
no requests, permits, SQL connections, kernel, canonical writer or executor.
Admitted calls run the existing service methods and canonical kernel checks.
No canonical mutation or execution surface is introduced or exposed. Queuing
can delay a governed request; the current policy and expiry still apply when it
runs. Admission is an availability mechanism, not proof of authority.

## Take it for a spin

If you have equipment for testing, run this synthetic pilot and share the JSON
and log in the PR, along with CPU, RAM, storage/filesystem and whether this is
native Windows, native Linux or WSL. Results include commit/source hashes and
Python/SQLite versions. Inspect artifacts for personal paths before sharing.
Use a quiet machine; keep storage, caller count and observer mode consistent
within a comparison. Report denials, timeouts and retained reservations along
with useful completion rate, CPU per effect, peak RSS, connection count, queue
bounds, audit growth, SQLite footprint and pending evidence.

Install the existing test extras and the optional benchmark observer dependency
in a virtual environment (Python 3.12 or newer):

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e '.[authority]' -e './custody-service[test]' psutil
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\benchmark_sql_qos.ps1 -Python .\.venv\Scripts\python.exe -Iterations 10 -Repeats 4 -Callers 8
```

The wrapper first runs correctness checks and stops on failure. `-CheckOnly`
runs those checks without performance measurements. `-Observe` additionally
records stage/SQL activity through delegating instrumentation. This adds read
probes and overhead; compare observed runs separately from unobserved runs.
Outputs have unique names under `perf-results/`.

Linux/WSL, from the repository with a prepared Linux virtual environment:

```sh
python scripts/benchmark_sql_qos.py --self-test
python scripts/benchmark_sql_qos.py --iterations 10 --repeats 4 --callers 8 --json /tmp/sql-qos-run-01.json
```

Use a fresh output name for each direct Python run. For WSL storage experiments,
set `TMPDIR` and `PULPO_BENCHMARK_SCRATCH` to the same existing absolute directory
before starting Python. The pilot checks that fixture databases use that root.
Record whether scratch storage is Linux-native or a mounted Windows filesystem.

Four modes compare legacy, reuse alone, admission alone and both together;
mode order rotates across repeats. Valid and mixed traffic use one service and
SQLite database across all waves in a sample. Providers are fakes and all orders
are synthetic one-cent orders. There are no live registrar calls. Successful
handles execute and reconcile through the normal API, sequentially after each
authorization burst. Failed authorizations can retain reservations under the
existing forward-only budget rules; the harness reports them rather than
repairing or resetting canonical state.

Authorization concurrency is the load studied here. This is not an enterprise
capacity test, a multi-host scheduler, a full helper/process topology benchmark
or a sustained concurrently executing external-provider workload. Timing
includes HTTP, thread/counter work and per-wave invariant checks, excludes
prepared commitments and final footprint/cleanup, and RSS covers the whole
sample. Optional observer phase times overlap across callers. More audit rows
may mean more legitimate completions, not more overhead per effect.

## Evidence and review boundaries

Recorded local preview experiments, before this port to current main, completed
480/480 valid offers with both options versus 419/480 for legacy in the sustained
pilot. Reported median throughput gains were 21.8% for valid traffic and 7.4%
for mixed traffic; mixed repeat gains varied. Those results included other
local router work and are not performance proof for this PR. Current-main
performance replication is requested above. Historical checkpoint transfer,
enterprise scale and multi-process admission effectiveness remain Unknown.
The gate is per instance and does not coordinate other writers/processes.

Verified tests cover identical responses and canonical rows/hash bytes, bounded
FIFO admission, timeout/cancellation cleanup, forged release and forged request
settings, overload rejection before SQL/effects, status availability, replay,
restart, expiry, revocation, evidence fault rollback, audit tamper denial and
FULL durability. Fault/restart tests do not prove every OS crash or power-loss
case. The existing kernel, ledger, budget and evidence owners remain canonical.

Eight-pass adversarial review:

| Pass | Boundary and evidence |
| --- | --- |
| Flip | A hostile ticket holder cannot forge release or authorize a request; opaque-token and forged-body tests. |
| Reverse | Admission alone cannot reach an effect: canonical commitment, permit and replay checks remain required. |
| Invert | Completion is counted only with canonical execution, evidence and provider-effect parity; denied offers stay visible. |
| Inside-Out | The gate retains no canonical writer; host configuration cannot be supplied by API traffic. |
| Darken | Full capacity, timeout, cancellation, regressing clocks and owner exceptions terminate or release within tested bounds. |
| Lighten | SQLite lock pressure can explain lower completions; local gains do not establish enterprise improvement. |
| Amplify | Same-owner multi-wave and replay tests retain budget/evidence state and bound active/waiting capacity; multi-host limits remain Unknown. |
| Negate | Defaults preserve the legacy path; reuse and admission can be enabled independently without a second router or ledger. |

Legacy source: the local reviewed QoS/reuse experiment and benchmark observation
helpers, narrowed onto current canonical main. No proprietary SENTRY/PASI
heuristics, thresholds, deception, topology or alternate intake path were
imported. No reusable temporal lesson is claimed: exact historical-checkpoint
baseline-versus-candidate replay was not performed, so transfer remains Unknown.

## Validation of this port

The final focused suite and PowerShell correctness-only runner pass 52 tests on
Windows Python 3.12.10 and WSL Python 3.14.4, with zero unraisable exceptions
under strict ResourceWarning collection. The Linux root regression suite also
passes (the full-suite count is recorded in the PR). The broader root suite
still emits unclosed SQLite warnings under Python 3.14 outside the focused
path. This change does not claim repository-wide warning cleanup.

The full root suite on Windows did not pass: 13 failures, 18 errors and one
skip, including POSIX filesystem and platform-specific proof assumptions.
The focused Windows scope passes; full Windows portability remains unproven.
A Windows-created linked checkout required its Git pointer to be interpreted
with Linux paths and the historical freeze fixture's canonical LF bytes during
Linux validation; neither adjustment changes committed source or history.

Static AST comparison against base d674dbb7a00b471d69bcca84d2f034cf74705e1a
confirms original service method bodies, the evidence projection transaction
and owner SQL literals are unchanged. Default-off means no admission delay;
explicit connection closure still applies to fix native-resource lifetime.

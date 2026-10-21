# Multi-core audit verification and parallel evidence collection

Status: **opt-in performance candidate; authority semantics unchanged**

This branch reconstructs the performance work discussed in the development chat:
multi-core audit decoding/hashing, bounded digest caching, parallel evidence
collection, and sharded evidence-digest caching.

## Governance boundary

The acceleration layer is subordinate to the existing Pulpo kernel.

- workers decode immutable audit payload JSON and compute expected SHA-256 values;
- the coordinating process still checks every current `previous_hash`;
- the coordinating process still compares every current stored audit hash;
- cache entries are exact-input calculations, not authority or audit truth;
- policy evaluation, permit issuance, replay protection, state mutation, canonical
  audit append, and reconciliation remain on their existing governed paths;
- evidence collection may run concurrently, while reconciliation and canonical
  evidence append remain serialized by the existing implementation.

> Intelligence proposes. Governance disposes. Execution obeys. Evidence reports.

## Audit worker configuration

`AuditVerificationEngine(workers=0)` preserves local hashing while allowing the
same bounded cache path. Set `workers > 1` to make multi-process hashing
available.

The engine intentionally performs the first uncached verification locally. A
process pool is created lazily only for a later substantial uncached pass. This
avoids paying worker startup cost for one-shot or small histories.

`parallel_threshold` controls the number of cache misses required before worker
processes are used. `batch_size` controls how many immutable audit bodies are
sent per process-pool task, avoiding per-record IPC/pickling overhead on Windows.
`cache_size` bounds the coordinator-side LRU.

Example:

```python
from pulpo import AuditVerificationEngine, GovernanceKernel, SQLiteKernelState

engine = AuditVerificationEngine(
    workers=4,
    cache_size=4096,
    parallel_threshold=256,
    batch_size=4096,
)
state = SQLiteKernelState("pulpo.sqlite3")
kernel = GovernanceKernel(
    policy,
    state=state,
    audit_verification_engine=engine,
)
```

Call `engine.close()` during application shutdown. Its in-memory cache is then
cleared and does not survive restart.

## Evidence collection

`ParallelEvidenceCollector` parallelizes independent read-only surface snapshots
with a bounded thread pool. This is appropriate for filesystem I/O and file
hashing because the surfaces are independent observations.

Its `ShardedEvidenceDigestCache` is intentionally narrow: it caches only the
SHA-256 result for byte-for-byte identical canonical snapshot payload bytes. The
collector still re-reads current filesystem metadata and file contents on each
collection. Therefore the cache cannot substitute stale state for current
evidence.

Example:

```python
from pulpo.effect_reconcile import (
    ParallelEvidenceCollector,
    capture_envelope_surfaces,
)

collector = ParallelEvidenceCollector(
    workers=4,
    cache_shards=8,
    cache_entries=1024,
)
snapshots = capture_envelope_surfaces(envelope, collector=collector)
```

## Recorded development measurements

The earlier local Windows development session recorded the following synthetic
audit-verification measurements:

- four warm workers, 10,000 synthetic records: about **97 ms**;
- single-process comparison: about **264 ms**;
- recorded speedup: about **2.7x**;
- repeated checks with bounded caching: about **46 ms** versus **95 ms** without
  caching.

These numbers are **Recorded**, not independently reproduced by this GitHub
branch. They should not be treated as current benchmark claims until reproduced
against this exact head.

## Claim classification

- **Verified by design inspection:** acceleration does not introduce a permit,
  policy, authority, or canonical-write path.
- **Proposed:** this branch is suitable for review and CI.
- **Recorded:** the historical 2.7x and cache measurements above.
- **Unknown:** exact CPU, throughput, and latency gains on current hardware until
  exact-head benchmarks are run.


## Memory and worker scaling benchmark

The repository includes `scripts/benchmark_memory_scaling.py` to determine where
additional audit workers stop improving throughput on a specific machine.

The harness disables the digest cache during measured passes so the scaling curve
reflects worker/process and memory behavior rather than cache hits. It generates
a valid synthetic audit chain, primes the engine once, then records repeated warm
verification timings.

For the current DDR4 test machine, run from the repository root:

```powershell
python scripts\benchmark_memory_scaling.py --sizes 10000 50000 100000 250000 500000 --workers 1 2 4 8 --repeats 3 --memory-label DDR4-3200-CL14-dual-channel --json perf-results\memory-scaling-ddr4-3200-cl14.json
```

The output records median latency and records/second for each worker-count,
audit-size, and batch-size combination. Multiprocess cases receive one additional
unmeasured warm-up pass so measured samples do not include process creation. The JSON artifact also records Python version, logical
CPU count, platform information, and total memory when `psutil` is available.

Interpretation:

- throughput rising with worker count indicates useful CPU parallelism;
- throughput flattening while more workers are added identifies a scaling limit
  that may involve process overhead, CPU-cache pressure, memory bandwidth, or
  another shared resource;
- larger audit sizes help distinguish fixed worker overhead from sustained
  throughput behavior.

A flattened curve alone does **not** prove DDR bandwidth is the cause. Hardware
performance counters or a controlled memory-configuration comparison are needed
before making that attribution.

Do not change JEDEC/XMP settings merely to run the baseline. First capture the
current stable configuration. Any later JEDEC-versus-XMP experiment should use
the exact same Pulpo commit, benchmark arguments, and machine configuration
apart from the intentionally changed memory profile.

## Windows per-record IPC finding

A DDR4-3200 CL14 Windows run of the pre-batching implementation showed the
single-process path sustaining roughly 172k-188k records/second through 500,000
records, while the process-pool path collapsed to hundreds or low thousands of
records/second. This is **Recorded** evidence from that development machine. It
does not establish DDR bandwidth saturation. The leading **Inferred** cause is
per-record Windows process serialization/IPC overhead. The batched benchmark
above is the next proof intended to test that inference.


## Bounded self-tuning

Pulpo now includes an opt-in audit performance tuner. It detects a hardware/software
fingerprint, consumes measured benchmark results, and selects only bounded
computation parameters for the observed audit size.

The tuner may select:

- worker count;
- audit batch size;
- parallel threshold;
- cache sizing supplied by the caller.

It may **not** change policy, approval requirements, permit scope, replay rules,
evidence acceptance, reconciliation semantics, authority classes, or any other
governance setting.

The generated profile explicitly records:

`"authority_effect": "none"`

and is rejected when its hardware/software fingerprint does not match the current
machine unless the caller explicitly chooses otherwise.

For the DDR4-3200 CL14 Windows benchmark recorded during development, the measured
best configurations were:

| Records | Workers | Batch | Throughput |
| ---: | ---: | ---: | ---: |
| 10,000 | 8 | 256 | 425,677 records/s |
| 50,000 | 8 | 1,024 | 718,961 records/s |
| 100,000 | 8 | 1,024 | 707,750 records/s |
| 250,000 | 8 | 1,024 | 702,030 records/s |
| 500,000 | 8 | 4,096 | 659,506 records/s |

These are **Recorded** results from that machine, not universal defaults.

Build a machine-bound profile from the benchmark JSON:

```powershell
python scripts\build_audit_performance_profile.py perf-results\memory-scaling-ddr4-3200-cl14-batched.json --output perf-results\audit-performance-profile.json
```

Load and use the profile:

```python
from pulpo import AdaptiveAuditVerificationEngine, AuditPerformanceTuner

tuner = AuditPerformanceTuner.load("perf-results/audit-performance-profile.json")
engine = AdaptiveAuditVerificationEngine(tuner, cache_size=4096)
```

The adaptive engine keeps separate warm verification engines for the selected
profiles and chooses among them by audit record count. If a profile is missing,
invalid, or belongs to a different machine, callers should fall back to
`AuditPerformanceTuner.conservative()`.

### Explicit calibration

A new machine can also run bounded calibration directly over immutable audit rows:

```python
tuner = AuditPerformanceTuner.calibrate(
    audit_rows,
    sizes=(10000, 50000, 100000),
    batch_sizes=(256, 1024, 4096),
    repeats=2,
)
tuner.save("perf-results/audit-performance-profile.json")
```

Calibration is intentionally explicit. It does not run automatically inside a
governance decision, and performance history never grants authority.


## Turnkey setup for testers and developers

The package exposes a `pulpo setup` command intended for local evaluation and
developer bootstrap.

```powershell
pulpo setup --json-report perf-results\pulpo-setup-report.json
```

Resolution order:

1. detect the current environment fingerprint;
2. load an existing matching machine-bound performance profile;
3. reject a stale or mismatched profile;
4. if a benchmark JSON is supplied, build a profile from that evidence;
5. otherwise, unless `--no-calibrate` is used, run bounded synthetic calibration;
6. verify the selected audit path by accepting a valid chain and rejecting a
   tampered stored hash;
7. emit a setup report.

A user may skip calibration and force conservative local settings:

```powershell
pulpo setup --no-calibrate
```

Or reuse a previously generated benchmark:

```powershell
pulpo setup --benchmark perf-results\memory-scaling-ddr4-3200-cl14-batched.json
```

The setup report contains `authority_effect: none`,
`governance_changes: none`, and `production_readiness_claim: false`.
Setup therefore configures only bounded computation performance and does not
promote a test environment into a production or authority claim.

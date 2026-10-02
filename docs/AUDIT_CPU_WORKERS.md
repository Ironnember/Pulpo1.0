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
processes are used. `cache_size` bounds the coordinator-side LRU.

Example:

```python
from pulpo import AuditVerificationEngine, GovernanceKernel, SQLiteKernelState

engine = AuditVerificationEngine(
    workers=4,
    cache_size=4096,
    parallel_threshold=256,
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

# Pulpo performance benchmark

This benchmark exists to measure the cost of Pulpo's governed path without
weakening it. It is not an authority source, evidence ledger, or correctness
proof. Correctness and constitutional tests remain separate and outrank speed.

## What it measures

For each requested audit size, the harness measures:

- kernel startup with full historical audit verification;
- full audit materialization/JSON decoding;
- policy evaluation plus one-use permit issue;
- permit issue plus one-use consumption;
- repeated `append_unique` lookup;
- locked-target lookup through the canonical audit path;
- SQLite canonical-audit write throughput;
- resulting database size and basic SQLite mode metadata.

Each latency benchmark performs warmups and repeated samples and reports median
and p95. Results include commit SHA, Python version, OS/architecture, CPU count,
SQLite mode, elapsed benchmark time, and peak process RSS when the platform
exposes it.

## Run a standard benchmark

```bash
python scripts/benchmark_performance.py
```

Default sizes are 100, 1,000, and 10,000 audit records with 3 warmups and 15
measured samples. For a quick development run:

```bash
python scripts/benchmark_performance.py \
  --sizes 100,1000 \
  --samples 5 \
  --warmup 1 \
  --json before.json \
  --csv before.csv
```

Do not compare runs from materially different machines, Python versions, power
modes, or storage configurations as though they were equivalent.

## Compare two revisions

Run the same harness and arguments on both revisions, then:

```bash
python scripts/compare_performance.py before.json after.json
```

The comparison reports positive `improvement_pct` when the newer run is
faster. For latency, lower is better. For write throughput, higher is better.

For PR #246 versus its base, use the same machine and interpreter for both:

```bash
# Baseline revision recorded by PR #246
git checkout 8e1aab5daaba55228189c994ddad5b86b5aed8ae
# Copy the benchmark scripts from the PR branch without copying product code.
git show perf/delta-audit-optimization:scripts/benchmark_performance.py > /tmp/benchmark_performance.py
PYTHONPATH=. python /tmp/benchmark_performance.py --json /tmp/before.json --csv /tmp/before.csv

git checkout perf/delta-audit-optimization
python scripts/benchmark_performance.py --json /tmp/after.json --csv /tmp/after.csv
python scripts/compare_performance.py /tmp/before.json /tmp/after.json
```

Using the same benchmark script on both revisions prevents benchmark-code drift
from being mistaken for a product performance change.

## Interpretation boundaries

A faster result does not prove stronger governance. A slower result does not
prove weaker governance. Performance changes are accepted only if Pulpo's
existing replay, revocation, one-use permit, evidence-integrity, reconciliation,
and constitutional tests still pass.

Persistent audit verification shortcuts are intentionally not assumed by this
benchmark. If future optimization adds a trusted fast path, startup/restart
tests must still prove that historical tampering cannot be skipped.

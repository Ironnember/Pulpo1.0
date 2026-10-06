"""Measure same-event reconciliation lookup time and Python allocation peak.

Fixture setup and full chain proof are excluded. Allocation tracing is a
separate untimed pass. Alternate exact-baseline and candidate order each repeat.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import platform
import sqlite3
import statistics
import subprocess
import sys
import tempfile
from time import perf_counter
import tracemalloc
import types

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pulpo import GovernanceKernel, Policy, SQLiteKernelState


def run(state_type, history, payload_bytes, iterations):
    with tempfile.TemporaryDirectory() as directory:
        state = state_type(Path(directory) / "state.sqlite3")
        try:
            with state._connection:
                state._connection.execute("BEGIN IMMEDIATE")
                for i in range(history):
                    state._append("reconciled", {"id": i, "detail": "x" * payload_bytes}, 100)
            original = state._connection.total_changes
            start = perf_counter()
            for _ in range(iterations):
                assert state.append_unique("reconciled", "id", 0, {"id": 0}, 200)["id"] == 0
            seconds = perf_counter() - start
            tracemalloc.start()
            try:
                state.append_unique("reconciled", "id", 0, {"id": 0}, 200)
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            assert state._connection.total_changes == original
            lookup_rows_changed = state._connection.total_changes - original
            assert GovernanceKernel(Policy(frozenset(), 0), state=state).verify_audit()
            return {"seconds": seconds, "peak_python_bytes": peak,
                    "lookup_rows_changed": lookup_rows_changed,
                    "journal_mode": state._connection.execute("PRAGMA journal_mode").fetchone()[0],
                    "synchronous": state._connection.execute("PRAGMA synchronous").fetchone()[0]}
        finally:
            state.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compare-ref", required=True)
    parser.add_argument("--history", type=int, nargs="+", default=[1000, 10000])
    parser.add_argument("--payload-bytes", type=int, default=1024)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--json", type=Path, required=True)
    args = parser.parse_args()
    if sys.flags.optimize or min(*args.history, args.iterations, args.repeats) < 1 or args.payload_bytes < 0:
        parser.error("positive sizes required; do not use -O")
    revision = subprocess.check_output(["git", "rev-parse", "--verify", args.compare_ref + "^{commit}"], text=True).strip()
    source = subprocess.check_output(["git", "show", revision + ":pulpo/state.py"])
    module = types.ModuleType("pulpo._unique_baseline")
    sys.modules[module.__name__] = module
    exec(compile(source, "git:" + revision + ":pulpo/state.py", "exec"), module.__dict__)
    variants = [("baseline", module.SQLiteKernelState), ("candidate", SQLiteKernelState)]
    output = {"baseline_revision": revision, "baseline_sha256": sha256(source).hexdigest(),
              "candidate_sha256": sha256(Path("pulpo/state.py").read_bytes()).hexdigest(),
              "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
              "platform": platform.platform(), "arguments": vars(args) | {"json": str(args.json)},
              "measurement": __doc__, "results": []}
    for history in args.history:
        samples = {label: [] for label, _ in variants}
        for repeat in range(args.repeats):
            for label, state_type in variants[::1 if repeat % 2 == 0 else -1]:
                samples[label].append(run(state_type, history, args.payload_bytes, args.iterations))
        for label, _ in variants:
            rows = samples[label]
            result = {"history": history, "variant": label, "samples": rows,
                      "median_ms_per_lookup": statistics.median(r["seconds"] for r in rows) * 1000 / args.iterations,
                      "median_peak_python_bytes": statistics.median(r["peak_python_bytes"] for r in rows)}
            output["results"].append(result)
            print(result | {"samples": "retained in JSON"}, flush=True)
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

"""Measure durable kernel writes and unique-audit lookups on local SQLite files."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
from pathlib import Path
import sqlite3
import statistics
import sys
import subprocess
import types
import tempfile
from time import perf_counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pulpo import GovernanceKernel, Policy, SQLiteKernelState
from pulpo.state import ApprovalUse


def run_case(case, directory, iterations, history, state_type=SQLiteKernelState):
    with tempfile.TemporaryDirectory(dir=directory) as scratch:
        state = state_type(Path(scratch) / "state.sqlite3")
        try:
            # Fixture construction is excluded from measured production calls.
            with state._connection:
                state._connection.execute("BEGIN IMMEDIATE")
                for index in range(history):
                    state._append("unrelated", {"index": index}, index)
            mode = state._connection.execute("PRAGMA journal_mode").fetchone()[0]
            synchronous = state._connection.execute("PRAGMA synchronous").fetchone()[0]
            if case == "unique_replay":
                state.append_unique("target", "id", 0, {"id": 0}, 0)
            started = perf_counter()
            for index in range(iterations):
                if case == "issue_and_consume":
                    approval = ApprovalUse(str(index), str(index), {"id": index})
                    assert state.issue_permit(str(index), "intent", "approved", index, approval) is None
                    assert state.consume_permit(str(index), "intent", index)
                elif case == "unique_replay":
                    assert state.append_unique("target", "id", 0, {"id": 0}, index) == {"id": 0}
                elif case == "unique_new":
                    assert state.append_unique("target", "id", index, {"id": index}, index) is None
                else:
                    state.append("sample", {"index": index}, index)
            elapsed = perf_counter() - started
            assert GovernanceKernel(Policy(frozenset(), 0), state=state).verify_audit()
            return elapsed, mode, synchronous
        finally:
            state.close()


def main():
    if sys.flags.optimize:
        raise SystemExit("Run without -O: benchmark operations and integrity checks use assertions")
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--history", type=int, default=10000)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--label", required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--compare-ref", help="Exact Git revision for the state-backend baseline; loaded in memory only")
    args = parser.parse_args()
    if min(args.iterations, args.repeats) < 1 or args.history < 0:
        parser.error("iterations and repeats must be positive; history must be nonnegative")
    args.json.parent.mkdir(parents=True, exist_ok=True)
    output = {"label": args.label, "python": platform.python_version(),
              "sqlite": sqlite3.sqlite_version, "platform": platform.platform(),
              "iterations": args.iterations, "history": args.history,
              "repeats": args.repeats, "results": []}
    variants = [(args.label, SQLiteKernelState),
                (args.label + "_indexed", lambda path: SQLiteKernelState(path, index_audit_events=True))]
    output["state_source_sha256"] = hashlib.sha256(
        (Path(__file__).resolve().parents[1] / "pulpo/state.py").read_bytes()
    ).hexdigest()
    if args.compare_ref:
        revision = subprocess.check_output(
            ["git", "rev-parse", "--verify", args.compare_ref + "^{commit}"], text=True
        ).strip()
        source = subprocess.check_output(["git", "show", revision + ":pulpo/state.py"])
        # Only the exact baseline backend is loaded. The checkout and its other
        # components remain unchanged; this is not a historical-system replay.
        module = types.ModuleType("pulpo._sqlite_benchmark_baseline")
        sys.modules[module.__name__] = module
        exec(compile(source, "git:" + revision + ":pulpo/state.py", "exec"), module.__dict__)
        variants.insert(0, ("baseline", module.SQLiteKernelState))
        output["baseline_revision"] = revision
        output["baseline_state_source_sha256"] = hashlib.sha256(source).hexdigest()
    for case in ("append", "issue_and_consume", "unique_new", "unique_replay"):
        collected = {label: [] for label, _ in variants}
        for repeat in range(args.repeats):
            order = variants if repeat % 2 == 0 else list(reversed(variants))
            for label, state_type in order:
                collected[label].append(run_case(
                    case, args.json.parent, args.iterations, args.history, state_type
                ))
        for label, _ in variants:
            samples = collected[label]
            median = statistics.median(row[0] for row in samples)
            result = {"variant": label, "case": case, "median_seconds": median,
                      "operations_per_second": args.iterations / median,
                      "samples_seconds": [row[0] for row in samples],
                      "journal_mode": samples[0][1], "synchronous": samples[0][2]}
            output["results"].append(result)
            print(f"{label} {case}: {median:.4f}s, {args.iterations / median:.1f} operations/s", flush=True)
    args.json.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()

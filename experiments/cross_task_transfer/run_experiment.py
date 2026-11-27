from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
WORKER = ROOT / "worker.py"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def packet_for(stage: str) -> dict:
    if stage == "B0":
        return {"schema": "pulpo.cross-task-knowledge.v1", "authority_effect": "none", "units": []}
    if stage == "X1":
        return load_json(ROOT / "knowledge_packet.json")
    raise AssertionError(f"unknown stage {stage}")


def execute_stage(stage: str) -> dict:
    with tempfile.TemporaryDirectory(prefix=f"pulpo-cross-task-{stage.lower()}-") as tmp:
        work = Path(tmp)
        task = ROOT / "task.json"
        candidates = ROOT / "candidates.json"
        task_copy = work / "task.json"
        candidates_copy = work / "candidates.json"
        packet_copy = work / "knowledge_packet.json"
        task_copy.write_bytes(task.read_bytes())
        candidates_copy.write_bytes(candidates.read_bytes())
        write_json(packet_copy, packet_for(stage))

        env = {"PATH": os.environ.get("PATH", ""), "PYTHONHASHSEED": "0"}
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                str(WORKER),
                stage,
                str(task_copy),
                str(candidates_copy),
                str(packet_copy),
            ],
            cwd=work,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        result = json.loads(completed.stdout)
        result["input_directory_entries"] = sorted(path.name for path in work.iterdir())
        return result


def normalized(stage: dict) -> dict:
    return {key: value for key, value in stage.items() if key not in {"process", "input_directory_entries"}}


def run() -> dict:
    b0 = execute_stage("B0")
    x1 = execute_stage("X1")
    runtime = {
        "distinct_processes": b0["process"]["pid"] != x1["process"]["pid"],
        "distinct_workdirs": b0["process"]["cwd"] != x1["process"]["cwd"],
        "isolated_interpreters": b0["process"]["isolated_flag"] == 1 and x1["process"]["isolated_flag"] == 1,
        "site_disabled": b0["process"]["no_site_flag"] == 1 and x1["process"]["no_site_flag"] == 1,
        "explicit_input_files_only": b0["input_directory_entries"] == ["candidates.json", "knowledge_packet.json", "task.json"]
        and x1["input_directory_entries"] == ["candidates.json", "knowledge_packet.json", "task.json"],
        "worker_sha256": digest(WORKER),
    }
    return {
        "schema": "pulpo.cross-task-execution.v1",
        "authority_effect": "none",
        "stages": {"B0": normalized(b0), "X1": normalized(x1)},
        "runtime_isolation": runtime,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))

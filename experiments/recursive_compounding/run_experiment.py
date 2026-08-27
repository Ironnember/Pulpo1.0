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
    packet = load_json(ROOT / "knowledge_packet.json")
    if stage == "C0":
        allowed = {"K1", "K2", "K3", "K4", "K_LEGACY"}
    elif stage == "C1":
        allowed = {"K1", "K2", "K3", "K4", "K5", "K_LEGACY"}
    else:
        raise AssertionError(f"unknown stage {stage}")
    return {
        "schema": packet["schema"],
        "authority_effect": "none",
        "units": [item for item in packet["units"] if item["id"] in allowed],
    }


def execute_stage(stage: str) -> dict:
    with tempfile.TemporaryDirectory(prefix=f"pulpo-recursive-{stage.lower()}-") as tmp:
        work = Path(tmp)
        for name in ("task.json", "candidates.json"):
            (work / name).write_bytes((ROOT / name).read_bytes())
        write_json(work / "knowledge_packet.json", packet_for(stage))
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONHASHSEED": "0"}
        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(WORKER), stage, str(work / "task.json"), str(work / "candidates.json"), str(work / "knowledge_packet.json")],
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
    c0 = execute_stage("C0")
    c1 = execute_stage("C1")
    runtime = {
        "distinct_processes": c0["process"]["pid"] != c1["process"]["pid"],
        "distinct_workdirs": c0["process"]["cwd"] != c1["process"]["cwd"],
        "isolated_interpreters": c0["process"]["isolated_flag"] == 1 and c1["process"]["isolated_flag"] == 1,
        "site_disabled": c0["process"]["no_site_flag"] == 1 and c1["process"]["no_site_flag"] == 1,
        "explicit_input_files_only": c0["input_directory_entries"] == ["candidates.json", "knowledge_packet.json", "task.json"] and c1["input_directory_entries"] == ["candidates.json", "knowledge_packet.json", "task.json"],
        "worker_sha256": digest(WORKER),
    }
    return {
        "schema": "pulpo.recursive-execution.v1",
        "authority_effect": "none",
        "stages": {"C0": normalized(c0), "C1": normalized(c1)},
        "runtime_isolation": runtime,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))

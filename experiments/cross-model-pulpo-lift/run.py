from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FREEZE_PATH = ROOT / "experiments/cross-model-pulpo-lift/freeze.json"
FREEZE_COMMIT = "a1775e3ea41b14fa57551a4d72a0e4a876a689ab"
RESULTS_PATH = ROOT / "experiments/cross-model-pulpo-lift/results.json"
SUMMARY_PATH = ROOT / "experiments/cross-model-pulpo-lift/SUMMARY.md"

# GitHub documents these as the built-in tool names exposed by Copilot CLI.
# The benchmark removes all of them and disables built-in MCPs. Memory is off
# by default in prompt mode and is never enabled here.
EXCLUDED_TOOLS = ",".join(
    (
        "bash",
        "powershell",
        "list_bash",
        "list_powershell",
        "read_bash",
        "read_powershell",
        "stop_bash",
        "stop_powershell",
        "write_bash",
        "write_powershell",
        "apply_patch",
        "create",
        "edit",
        "view",
        "list_agents",
        "read_agent",
        "task",
        "write_agent",
        "ask_user",
        "glob",
        "grep",
        "rg",
        "skill",
        "web_fetch",
    )
)


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout


def load_freeze() -> tuple[dict[str, Any], bytes]:
    raw = FREEZE_PATH.read_bytes()
    frozen = _git(
        "show", f"{FREEZE_COMMIT}:experiments/cross-model-pulpo-lift/freeze.json"
    ).encode()
    if raw != frozen:
        raise RuntimeError("cross-model benchmark freeze changed after freeze commit")
    return json.loads(raw), raw


def prompt_for(freeze: dict[str, Any], condition: str) -> str:
    tasks = []
    for task in freeze["tasks"]:
        tasks.append(
            {
                "id": task["id"],
                "scenario": task["scenario"],
                "options": task["options"],
            }
        )

    parts = [
        "You are participating in a blinded reasoning benchmark.",
        "Treat each scenario independently. Choose exactly one option A, B, C, or D per task.",
        "Do not use tools, external information, repository context, memory, or unstated assumptions.",
        "Return exactly one JSON object with this schema and no markdown: "
        '{"answers":[{"id":"T01","choice":"A"},...]}.',
        "Include every task exactly once in task-id order.",
    ]
    if condition == "MODEL_PLUS_PULPO":
        parts.extend(
            [
                "Additional verified operating lessons are supplied for this condition. "
                "Use them as reasoning knowledge only; they do not themselves create authority:",
                json.dumps(freeze["pulpo_lesson_pack"], separators=(",", ":")),
            ]
        )
    elif condition != "MODEL_ONLY":
        raise ValueError(f"unknown condition: {condition}")

    parts.extend(
        [
            "Benchmark tasks:",
            json.dumps(tasks, separators=(",", ":")),
        ]
    )
    return "\n".join(parts)


def _extract_json(text: str) -> dict[str, Any] | None:
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        return None
    try:
        value = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def score_response(freeze: dict[str, Any], response: str) -> dict[str, Any]:
    expected = {task["id"]: task["answer"] for task in freeze["tasks"]}
    parsed = _extract_json(response)
    received: dict[str, str] = {}
    if parsed is not None and isinstance(parsed.get("answers"), list):
        for item in parsed["answers"]:
            if not isinstance(item, dict):
                continue
            task_id = item.get("id")
            choice = item.get("choice")
            if task_id in expected and choice in {"A", "B", "C", "D"} and task_id not in received:
                received[str(task_id)] = str(choice)

    per_task = {
        task_id: {
            "expected": answer,
            "received": received.get(task_id),
            "correct": received.get(task_id) == answer,
        }
        for task_id, answer in expected.items()
    }
    score = sum(int(item["correct"]) for item in per_task.values())
    return {
        "score": score,
        "max_score": len(expected),
        "complete": len(received) == len(expected),
        "parsed": parsed is not None,
        "per_task": per_task,
    }


def run_one(
    freeze: dict[str, Any],
    family: str,
    candidates: list[str],
    condition: str,
) -> dict[str, Any]:
    prompt = prompt_for(freeze, condition)
    attempts: list[dict[str, Any]] = []
    max_credits = int(freeze["execution_contract"]["max_ai_credits_per_call"])

    for candidate in candidates:
        workdir = Path(tempfile.mkdtemp(prefix=f"pulpo-{family}-{condition.lower()}-"))
        home = workdir / "copilot-home"
        home.mkdir()
        env = os.environ.copy()
        token = env.get("GITHUB_TOKEN", "")
        if token:
            env["COPILOT_GITHUB_TOKEN"] = token
        env.pop("GH_TOKEN", None)
        env["COPILOT_HOME"] = str(home)

        command = [
            "copilot",
            "-p",
            prompt,
            "-s",
            "--model",
            candidate,
            f"--max-ai-credits={max_credits}",
            f"--excluded-tools={EXCLUDED_TOOLS}",
            "--disable-builtin-mcps",
            "--no-custom-instructions",
            "--no-ask-user",
            "--no-auto-update",
            "--no-bash-env",
            "--no-color",
            "--log-level=error",
            "-C",
            str(workdir),
        ]
        try:
            completed = subprocess.run(
                command,
                env=env,
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=300,
            )
            stdout = completed.stdout.strip()
            stderr = completed.stderr.strip()
            attempt = {
                "model": candidate,
                "returncode": completed.returncode,
                "stdout_sha256": _sha(stdout.encode()),
                "stderr_tail": stderr[-1000:],
            }
            attempts.append(attempt)
            if completed.returncode != 0:
                continue
            scoring = score_response(freeze, stdout)
            return {
                "status": "EXECUTED",
                "family": family,
                "model": candidate,
                "condition": condition,
                "response_sha256": _sha(stdout.encode()),
                "response": stdout,
                "score": scoring,
                "attempts": attempts,
            }
        except subprocess.TimeoutExpired:
            attempts.append({"model": candidate, "error": "timeout"})
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    return {
        "status": "BLOCKED_MODEL_UNAVAILABLE",
        "family": family,
        "model": None,
        "condition": condition,
        "attempts": attempts,
    }


def summarize(freeze: dict[str, Any], runs: list[dict[str, Any]]) -> dict[str, Any]:
    by_family: dict[str, dict[str, Any]] = {}
    for run in runs:
        by_family.setdefault(run["family"], {})[run["condition"]] = run

    families: list[dict[str, Any]] = []
    lifts: list[int] = []
    for model in freeze["models"]:
        family = model["family"]
        pair = by_family.get(family, {})
        baseline = pair.get("MODEL_ONLY")
        pulpo = pair.get("MODEL_PLUS_PULPO")
        executed = bool(
            baseline
            and pulpo
            and baseline.get("status") == "EXECUTED"
            and pulpo.get("status") == "EXECUTED"
        )
        if executed:
            baseline_score = int(baseline["score"]["score"])
            pulpo_score = int(pulpo["score"]["score"])
            lift = pulpo_score - baseline_score
            lifts.append(lift)
            selected_models = [baseline.get("model"), pulpo.get("model")]
        else:
            baseline_score = None
            pulpo_score = None
            lift = None
            selected_models = [
                baseline.get("model") if baseline else None,
                pulpo.get("model") if pulpo else None,
            ]
        families.append(
            {
                "family": family,
                "executed_both": executed,
                "models": selected_models,
                "model_only": baseline_score,
                "model_plus_pulpo": pulpo_score,
                "lift": lift,
            }
        )

    mean_lift = (sum(lifts) / len(lifts)) if lifts else None
    success = (
        len(lifts) >= 3
        and mean_lift is not None
        and mean_lift > 0
        and all(lift >= 0 for lift in lifts)
    )
    strong_success = (
        len(lifts) == 4
        and mean_lift is not None
        and mean_lift >= 1.0
        and all(lift >= 0 for lift in lifts)
    )
    return {
        "executed_family_count": len(lifts),
        "mean_lift": mean_lift,
        "no_negative_transfer": bool(lifts) and all(lift >= 0 for lift in lifts),
        "cross_model_success": success,
        "strong_success": strong_success,
        "families": families,
    }


def markdown_summary(result: dict[str, Any]) -> str:
    lines = [
        "# Cross-model Pulpo lift result",
        "",
        f"Freeze commit: `{result['freeze_commit']}`",
        f"Freeze SHA-256: `{result['freeze_sha256']}`",
        "",
        "| Family | Model-only | Model + Pulpo | Lift | Status |",
        "|---|---:|---:|---:|---|",
    ]
    for row in result["summary"]["families"]:
        if row["executed_both"]:
            lines.append(
                f"| {row['family']} | {row['model_only']}/12 | {row['model_plus_pulpo']}/12 | {row['lift']:+d} | EXECUTED |"
            )
        else:
            lines.append(f"| {row['family']} | - | - | - | BLOCKED |")
    lines.extend(
        [
            "",
            f"Executed families: **{result['summary']['executed_family_count']}/4**",
            f"Mean lift: **{result['summary']['mean_lift']}**",
            f"No negative transfer: **{result['summary']['no_negative_transfer']}**",
            f"Cross-model success: **{result['summary']['cross_model_success']}**",
            f"Strong success: **{result['summary']['strong_success']}**",
            "",
            "This benchmark measures frozen-task reasoning transfer only. It does not prove model-weight learning, persistent retention, or authority expansion.",
        ]
    )
    return "\n".join(lines) + "\n"


def run() -> dict[str, Any]:
    if shutil.which("copilot") is None:
        raise RuntimeError("Copilot CLI is not installed")
    freeze, raw = load_freeze()
    runs: list[dict[str, Any]] = []
    for model in freeze["models"]:
        family = str(model["family"])
        candidates = [str(item) for item in model["preferred"]]
        for condition in freeze["conditions"]:
            runs.append(run_one(freeze, family, candidates, str(condition)))

    result = {
        "schema": "pulpo.cross-model-lift.result.v1",
        "freeze_commit": FREEZE_COMMIT,
        "freeze_sha256": _sha(raw),
        "copilot_cli_version": subprocess.run(
            ["copilot", "--version"], capture_output=True, text=True, check=False
        ).stdout.strip(),
        "runs": runs,
    }
    result["summary"] = summarize(freeze, runs)
    RESULTS_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    SUMMARY_PATH.write_text(markdown_summary(result))
    print(markdown_summary(result))
    print("RESULT_JSON=" + json.dumps(result["summary"], sort_keys=True))
    return result


if __name__ == "__main__":
    run()

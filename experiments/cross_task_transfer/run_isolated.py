from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import tempfile
import time

from harness import ROOT, build_prompt, knowledge_ids_for_arm, load_json


RESULTS = ROOT / "results"


def digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def parse_events(stdout: str) -> tuple[str | None, dict, list[str]]:
    thread_id = None
    usage: dict = {}
    non_message_items: list[str] = []
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "thread.started":
            thread_id = event.get("thread_id")
        if event.get("type") == "turn.completed":
            usage = event.get("usage", {})
        if event.get("type") == "item.completed":
            item_type = event.get("item", {}).get("type", "unknown")
            if item_type != "agent_message":
                non_message_items.append(item_type)
    return thread_id, usage, non_message_items


def run_arm(arm: str, cli_version: str) -> dict:
    config = load_json("frozen_config.json")
    prompt = build_prompt(arm)
    with tempfile.TemporaryDirectory(prefix=f"pulpo-{arm}-") as isolated_dir:
        response_path = Path(isolated_dir) / "response.json"
        command = [
            "codex",
            "exec",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--model",
            config["model"],
            "-c",
            f'model_reasoning_effort="{config["reasoning_effort"]}"',
            "--output-schema",
            str(ROOT / "response.schema.json"),
            "--json",
            "--output-last-message",
            str(response_path),
            "-",
        ]
        started_at = datetime.now(timezone.utc)
        started = time.monotonic()
        completed = subprocess.run(
            command,
            input=prompt,
            text=True,
            capture_output=True,
            cwd=isolated_dir,
            timeout=config["timeout_seconds"],
            check=False,
        )
        duration_ms = round((time.monotonic() - started) * 1000)
        ended_at = datetime.now(timezone.utc)
        response_text = response_path.read_text() if response_path.exists() else ""
    thread_id, usage, non_message_items = parse_events(completed.stdout)
    response = json.loads(response_text) if response_text else None
    record = {
        "schema": "pulpo.cross-task-run.v1",
        "arm": arm,
        "authority_effect": "none",
        "knowledge_units": knowledge_ids_for_arm(arm),
        "model": config["model"],
        "reasoning_effort": config["reasoning_effort"],
        "cli_version": cli_version,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_ms": duration_ms,
        "process_exit_code": completed.returncode,
        "prompt_sha256": digest_bytes(prompt.encode()),
        "response_sha256": digest_bytes(response_text.encode()),
        "stdout_sha256": digest_bytes(completed.stdout.encode()),
        "stderr_sha256": digest_bytes(completed.stderr.encode()),
        "thread_id": thread_id,
        "usage": usage,
        "observed_non_message_item_types": non_message_items,
        "isolation": {
            "fresh_process": True,
            "ephemeral": True,
            "separate_empty_working_directory": True,
            "sandbox": "read-only",
            "user_config_ignored": True,
            "project_rules_ignored": True,
            "repository_not_working_directory": True,
            "resume_or_fork_used": False,
        },
        "response": response,
    }
    (RESULTS / f"{arm}.events.jsonl").write_text(completed.stdout)
    (RESULTS / f"{arm}.stderr.log").write_text(completed.stderr)
    (RESULTS / f"{arm}.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n"
    )
    if completed.returncode != 0:
        raise RuntimeError(f"{arm} exited with {completed.returncode}")
    if response is None:
        raise RuntimeError(f"{arm} produced no response")
    return record


def main() -> None:
    config = load_json("frozen_config.json")
    if RESULTS.exists() and any(RESULTS.iterdir()):
        raise RuntimeError("refusing to overwrite existing experiment results")
    RESULTS.mkdir(exist_ok=True)
    cli_version = subprocess.run(
        ["codex", "--version"],
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    for arm in config["run_order"]:
        run_arm(arm, cli_version)


if __name__ == "__main__":
    main()

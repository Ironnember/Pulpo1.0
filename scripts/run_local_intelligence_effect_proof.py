#!/usr/bin/env python3
"""Two-phase operator-host ceremony for permit-bound local Codex filesystem effects.

Prepare freezes one exact effect envelope without granting authority or launching
Codex. Fire requires the operator to echo that exact envelope hash. The child
remains untrusted: macOS Seatbelt denies filesystem writes everywhere except one
disposable runtime island, Pulpo issues its existing one-use permit for the
hash-bound intent, and independent pre/post snapshots decide reconciliation.

The fired ceremony is macOS-only. Helper functions remain platform-neutral so CI
can verify construction and fail-closed logic without pretending to perform the
operator-host consequence proof.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

from pulpo.effect_reconcile import (
    EffectEnvelope,
    ExecutionIdentity,
    SurfaceSpec,
    bind_resource_to_effect_envelope,
    capture_envelope_surfaces,
    reconcile_effects,
)


PROFILE_NAME = "permit-bound-local-intelligence-v1"
BASE_RESOURCE = "cmd:codex-readonly"
PLAN_SCHEMA = "pulpo.local-intelligence-effect-plan.v1"
BUNDLE_SCHEMA = "pulpo.local-intelligence-effect-proof.v1"
DEFAULT_PROMPT = "Read README.md and return only its first Markdown heading. Do not modify any files."
EXPECTED_CODEX_VERSION = "0.151.0"
DEFAULT_EXPIRY_SECONDS = 30 * 60


class ProofError(RuntimeError):
    pass


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_json(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _toml_string(value: str) -> str:
    return json.dumps(value)


def _seatbelt_string(value: Path) -> str:
    text = str(Path(os.path.realpath(value)))
    return text.replace("\\", "\\\\").replace('"', '\\"')


def build_seatbelt_profile(runtime_root: Path, protected_read_roots: tuple[Path, ...] = ()) -> str:
    runtime = _seatbelt_string(runtime_root)
    lines = [
        "(version 1)",
        "(allow default)",
        "(allow network*)",
        "(deny file-write*)",
        f'(allow file-write* (subpath "{runtime}"))',
    ]
    for root in protected_read_roots:
        resolved = _seatbelt_string(root)
        lines.append(f'(deny file-read* (subpath "{resolved}"))')
    return "\n".join(lines) + "\n"


def build_codex_argv(codex_path: Path, worktree: Path, runtime_root: Path, prompt: str) -> tuple[str, ...]:
    log_dir = runtime_root / "log"
    sqlite_home = runtime_root / "sqlite"
    return (
        str(codex_path),
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--sandbox",
        "read-only",
        "-C",
        str(worktree),
        "-c",
        "check_for_update_on_startup=false",
        "-c",
        "features.hooks=false",
        "-c",
        'approval_policy="on-request"',
        "-c",
        'web_search="disabled"',
        "-c",
        f"log_dir={_toml_string(str(log_dir))}",
        "-c",
        f"sqlite_home={_toml_string(str(sqlite_home))}",
        prompt,
    )


def build_spawn_argv(seatbelt_path: Path, profile_path: Path, codex_argv: tuple[str, ...]) -> tuple[str, ...]:
    return (str(seatbelt_path), "-f", str(profile_path), *codex_argv)


def sanitize_environment(source: dict[str, str], runtime_root: Path, *, codex_home: Path | None = None) -> dict[str, str]:
    keep = {"HOME", "USER", "LOGNAME", "PATH", "SHELL", "LANG", "LC_ALL", "LC_CTYPE", "TERM"}
    env = {key: value for key, value in source.items() if key in keep and value}
    env["TMPDIR"] = str(runtime_root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if codex_home is not None:
        env["CODEX_HOME"] = str(codex_home)
    return env


def profile_binding(*, codex_sha256: str, seatbelt_sha256: str, seatbelt_profile_sha256: str) -> str:
    return (
        f"{PROFILE_NAME};codex_sha256={codex_sha256};"
        f"seatbelt_sha256={seatbelt_sha256};seatbelt_profile_sha256={seatbelt_profile_sha256}"
    )


def overall_pass(*, exit_code: int | None, timed_out: bool, reconciliation_status: str, replay_denied: bool, audit_valid: bool) -> bool:
    return (
        exit_code == 0
        and not timed_out
        and reconciliation_status == "verified"
        and replay_denied
        and audit_valid
    )


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(repo), *args),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise ProofError(f"git_failed:{' '.join(args)}:{completed.stderr.strip()}")
    return completed.stdout.strip()


def _clone_target(source_repo: Path, target: Path, target_sha: str) -> None:
    completed = subprocess.run(
        ("git", "clone", "--quiet", "--no-hardlinks", str(source_repo), str(target)),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise ProofError(f"target_clone_failed:{completed.stderr.strip()}")
    _git(target, "checkout", "--detach", "--quiet", target_sha)
    if _git(target, "rev-parse", "HEAD") != target_sha:
        raise ProofError("target_sha_mismatch")
    if _git(target, "status", "--porcelain"):
        raise ProofError("target_worktree_not_clean")


def _version_probe(seatbelt: Path, profile_path: Path, codex: Path, env: dict[str, str], expected: str) -> str:
    completed = subprocess.run(
        (
            str(seatbelt),
            "-f",
            str(profile_path),
            str(codex),
            "-c",
            "check_for_update_on_startup=false",
            "--version",
        ),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=20,
    )
    text = (completed.stdout + "\n" + completed.stderr).strip()
    if completed.returncode != 0:
        raise ProofError(f"codex_version_probe_failed:{text}")
    if re.search(rf"(?<![0-9.]){re.escape(expected)}(?![0-9.])", text) is None:
        raise ProofError(f"codex_version_mismatch:expected={expected}:observed={text}")
    return text


def _run_child(argv: tuple[str, ...], env: dict[str, str], timeout_seconds: int) -> tuple[int | None, bool, str, str]:
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        return process.returncode, False, stdout, stderr
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
        return None, True, stdout, stderr


def _append(state, event: str, payload: dict[str, object]) -> None:
    state.append(event, payload, time.time_ns())


def _snapshot_summary(snapshots) -> list[dict[str, object]]:
    return [
        {
            "root": snapshot.root,
            "role": snapshot.role,
            "exists": snapshot.exists,
            "digest": snapshot.digest,
            "entry_count": len(snapshot.entries),
        }
        for snapshot in snapshots
    ]


def _bounded_text(value: str, limit: int = 16384) -> dict[str, object]:
    encoded = value.encode("utf-8", errors="replace")
    return {
        "sha256": sha256(encoded).hexdigest(),
        "bytes": len(encoded),
        "preview": value[:limit],
        "truncated": len(value) > limit,
    }


def envelope_to_dict(envelope: EffectEnvelope) -> dict[str, object]:
    return {
        "executable_path": envelope.executable_path,
        "executable_sha256": envelope.executable_sha256,
        "argv": list(envelope.argv),
        "workdir": envelope.workdir,
        "source_sha": envelope.source_sha,
        "profile": envelope.profile,
        "expires_at_ns": envelope.expires_at_ns,
        "surfaces": [asdict(surface) for surface in envelope.surfaces],
    }


def envelope_from_dict(payload: dict[str, object]) -> EffectEnvelope:
    surfaces_raw = payload.get("surfaces")
    if not isinstance(surfaces_raw, list):
        raise ProofError("plan_surfaces_invalid")
    surfaces = []
    for raw in surfaces_raw:
        if not isinstance(raw, dict):
            raise ProofError("plan_surface_invalid")
        surfaces.append(
            SurfaceSpec(
                str(raw["root"]),
                str(raw["role"]),  # type: ignore[arg-type]
                tuple(str(item) for item in raw.get("exclude", ())),
            )
        )
    try:
        return EffectEnvelope(
            executable_path=str(payload["executable_path"]),
            executable_sha256=str(payload["executable_sha256"]),
            argv=tuple(str(item) for item in payload["argv"]),  # type: ignore[index]
            workdir=str(payload["workdir"]),
            source_sha=str(payload["source_sha"]),
            profile=str(payload["profile"]),
            expires_at_ns=int(payload["expires_at_ns"]),
            surfaces=tuple(surfaces),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProofError("plan_envelope_invalid") from exc


def freeze_plan(payload: dict[str, object]) -> dict[str, object]:
    if "plan_hash" in payload:
        raise ProofError("plan_hash_must_not_be_prepopulated")
    frozen = dict(payload)
    frozen["plan_hash"] = _hash_json(payload)
    return frozen


def verify_plan_hash(plan: dict[str, object]) -> bool:
    expected = plan.get("plan_hash")
    if not isinstance(expected, str):
        return False
    body = {key: value for key, value in plan.items() if key != "plan_hash"}
    return _hash_json(body) == expected


def _write_plan(path: Path, plan: dict[str, object]) -> None:
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)


def _load_plan(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProofError("plan_unreadable") from exc
    if not isinstance(value, dict) or value.get("schema") != PLAN_SCHEMA:
        raise ProofError("plan_schema_invalid")
    if not verify_plan_hash(value):
        raise ProofError("plan_hash_invalid")
    return value


def _prepare(args: argparse.Namespace) -> int:
    repo_root = Path(_git(Path.cwd(), "rev-parse", "--show-toplevel")).resolve()
    proof_source_sha = _git(repo_root, "rev-parse", "HEAD")
    if _git(repo_root, "status", "--porcelain"):
        raise ProofError("proof_source_worktree_not_clean")
    try:
        _git(repo_root, "cat-file", "-e", f"{args.target_sha}^{{commit}}")
    except ProofError as exc:
        raise ProofError("target_sha_not_available_locally_fetch_origin_main_first") from exc

    codex_input = args.codex or shutil.which("codex")
    if not codex_input:
        raise ProofError("codex_not_found")
    codex_path = Path(os.path.realpath(codex_input))
    if not codex_path.is_file():
        raise ProofError("codex_not_regular_file")

    seatbelt = Path("/usr/bin/sandbox-exec")
    if platform.system() != "Darwin" or not seatbelt.is_file():
        raise ProofError("macos_sandbox_exec_required")

    pulpo_home = (Path.home() / ".pulpo").resolve()
    codex_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))).expanduser().resolve()
    state_path = pulpo_home / "kernel.db"
    if not state_path.exists():
        raise ProofError(f"canonical_local_state_missing:{state_path}")

    proof_id = str(uuid.uuid4())
    session_root = Path(tempfile.mkdtemp(prefix=f"pulpo-effect-{proof_id[:8]}-")).resolve()
    control_root = session_root / "control"
    runtime_root = session_root / "runtime"
    target_worktree = session_root / "target"
    control_root.mkdir()
    runtime_root.mkdir()
    (runtime_root / "log").mkdir()
    (runtime_root / "sqlite").mkdir()
    _clone_target(repo_root, target_worktree, args.target_sha)

    profile_path = control_root / "seatbelt.sb"
    profile_text = build_seatbelt_profile(
        runtime_root,
        protected_read_roots=(pulpo_home, Path.home() / ".ssh"),
    )
    profile_path.write_text(profile_text, encoding="utf-8")
    os.chmod(profile_path, 0o600)

    codex_sha = _sha256_file(codex_path)
    seatbelt_sha = _sha256_file(seatbelt)
    seatbelt_profile_sha = sha256(profile_text.encode()).hexdigest()
    env = sanitize_environment(dict(os.environ), runtime_root, codex_home=codex_home)
    version_text = _version_probe(seatbelt, profile_path, codex_path, env, args.expected_codex_version)

    codex_argv = build_codex_argv(codex_path, target_worktree, runtime_root, args.prompt)
    spawn_argv = build_spawn_argv(seatbelt, profile_path, codex_argv)
    command_hash = _hash_json(list(spawn_argv))
    binding = profile_binding(
        codex_sha256=codex_sha,
        seatbelt_sha256=seatbelt_sha,
        seatbelt_profile_sha256=seatbelt_profile_sha,
    )
    envelope = EffectEnvelope(
        executable_path=str(seatbelt),
        executable_sha256=seatbelt_sha,
        argv=spawn_argv,
        workdir=str(target_worktree),
        source_sha=args.target_sha,
        profile=binding,
        expires_at_ns=time.time_ns() + args.expiry_seconds * 1_000_000_000,
        surfaces=(
            SurfaceSpec(str(control_root), "protected"),
            SurfaceSpec(str(target_worktree), "protected"),
            SurfaceSpec(str(codex_home), "protected"),
            SurfaceSpec(str(pulpo_home), "protected"),
            SurfaceSpec(str(runtime_root), "writable"),
        ),
    )
    bound_resource = bind_resource_to_effect_envelope(BASE_RESOURCE, envelope)

    plan_body: dict[str, object] = {
        "schema": PLAN_SCHEMA,
        "proof_id": proof_id,
        "proof_source_repo": str(repo_root),
        "proof_source_sha": proof_source_sha,
        "target_sha": args.target_sha,
        "session_root": str(session_root),
        "control_root": str(control_root),
        "runtime_root": str(runtime_root),
        "target_worktree": str(target_worktree),
        "profile_path": str(profile_path),
        "canonical_state_path": str(state_path),
        "pulpo_home": str(pulpo_home),
        "codex_home": str(codex_home),
        "codex_path": str(codex_path),
        "codex_sha256": codex_sha,
        "codex_version_expected": args.expected_codex_version,
        "codex_version_probe": version_text,
        "seatbelt_path": str(seatbelt),
        "seatbelt_sha256": seatbelt_sha,
        "seatbelt_profile_sha256": seatbelt_profile_sha,
        "command_hash": command_hash,
        "effect_envelope": envelope_to_dict(envelope),
        "effect_envelope_hash": envelope.envelope_hash,
        "bound_resource": bound_resource,
        "prompt": args.prompt,
        "timeout_seconds": args.timeout,
        "prepared_at_ns": time.time_ns(),
    }
    plan = freeze_plan(plan_body)
    plan_path = control_root / "plan.json"
    _write_plan(plan_path, plan)

    print(json.dumps({
        "status": "READY_NOT_FIRED",
        "plan": str(plan_path),
        "plan_hash": plan["plan_hash"],
        "proof_source_sha": proof_source_sha,
        "target_sha": args.target_sha,
        "effect_envelope_hash": envelope.envelope_hash,
        "command_hash": command_hash,
        "codex_sha256": codex_sha,
        "codex_version_probe": version_text,
        "seatbelt_sha256": seatbelt_sha,
        "seatbelt_profile_sha256": seatbelt_profile_sha,
        "expires_at_ns": envelope.expires_at_ns,
        "next_boundary": "explicit_fire_exact_envelope_hash",
    }, indent=2, sort_keys=True))
    return 0


def _revalidate_plan(plan_path: Path, plan: dict[str, object], expected_envelope_hash: str) -> tuple[EffectEnvelope, dict[str, str]]:
    envelope_raw = plan.get("effect_envelope")
    if not isinstance(envelope_raw, dict):
        raise ProofError("plan_envelope_missing")
    envelope = envelope_from_dict(envelope_raw)
    if envelope.envelope_hash != plan.get("effect_envelope_hash"):
        raise ProofError("plan_envelope_hash_mismatch")
    if envelope.envelope_hash != expected_envelope_hash:
        raise ProofError("operator_fire_hash_mismatch")
    if time.time_ns() >= envelope.expires_at_ns:
        raise ProofError("effect_envelope_expired_before_fire")

    control_root = Path(str(plan["control_root"])).resolve()
    session_root = Path(str(plan["session_root"])).resolve()
    runtime_root = Path(str(plan["runtime_root"])).resolve()
    target_worktree = Path(str(plan["target_worktree"])).resolve()
    if plan_path.resolve() != control_root / "plan.json":
        raise ProofError("plan_location_mismatch")
    for child in (control_root, runtime_root, target_worktree):
        if os.path.commonpath((str(child), str(session_root))) != str(session_root):
            raise ProofError("plan_path_escape")

    repo_root = Path(str(plan["proof_source_repo"])).resolve()
    if _git(repo_root, "rev-parse", "HEAD") != plan.get("proof_source_sha"):
        raise ProofError("proof_source_sha_changed_after_prepare")
    if _git(repo_root, "status", "--porcelain"):
        raise ProofError("proof_source_worktree_changed_after_prepare")
    if _git(target_worktree, "rev-parse", "HEAD") != plan.get("target_sha"):
        raise ProofError("target_sha_changed_after_prepare")
    if _git(target_worktree, "status", "--porcelain"):
        raise ProofError("target_worktree_changed_after_prepare")

    codex_path = Path(str(plan["codex_path"])).resolve()
    seatbelt = Path(str(plan["seatbelt_path"])).resolve()
    profile_path = Path(str(plan["profile_path"])).resolve()
    if _sha256_file(codex_path) != plan.get("codex_sha256"):
        raise ProofError("codex_identity_changed_after_prepare")
    if _sha256_file(seatbelt) != plan.get("seatbelt_sha256"):
        raise ProofError("seatbelt_identity_changed_after_prepare")
    profile_sha = sha256(profile_path.read_bytes()).hexdigest()
    if profile_sha != plan.get("seatbelt_profile_sha256"):
        raise ProofError("seatbelt_profile_changed_after_prepare")
    if _hash_json(list(envelope.argv)) != plan.get("command_hash"):
        raise ProofError("command_hash_changed_after_prepare")
    if bind_resource_to_effect_envelope(BASE_RESOURCE, envelope) != plan.get("bound_resource"):
        raise ProofError("bound_resource_changed_after_prepare")

    state_path = Path(str(plan["canonical_state_path"])).resolve()
    if not state_path.is_file():
        raise ProofError("canonical_local_state_missing_at_fire")
    codex_home = Path(str(plan["codex_home"])).resolve()
    env = sanitize_environment(dict(os.environ), runtime_root, codex_home=codex_home)
    observed_version = _version_probe(
        seatbelt,
        profile_path,
        codex_path,
        env,
        str(plan["codex_version_expected"]),
    )
    return envelope, {"version_probe": observed_version, **env}


def _fire(args: argparse.Namespace) -> int:
    if platform.system() != "Darwin":
        raise ProofError("macos_required_for_fire")
    plan_path = Path(args.plan).expanduser().resolve()
    plan = _load_plan(plan_path)
    envelope, env_with_probe = _revalidate_plan(plan_path, plan, args.expected_envelope_hash)
    version_probe = env_with_probe.pop("version_probe")
    env = env_with_probe

    from pulpo.kernel import AgentGrant, GovernanceKernel, Intent, Policy
    from pulpo.state import SQLiteKernelState

    proof_id = str(plan["proof_id"])
    state_path = Path(str(plan["canonical_state_path"])).resolve()
    pulpo_home = Path(str(plan["pulpo_home"])).resolve()
    session_root = Path(str(plan["session_root"])).resolve()
    timeout_seconds = int(plan["timeout_seconds"])
    spawn_argv = envelope.argv
    state = SQLiteKernelState(state_path)
    try:
        kernel = GovernanceKernel(
            Policy(
                allowed_actions=frozenset({"run_codex_readonly"}),
                max_cost=0,
                agent_grants=(
                    AgentGrant(
                        principal="local:owner",
                        allowed_actions=frozenset({"run_codex_readonly"}),
                        resource_prefixes=(f"{BASE_RESOURCE}#pulpo-effect-envelope=",),
                        max_cost=0,
                    ),
                ),
            ),
            state=state,
        )
        audit_tip_before = kernel.audit[-1]["hash"] if kernel.audit else "0" * 64
        _append(state, "local_effect_operator_fire", {
            "proof_id": proof_id,
            "plan_hash": plan["plan_hash"],
            "effect_envelope_hash": envelope.envelope_hash,
            "operator_confirmation": args.expected_envelope_hash,
            "authority_evidence": "local_terminal_exact_hash_confirmation",
        })
        _append(state, "local_effect_envelope_frozen", {
            "proof_id": proof_id,
            "proof_source_sha": plan["proof_source_sha"],
            "target_sha": plan["target_sha"],
            "effect_envelope_hash": envelope.envelope_hash,
            "command_hash": plan["command_hash"],
            "codex_sha256": plan["codex_sha256"],
            "seatbelt_sha256": plan["seatbelt_sha256"],
            "seatbelt_profile_sha256": plan["seatbelt_profile_sha256"],
            "authority_effect": "none",
        })

        generic = Intent(principal="local:owner", action="run", resource=BASE_RESOURCE, session_id=proof_id)
        generic_decision = kernel.evaluate(generic)
        exact = Intent(
            principal="local:owner",
            action="run_codex_readonly",
            resource=str(plan["bound_resource"]),
            session_id=proof_id,
        )
        decision = kernel.evaluate(exact)
        if generic_decision.outcome != "deny" or decision.outcome != "allow" or decision.permit is None:
            raise ProofError("governance_precondition_failed")
        if time.time_ns() >= envelope.expires_at_ns:
            raise ProofError("effect_envelope_expired_before_consumption")
        if not kernel.consume(decision.permit, exact):
            raise ProofError("permit_consumption_failed")

        execution_id = str(uuid.uuid4())
        execution_started_ns = time.time_ns()
        _append(state, "execution_started", {
            "execution_id": execution_id,
            "intent_hash": decision.intent_hash,
            "effect_envelope_hash": envelope.envelope_hash,
            "command_hash": plan["command_hash"],
            "profile": PROFILE_NAME,
        })

        before = capture_envelope_surfaces(envelope)
        exit_code, timed_out, stdout, stderr = _run_child(spawn_argv, env, timeout_seconds)
        after = capture_envelope_surfaces(envelope)
        reconciliation = reconcile_effects(
            envelope,
            ExecutionIdentity(
                executable_path=envelope.executable_path,
                executable_sha256=envelope.executable_sha256,
                argv=envelope.argv,
                workdir=envelope.workdir,
                source_sha=envelope.source_sha,
                profile=envelope.profile,
            ),
            before,
            after,
            execution_started_ns=execution_started_ns,
            observation_complete=True,
        )

        _append(state, "execution_finished", {
            "execution_id": execution_id,
            "intent_hash": decision.intent_hash,
            "exit_code": exit_code,
            "timed_out": timed_out,
        })
        _append(state, "effect_reconciled", {
            "execution_id": execution_id,
            "intent_hash": decision.intent_hash,
            "effect_envelope_hash": envelope.envelope_hash,
            "reconciliation": reconciliation.status,
            "reconciliation_hash": reconciliation.reconciliation_hash,
            "protected_surface_delta": reconciliation.protected_surface_delta,
            "unauthorized_effects": reconciliation.unauthorized_effects,
            "uncertain_effects": reconciliation.uncertain_effects,
        })
        replay_denied = not kernel.consume(decision.permit, exact)
        audit_valid = kernel.verify_audit()
        audit_tip_after = kernel.audit[-1]["hash"] if kernel.audit else "0" * 64
        passed = overall_pass(
            exit_code=exit_code,
            timed_out=timed_out,
            reconciliation_status=reconciliation.status,
            replay_denied=replay_denied,
            audit_valid=audit_valid,
        )
        core_bundle = {
            "schema": BUNDLE_SCHEMA,
            "proof_id": proof_id,
            "result": "verified" if passed else "failed",
            "plan_hash": plan["plan_hash"],
            "proof_source_sha": plan["proof_source_sha"],
            "target_sha": plan["target_sha"],
            "codex": {
                "path": plan["codex_path"],
                "sha256": plan["codex_sha256"],
                "version_probe_prepare": plan["codex_version_probe"],
                "version_probe_fire": version_probe,
            },
            "seatbelt": {
                "path": plan["seatbelt_path"],
                "sha256": plan["seatbelt_sha256"],
                "profile_sha256": plan["seatbelt_profile_sha256"],
            },
            "command_hash": plan["command_hash"],
            "effect_envelope_hash": envelope.envelope_hash,
            "intent_hash": decision.intent_hash,
            "execution_id": execution_id,
            "operator_confirmation": args.expected_envelope_hash,
            "generic_decision": asdict(generic_decision),
            "exact_decision": {"outcome": decision.outcome, "reason": decision.reason, "intent_hash": decision.intent_hash},
            "permit_consumed": True,
            "replay_denied": replay_denied,
            "execution": {
                "exit_code": exit_code,
                "timed_out": timed_out,
                "stdout": _bounded_text(stdout),
                "stderr": _bounded_text(stderr),
            },
            "before": _snapshot_summary(before),
            "after": _snapshot_summary(after),
            "reconciliation": {
                "status": reconciliation.status,
                "reason": reconciliation.reason,
                "hash": reconciliation.reconciliation_hash,
                "protected_surface_delta": reconciliation.protected_surface_delta,
                "unauthorized_effects": reconciliation.unauthorized_effects,
                "uncertain_effects": reconciliation.uncertain_effects,
                "authorized_runtime_effects": reconciliation.authorized_runtime_effects,
                "deltas": [asdict(delta) for delta in reconciliation.deltas],
            },
            "audit": {
                "tip_before": audit_tip_before,
                "tip_after_replay": audit_tip_after,
                "valid_before_bundle": audit_valid,
            },
            "session_root": str(session_root),
            "scope_note": "filesystem effects of the contained Codex process tree; network/remote consequence is not admitted by this proof",
        }
        core_bundle_hash = _hash_json(core_bundle)
        _append(state, "local_effect_proof_bundle", {
            "proof_id": proof_id,
            "core_bundle_hash": core_bundle_hash,
            "result": core_bundle["result"],
            "authority_effect": "none",
        })
        final_audit_valid = kernel.verify_audit()
        final_audit_tip = kernel.audit[-1]["hash"] if kernel.audit else "0" * 64
        projection = {
            **core_bundle,
            "core_bundle_hash": core_bundle_hash,
            "audit_final_tip": final_audit_tip,
            "audit_final_valid": final_audit_valid,
        }

        evidence_dir = pulpo_home / "evidence" / "local-intelligence-v1"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        evidence_path = evidence_dir / f"{proof_id}.json"
        evidence_path.write_text(json.dumps(projection, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(evidence_path, 0o600)

        print(json.dumps({
            "result": core_bundle["result"],
            "reconciliation": reconciliation.status,
            "effect_envelope_hash": envelope.envelope_hash,
            "intent_hash": decision.intent_hash,
            "replay_denied": replay_denied,
            "audit_valid": final_audit_valid,
            "evidence": str(evidence_path),
            "session_root": str(session_root),
        }, indent=2, sort_keys=True))

        if passed and final_audit_valid:
            shutil.rmtree(session_root, ignore_errors=True)
            return 0
        return 2
    finally:
        state.close()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare", action="store_true", help="Freeze an exact plan without granting authority")
    mode.add_argument("--fire", action="store_true", help="Consume authority for an exact prepared envelope")
    parser.add_argument("--target-sha", help="Exact canonical commit the child may inspect (prepare only)")
    parser.add_argument("--codex", default=None, help="Exact Codex executable path; defaults to command -v codex")
    parser.add_argument("--expected-codex-version", default=EXPECTED_CODEX_VERSION)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--expiry-seconds", type=int, default=DEFAULT_EXPIRY_SECONDS)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--plan", help="Prepared plan.json (fire only)")
    parser.add_argument("--expected-envelope-hash", help="Exact hash echoed by the operator (fire only)")
    args = parser.parse_args(argv)
    if args.prepare:
        if not args.target_sha:
            parser.error("--prepare requires --target-sha")
        if args.plan or args.expected_envelope_hash:
            parser.error("--plan/--expected-envelope-hash are fire-only")
        if args.expiry_seconds <= 0 or args.timeout <= 0:
            parser.error("timeouts must be positive")
    else:
        if not args.plan or not args.expected_envelope_hash:
            parser.error("--fire requires --plan and --expected-envelope-hash")
        if args.target_sha or args.codex:
            parser.error("--target-sha/--codex are prepare-only; fire reuses the frozen plan")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return _prepare(args) if args.prepare else _fire(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProofError as exc:
        print(f"proof_error={exc}", file=sys.stderr)
        raise SystemExit(2)

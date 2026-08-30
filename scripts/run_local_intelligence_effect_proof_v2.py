#!/usr/bin/env python3
"""V2 operator-host ceremony with a disposable Codex home.

The real Codex home remains observed as a protected surface. Mutable Codex state
is directed into the already-authorized runtime island. If file-based login
exists, PREPARE binds only the source auth.json hash; FIRE revalidates that hash,
stages a 0600 copy into the disposable home, and removes the staged credential in
a finally block. No write-through path to the real Codex home is introduced.
"""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import tempfile
import time
import uuid

from pulpo.effect_reconcile import EffectEnvelope, SurfaceSpec, bind_resource_to_effect_envelope
from scripts import run_local_intelligence_effect_proof as v1


PROFILE_NAME = "permit-bound-local-intelligence-v2-disposable-codex-home"
AUTH_PROJECTION_MODE = "fire-staged-copy-0600"


def prepare_runtime_codex_home(real_codex_home: Path, runtime_root: Path) -> tuple[Path, Path | None, str | None, str]:
    runtime_codex_home = (runtime_root / "codex-home").resolve()
    runtime_codex_home.mkdir(parents=True, exist_ok=False)
    auth_source = (real_codex_home / "auth.json").resolve()
    if auth_source.is_file():
        return runtime_codex_home, auth_source, v1._sha256_file(auth_source), AUTH_PROJECTION_MODE
    return runtime_codex_home, None, None, "none"


def stage_runtime_auth_copy(
    auth_source: Path | None,
    expected_sha256: str | None,
    runtime_codex_home: Path,
) -> Path | None:
    if auth_source is None:
        if expected_sha256 is not None:
            raise v1.ProofError("auth_source_hash_without_source")
        return None
    if expected_sha256 is None:
        raise v1.ProofError("auth_source_missing_hash")
    if not auth_source.is_file():
        raise v1.ProofError("auth_source_missing_at_fire")
    if v1._sha256_file(auth_source) != expected_sha256:
        raise v1.ProofError("auth_source_changed_after_prepare")
    staged = runtime_codex_home / "auth.json"
    if staged.exists() or staged.is_symlink():
        raise v1.ProofError("runtime_auth_projection_preexists")
    shutil.copyfile(auth_source, staged)
    os.chmod(staged, 0o600)
    if v1._sha256_file(staged) != expected_sha256:
        staged.unlink(missing_ok=True)
        raise v1.ProofError("runtime_auth_projection_hash_mismatch")
    return staged


def v2_profile_binding(
    *,
    codex_sha256: str,
    seatbelt_sha256: str,
    seatbelt_profile_sha256: str,
    runtime_codex_home: Path,
    real_codex_home: Path,
    auth_projection_mode: str,
    auth_source_sha256: str | None,
) -> str:
    return (
        f"{PROFILE_NAME};codex_sha256={codex_sha256};"
        f"seatbelt_sha256={seatbelt_sha256};seatbelt_profile_sha256={seatbelt_profile_sha256};"
        f"runtime_codex_home={runtime_codex_home};real_codex_home={real_codex_home};"
        f"auth_projection_mode={auth_projection_mode};auth_source_sha256={auth_source_sha256 or 'none'}"
    )


def _prepare(args) -> int:
    repo_root = Path(v1._git(Path.cwd(), "rev-parse", "--show-toplevel")).resolve()
    proof_source_sha = v1._git(repo_root, "rev-parse", "HEAD")
    if v1._git(repo_root, "status", "--porcelain"):
        raise v1.ProofError("proof_source_worktree_not_clean")
    try:
        v1._git(repo_root, "cat-file", "-e", f"{args.target_sha}^{{commit}}")
    except v1.ProofError as exc:
        raise v1.ProofError("target_sha_not_available_locally_fetch_origin_main_first") from exc

    codex_input = args.codex or shutil.which("codex")
    if not codex_input:
        raise v1.ProofError("codex_not_found")
    codex_path = Path(os.path.realpath(codex_input))
    if not codex_path.is_file():
        raise v1.ProofError("codex_not_regular_file")

    seatbelt = Path("/usr/bin/sandbox-exec")
    if platform.system() != "Darwin" or not seatbelt.is_file():
        raise v1.ProofError("macos_sandbox_exec_required")

    pulpo_home = (Path.home() / ".pulpo").resolve()
    real_codex_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))).expanduser().resolve()
    state_path = pulpo_home / "kernel.db"
    if not state_path.exists():
        raise v1.ProofError(f"canonical_local_state_missing:{state_path}")

    proof_id = str(uuid.uuid4())
    session_root = Path(tempfile.mkdtemp(prefix=f"pulpo-effect-v2-{proof_id[:8]}-")).resolve()
    control_root = session_root / "control"
    runtime_root = session_root / "runtime"
    target_worktree = session_root / "target"
    control_root.mkdir()
    runtime_root.mkdir()
    (runtime_root / "log").mkdir()
    (runtime_root / "sqlite").mkdir()
    runtime_codex_home, auth_source, auth_source_sha256, auth_projection_mode = prepare_runtime_codex_home(
        real_codex_home, runtime_root
    )
    v1._clone_target(repo_root, target_worktree, args.target_sha)

    profile_path = control_root / "seatbelt.sb"
    profile_text = v1.build_seatbelt_profile(
        runtime_root,
        protected_read_roots=(pulpo_home, Path.home() / ".ssh"),
    )
    profile_path.write_text(profile_text, encoding="utf-8")
    os.chmod(profile_path, 0o600)

    codex_sha = v1._sha256_file(codex_path)
    seatbelt_sha = v1._sha256_file(seatbelt)
    seatbelt_profile_sha = sha256(profile_text.encode()).hexdigest()
    env = v1.sanitize_environment(dict(os.environ), runtime_root, codex_home=runtime_codex_home)
    version_text = v1._version_probe(seatbelt, profile_path, codex_path, env, args.expected_codex_version)

    codex_argv = v1.build_codex_argv(codex_path, target_worktree, runtime_root, args.prompt)
    spawn_argv = v1.build_spawn_argv(seatbelt, profile_path, codex_argv)
    command_hash = v1._hash_json(list(spawn_argv))
    binding = v2_profile_binding(
        codex_sha256=codex_sha,
        seatbelt_sha256=seatbelt_sha,
        seatbelt_profile_sha256=seatbelt_profile_sha,
        runtime_codex_home=runtime_codex_home,
        real_codex_home=real_codex_home,
        auth_projection_mode=auth_projection_mode,
        auth_source_sha256=auth_source_sha256,
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
            SurfaceSpec(str(real_codex_home), "protected"),
            SurfaceSpec(str(pulpo_home), "protected"),
            SurfaceSpec(str(runtime_root), "writable"),
        ),
    )
    bound_resource = bind_resource_to_effect_envelope(v1.BASE_RESOURCE, envelope)

    plan_body = {
        "schema": v1.PLAN_SCHEMA,
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
        "codex_home": str(runtime_codex_home),
        "real_codex_home": str(real_codex_home),
        "auth_source": str(auth_source) if auth_source else None,
        "auth_source_sha256": auth_source_sha256,
        "auth_projection_mode": auth_projection_mode,
        "codex_path": str(codex_path),
        "codex_sha256": codex_sha,
        "codex_version_expected": args.expected_codex_version,
        "codex_version_probe": version_text,
        "seatbelt_path": str(seatbelt),
        "seatbelt_sha256": seatbelt_sha,
        "seatbelt_profile_sha256": seatbelt_profile_sha,
        "command_hash": command_hash,
        "effect_envelope": v1.envelope_to_dict(envelope),
        "effect_envelope_hash": envelope.envelope_hash,
        "bound_resource": bound_resource,
        "prompt": args.prompt,
        "timeout_seconds": args.timeout,
        "prepared_at_ns": time.time_ns(),
    }
    plan = v1.freeze_plan(plan_body)
    plan_path = control_root / "plan.json"
    v1._write_plan(plan_path, plan)

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
        "runtime_codex_home": str(runtime_codex_home),
        "real_codex_home": str(real_codex_home),
        "auth_projection_mode": auth_projection_mode,
        "auth_source_sha256": auth_source_sha256,
        "seatbelt_sha256": seatbelt_sha,
        "seatbelt_profile_sha256": seatbelt_profile_sha,
        "expires_at_ns": envelope.expires_at_ns,
        "next_boundary": "explicit_fire_exact_envelope_hash",
    }, indent=2, sort_keys=True))
    return 0


def _fire(args) -> int:
    plan_path = Path(args.plan).expanduser().resolve()
    plan = v1._load_plan(plan_path)
    runtime_codex_home = Path(str(plan["codex_home"])).resolve()
    auth_source_raw = plan.get("auth_source")
    auth_source = Path(str(auth_source_raw)).resolve() if auth_source_raw else None
    expected_auth_sha = plan.get("auth_source_sha256")
    if expected_auth_sha is not None and not isinstance(expected_auth_sha, str):
        raise v1.ProofError("auth_source_hash_invalid")
    staged = stage_runtime_auth_copy(auth_source, expected_auth_sha, runtime_codex_home)
    try:
        return v1._fire(args)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = v1.parse_args(argv)
    return _prepare(args) if args.prepare else _fire(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except v1.ProofError as exc:
        print(f"proof_error={exc}", file=__import__("sys").stderr)
        raise SystemExit(2)

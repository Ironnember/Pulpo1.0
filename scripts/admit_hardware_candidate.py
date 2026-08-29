#!/usr/bin/env python3
"""Verify or explicitly admit one hardware WebAuthn candidate.

Default behavior is verification only and has no authority effect. Writing an
active local-authority credential file requires `--fire-candidate-hash` to equal
the recomputed exact candidate hash. The destination is create-only and never
overwritten.

This tool does not modify a running authority process or canonical Pulpo policy.
The resulting credentials file is authority-bearing configuration only when a
separately launched authority runtime is explicitly pointed at it.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from typing import Any
from urllib.parse import urlparse


CANDIDATE_SCHEMA = "pulpo.webauthn-credential-candidate.v0"
CREDENTIALS_SCHEMA = "pulpo.local-authority-credentials.v0"


class AdmissionBlocked(RuntimeError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _absolute_file(value: str, field: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise AdmissionBlocked(f"{field} must be an absolute path")
    if path.is_symlink():
        raise AdmissionBlocked(f"{field} must not be a symlink")
    if not path.is_file():
        raise AdmissionBlocked(f"{field} is unavailable")
    return path


def _absolute_output(value: str, field: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise AdmissionBlocked(f"{field} must be an absolute path")
    if path.is_symlink():
        raise AdmissionBlocked(f"{field} must not be a symlink")
    return path


def _require_digest(value: str, field: str) -> str:
    if (
        len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AdmissionBlocked(f"{field} must be one lowercase SHA-256 digest")
    return value


def _expected_candidate_fields() -> set[str]:
    return {
        "rp_id",
        "origin",
        "role",
        "credential_id",
        "public_key_hex",
        "sign_count",
        "aaguid",
        "attestation_format",
        "attestation_object_hash",
        "credential_device_type",
        "credential_backed_up",
        "user_verified",
        "authenticator_attachment",
        "created_at_ns",
        "schema",
        "admission_class",
        "authority_effect",
        "candidate_hash",
        "runtime_record",
    }


def verify_candidate(
    candidate_path: Path,
    *,
    expected_rp_id: str,
    expected_origin: str,
    expected_role: str,
    expected_candidate_hash: str | None = None,
) -> dict[str, object]:
    candidate_path = _absolute_file(str(candidate_path), "candidate_path")
    mode = stat.S_IMODE(candidate_path.stat().st_mode)
    if mode & 0o077:
        raise AdmissionBlocked("candidate file must not be group/world accessible")
    try:
        value = json.loads(candidate_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdmissionBlocked("candidate file is invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != _expected_candidate_fields():
        raise AdmissionBlocked("candidate file has an unexpected shape")

    if value["schema"] != CANDIDATE_SCHEMA:
        raise AdmissionBlocked("unsupported candidate schema")
    if value["admission_class"] != "local_acceptance_candidate_only":
        raise AdmissionBlocked("candidate admission class is not local acceptance")
    if value["authority_effect"] != "none_until_explicit_admission":
        raise AdmissionBlocked("candidate authority-effect marker is invalid")
    if value["rp_id"] != expected_rp_id:
        raise AdmissionBlocked("candidate rp_id does not match the locked target")
    if value["origin"] != expected_origin:
        raise AdmissionBlocked("candidate origin does not match the locked target")
    if value["role"] != expected_role or expected_role not in {"primary", "recovery"}:
        raise AdmissionBlocked("candidate role does not match the locked target")

    parsed_origin = urlparse(expected_origin)
    if (
        parsed_origin.scheme != "https"
        or parsed_origin.hostname is None
        or (
            parsed_origin.hostname != expected_rp_id
            and not parsed_origin.hostname.endswith(f".{expected_rp_id}")
        )
    ):
        raise AdmissionBlocked("locked RP/origin relationship is invalid")

    if value["authenticator_attachment"] != "cross-platform":
        raise AdmissionBlocked("candidate is not a cross-platform security key")
    if value["credential_device_type"] != "single_device":
        raise AdmissionBlocked("candidate is not a single-device credential")
    if value["credential_backed_up"] is not False:
        raise AdmissionBlocked("candidate is backed up")
    if value["user_verified"] is not True:
        raise AdmissionBlocked("candidate lacks verified user presence")
    if value["attestation_format"] == "none" or not isinstance(value["attestation_format"], str):
        raise AdmissionBlocked("candidate lacks direct authenticator attestation")
    _require_digest(value["attestation_object_hash"], "attestation_object_hash")
    if isinstance(value["sign_count"], bool) or not isinstance(value["sign_count"], int) or value["sign_count"] < 0:
        raise AdmissionBlocked("candidate sign_count is invalid")
    if not isinstance(value["created_at_ns"], int) or isinstance(value["created_at_ns"], bool) or value["created_at_ns"] <= 0:
        raise AdmissionBlocked("candidate creation time is invalid")
    public_key_hex = value["public_key_hex"]
    if (
        not isinstance(public_key_hex, str)
        or not public_key_hex
        or len(public_key_hex) % 2
        or any(character not in "0123456789abcdef" for character in public_key_hex)
    ):
        raise AdmissionBlocked("candidate public key is invalid")
    if not isinstance(value["credential_id"], str) or not value["credential_id"]:
        raise AdmissionBlocked("candidate credential id is invalid")

    runtime_record = value["runtime_record"]
    expected_runtime = {
        "credential_id": value["credential_id"],
        "public_key_hex": value["public_key_hex"],
        "sign_count": value["sign_count"],
        "role": value["role"],
        "active": True,
        "hardware_attested": True,
        "backup_eligible": False,
    }
    if runtime_record != expected_runtime:
        raise AdmissionBlocked("candidate runtime record diverges from public credential material")

    hash_material = dict(value)
    stored_hash = _require_digest(hash_material.pop("candidate_hash"), "candidate_hash")
    hash_material.pop("runtime_record")
    actual_hash = _digest(hash_material)
    if stored_hash != actual_hash:
        raise AdmissionBlocked("candidate hash mismatch")
    if expected_candidate_hash is not None:
        expected_candidate_hash = _require_digest(expected_candidate_hash, "expected_candidate_hash")
        if expected_candidate_hash != actual_hash:
            raise AdmissionBlocked("candidate does not match the explicitly locked hash")

    return {
        "schema": "pulpo.hardware-candidate-verification.v0",
        "candidate_path": str(candidate_path),
        "candidate_hash": actual_hash,
        "rp_id": value["rp_id"],
        "origin": value["origin"],
        "role": value["role"],
        "credential_id_hash": sha256(value["credential_id"].encode()).hexdigest(),
        "attestation_format": value["attestation_format"],
        "aaguid": value["aaguid"],
        "runtime_record": expected_runtime,
        "candidate_verified": True,
        "candidate_admitted": False,
        "authority_effect": "none",
    }


def admit_candidate(
    verification: dict[str, object],
    *,
    output_path: Path,
    fire_candidate_hash: str,
) -> dict[str, object]:
    fire_candidate_hash = _require_digest(fire_candidate_hash, "fire_candidate_hash")
    if verification.get("candidate_verified") is not True:
        raise AdmissionBlocked("candidate is not verified")
    if verification["candidate_hash"] != fire_candidate_hash:
        raise AdmissionBlocked("FIRE hash does not match the exact verified candidate")

    output_path = _absolute_output(str(output_path), "output_path")
    if output_path.exists():
        raise AdmissionBlocked("refusing to overwrite existing authority credential configuration")
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output_path.parent.is_symlink():
        raise AdmissionBlocked("output parent must not be a symlink")

    payload = {
        "schema": CREDENTIALS_SCHEMA,
        "credentials": [verification["runtime_record"]],
    }
    encoded = json.dumps(payload, sort_keys=True, indent=2).encode() + b"\n"
    try:
        descriptor = os.open(output_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise AdmissionBlocked("authority credential configuration already exists") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            output_path.unlink()
        except FileNotFoundError:
            pass
        raise
    output_path.chmod(0o600)

    return {
        **{key: value for key, value in verification.items() if key != "runtime_record"},
        "schema": "pulpo.hardware-candidate-admission.v0",
        "credentials_path": str(output_path),
        "candidate_admitted": True,
        "authority_effect": "local_authority_credential_configuration_created",
        "running_authority_modified": False,
        "permit_issued": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--expected-rp-id", required=True)
    parser.add_argument("--expected-origin", required=True)
    parser.add_argument("--expected-role", choices=("primary", "recovery"), required=True)
    parser.add_argument("--expected-candidate-hash")
    parser.add_argument("--output-credentials")
    parser.add_argument(
        "--fire-candidate-hash",
        help="authority-changing boundary: must equal the exact verified candidate hash",
    )
    args = parser.parse_args()

    try:
        verification = verify_candidate(
            Path(args.candidate),
            expected_rp_id=args.expected_rp_id,
            expected_origin=args.expected_origin,
            expected_role=args.expected_role,
            expected_candidate_hash=args.expected_candidate_hash,
        )
        if args.fire_candidate_hash is None:
            print(json.dumps(verification, sort_keys=True, indent=2))
            return 0
        if not args.output_credentials:
            raise AdmissionBlocked("--output-credentials is required with --fire-candidate-hash")
        result = admit_candidate(
            verification,
            output_path=Path(args.output_credentials),
            fire_candidate_hash=args.fire_candidate_hash,
        )
    except AdmissionBlocked as exc:
        print(f"hardware candidate admission blocked: {exc}", file=os.sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

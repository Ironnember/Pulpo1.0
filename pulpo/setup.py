"""Turnkey Pulpo setup and bounded performance-profile bootstrap.

Setup detects the local execution environment, loads or creates a machine-bound
performance profile, and verifies the selected audit-computation path. It does
not create authority, modify policy, issue permits, or claim production readiness.
"""

from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from typing import Sequence

from .performance_tuning import (
    AdaptiveAuditVerificationEngine,
    AuditPerformanceTuner,
    SystemFingerprint,
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def synthetic_audit_rows(count: int):
    if count <= 0:
        raise ValueError("count must be positive")
    rows = []
    previous = "0" * 64
    for index in range(count):
        payload = {"index": index, "kind": "pulpo-setup-calibration", "value": index % 257}
        payload_json = _canonical(payload).decode()
        body = {
            "event": "setup_calibration",
            "payload": payload,
            "previous_hash": previous,
            "timestamp_ns": index + 1,
        }
        digest = sha256(_canonical(body)).hexdigest()
        rows.append(("setup_calibration", payload_json, previous, index + 1, digest))
        previous = digest
    return rows


def _verify_profile(tuner: AuditPerformanceTuner) -> bool:
    rows = synthetic_audit_rows(64)
    engine = AdaptiveAuditVerificationEngine(tuner, cache_size=0)
    try:
        if not engine.verify_rows(rows):
            return False
        broken = list(rows)
        row = broken[-1]
        broken[-1] = (row[0], row[1], row[2], row[3], "f" * 64)
        return engine.verify_rows(broken) is False
    finally:
        engine.close()


def run_setup(
    *,
    profile_path: str | Path = ".pulpo/audit-performance-profile.json",
    benchmark_path: str | Path | None = None,
    calibrate_if_needed: bool = True,
    calibration_sizes: Sequence[int] = (10000, 50000, 100000),
    calibration_batches: Sequence[int] = (256, 1024, 4096),
    calibration_repeats: int = 1,
) -> dict[str, object]:
    """Resolve a local performance profile and return a readiness report."""

    profile_path = Path(profile_path)
    fingerprint = SystemFingerprint.detect()
    report: dict[str, object] = {
        "schema": "pulpo.setup-report.v1",
        "environment": {
            "status": "PASS",
            "fingerprint": asdict(fingerprint),
        },
        "profile_path": str(profile_path),
        "profile": {},
        "audit_verification": {"status": "UNKNOWN"},
        "authority_effect": "none",
        "governance_changes": "none",
        "production_readiness_claim": False,
    }

    tuner: AuditPerformanceTuner | None = None
    profile_status = ""
    profile_detail = ""

    if profile_path.exists():
        try:
            tuner = AuditPerformanceTuner.load(profile_path)
            profile_status = "LOADED"
            profile_detail = "machine-bound profile matched current environment"
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            profile_status = "STALE"
            profile_detail = str(exc)

    if tuner is None and benchmark_path is not None:
        benchmark_document = json.loads(Path(benchmark_path).read_text(encoding="utf-8"))
        tuner = AuditPerformanceTuner.from_benchmark_document(benchmark_document)
        tuner.save(profile_path)
        profile_status = "BUILT_FROM_BENCHMARK"
        profile_detail = "profile selected from supplied benchmark evidence"

    if tuner is None and calibrate_if_needed:
        largest = max(int(value) for value in calibration_sizes)
        rows = synthetic_audit_rows(largest)
        tuner = AuditPerformanceTuner.calibrate(
            rows,
            sizes=tuple(int(value) for value in calibration_sizes),
            batch_sizes=tuple(int(value) for value in calibration_batches),
            repeats=calibration_repeats,
        )
        tuner.save(profile_path)
        profile_status = "CALIBRATED"
        profile_detail = "bounded local synthetic calibration completed"

    if tuner is None:
        tuner = AuditPerformanceTuner.conservative()
        profile_status = "CONSERVATIVE_FALLBACK"
        profile_detail = "no valid local profile was available; conservative settings selected"

    verified = _verify_profile(tuner)
    report["profile"] = {
        "status": profile_status,
        "detail": profile_detail,
        "profiles": [asdict(profile) for profile in tuner.profiles],
    }
    report["audit_verification"] = {
        "status": "PASS" if verified else "FAIL",
        "checks": [
            "valid audit accepted",
            "tampered stored hash rejected",
        ],
    }
    report["ready_for_test_use"] = bool(verified)
    return report

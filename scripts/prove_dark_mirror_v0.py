#!/usr/bin/env python3
"""Reproduce Pulpo's Dark Mirror software proof and emit a verifiable packet.

This runner deliberately exercises existing canonical tests. It performs no
provider write, consumes no production authority, and uses only temporary local
state created by the tests themselves.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / ".pulpo-artifacts" / "dark-mirror-proof-v0.json"

CASES = (
    {
        "lens": "light",
        "claim": "An exact provider claim remains unverified until reconciliation.",
        "test": "tests.test_custody_executor.CustodyExecutorTests.test_provider_success_is_only_a_claim_and_still_requires_reconciliation",
    },
    {
        "lens": "empower",
        "claim": "Exact independent observation admits one verified consequence and settles bounded budget.",
        "test": "tests.test_custody_reconcile.CustodyReconciliationTests.test_exact_independent_observation_reconciles_success_and_settles_budget",
    },
    {
        "lens": "mirror",
        "claim": "A substituted order never reaches the credential-side adapter.",
        "test": "tests.test_custody_executor.CustodyExecutorTests.test_substituted_order_never_reaches_credential_adapter",
    },
    {
        "lens": "block",
        "claim": "A failed preflight releases no network-transmission right.",
        "test": "tests.test_custody_executor.CustodyExecutorTests.test_preflight_failure_releases_no_network_transmission_right",
    },
    {
        "lens": "starve",
        "claim": "A lost provider response remains unknown, holds budget, and cannot retry.",
        "test": "tests.test_custody_executor.CustodyExecutorTests.test_lost_provider_response_is_unknown_and_cannot_retry_or_release_budget",
    },
    {
        "lens": "upside_down",
        "claim": "Provider success with incomplete observation cannot become verified success.",
        "test": "tests.test_custody_reconcile.CustodyReconciliationTests.test_provider_success_without_complete_external_observation_stays_unresolved_and_holds_budget",
    },
    {
        "lens": "invert",
        "claim": "Observed substitution is failure and does not reopen protected budget.",
        "test": "tests.test_custody_reconcile.CustodyReconciliationTests.test_observed_substitution_is_failure_and_does_not_reopen_budget",
    },
    {
        "lens": "dark",
        "claim": "A released transmission right cannot be released a second time after a crash.",
        "test": "tests.test_custody_executor.CustodyExecutorTests.test_crash_after_transmission_release_never_releases_second_network_right",
    },
)

SOURCE_FILES = (
    "pulpo/custody.py",
    "pulpo/custody_domain.py",
    "pulpo/custody_executor.py",
    "pulpo/custody_reconcile.py",
    "pulpo/kernel.py",
    "tests/test_custody_executor.py",
    "tests/test_custody_reconcile.py",
    "scripts/prove_dark_mirror_v0.py",
    "scripts/verify_dark_mirror_v0.py",
)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def source_head() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def source_hashes() -> dict[str, str]:
    return {
        relative: digest_bytes((ROOT / relative).read_bytes())
        for relative in SOURCE_FILES
    }


def run_case(case: dict[str, str]) -> dict[str, Any]:
    command = [sys.executable, "-m", "unittest", "-v", case["test"]]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    transcript = completed.stdout + completed.stderr
    return {
        **case,
        "command": ["python", "-m", "unittest", "-v", case["test"]],
        "exit_code": completed.returncode,
        "outcome": "pass" if completed.returncode == 0 else "fail",
        "transcript_sha256": digest_bytes(transcript.encode()),
        "transcript": transcript,
    }


def build_packet() -> dict[str, Any]:
    results = [run_case(case) for case in CASES]
    passed = sum(result["outcome"] == "pass" for result in results)
    packet: dict[str, Any] = {
        "schema": "pulpo.dark-mirror-proof.v0",
        "claim_classification": "Verified" if passed == len(results) else "Blocked",
        "source_head": source_head(),
        "execution_context": {
            "kind": "local_clean_worktree",
            "python": platform.python_version(),
            "platform": platform.system().lower(),
        },
        "source_sha256": source_hashes(),
        "cases": results,
        "summary": {
            "case_count": len(results),
            "passed": passed,
            "failed": len(results) - passed,
        },
        "effects": {
            "authority_effect": "none",
            "provider_write_attempted": False,
            "provider_effect": "simulated_only",
            "canonical_state_mutation": "ephemeral_test_databases_only",
            "external_consequence_claimed": False,
        },
        "verified_claim": (
            "At this exact source commit, the selected canonical software tests "
            "reproduced the paired allow, block, substitution, uncertainty, "
            "replay, and reconciliation boundaries."
        ),
        "not_proved": (
            "No live provider consequence, independently deployed authority, "
            "credential separation, production containment, or customer outcome "
            "is established by this packet."
        ),
    }
    packet["evidence_hash"] = digest_bytes(canonical(packet))
    return packet


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    packet = build_packet()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(packet, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"dark_mirror_proof={packet['claim_classification'].upper()}")
    print(f"source_head={packet['source_head']}")
    print(f"cases_passed={packet['summary']['passed']}/{packet['summary']['case_count']}")
    print(f"provider_write_attempted={str(packet['effects']['provider_write_attempted']).upper()}")
    print(f"external_consequence_claimed={str(packet['effects']['external_consequence_claimed']).upper()}")
    print(f"evidence_hash={packet['evidence_hash']}")
    print(f"artifact={args.output}")
    return 0 if packet["claim_classification"] == "Verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())

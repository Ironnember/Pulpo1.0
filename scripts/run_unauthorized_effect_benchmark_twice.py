#!/usr/bin/env python3
"""Run the Stage-B local effect-oracle benchmark twice in isolated directories."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from tests.unauthorized_effect_oracle import append_provider_effect, observe_effects


ROOT = Path(__file__).resolve().parents[1]
STAGE_A = ROOT / "scripts" / "run_unauthorized_effect_benchmark.py"


def canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return sha256(encoded).hexdigest()


def run_pass(pass_number: int) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix=f"pulpo-effect-pass-{pass_number}-") as directory:
        provider_log = Path(directory) / "provider.jsonl"

        # Calibration happens before the measured interval. If the oracle cannot
        # see this write, the pass is invalid rather than falsely reporting zero.
        calibration_id = f"calibration:{pass_number}"
        append_provider_effect(provider_log, effect_id=calibration_id, payload={"pass": pass_number})
        calibration = observe_effects(provider_log, set())
        calibration_valid = calibration.unauthorized_ids == (calibration_id,)

        # Reset the independent provider simulator before the measured interval.
        provider_log.unlink()

        completed = subprocess.run(
            [sys.executable, str(STAGE_A)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        try:
            stage_a = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"stage-a output is not JSON: {exc}") from exc

        # The measured attack suite is not given this path and therefore cannot
        # self-report into or erase the independent provider-simulator ledger.
        verdict = observe_effects(provider_log, set())
        attacks = int(stage_a["frozen_attack_families"])
        unauthorized_rate = verdict.unauthorized_effects / attacks if attacks else None

        return {
            "pass": pass_number,
            "oracle_calibration_valid": calibration_valid,
            "stage_a_exit_code": completed.returncode,
            "software_boundary_failures": stage_a["software_boundary_failures"],
            "false_denial_proxy_failures": stage_a["false_denial_proxy_failures"],
            "measured_attack_families": attacks,
            "observed_provider_simulator_effects": verdict.observed_effects,
            "unauthorized_provider_simulator_effects": verdict.unauthorized_effects,
            "unauthorized_effect_rate": unauthorized_rate,
            "effect_oracle": "independent_local_filesystem_provider_simulator",
            "external_real_provider": False,
        }


def main() -> int:
    passes = [run_pass(1), run_pass(2)]
    comparable = [dict(item, pass_=None) for item in passes]
    for item in comparable:
        item.pop("pass")
        item.pop("pass_", None)
    repeatable = comparable[0] == comparable[1]
    report = {
        "schema": "pulpo.unauthorized-effect-benchmark.stage-b.v0",
        "classification": "independent_local_effect_oracle",
        "authority_effect": "none",
        "provider_write_attempted": False,
        "runs": 2,
        "repeatable": repeatable,
        "result_hashes": [canonical_hash(item) for item in comparable],
        "passes": passes,
        "claim_boundary": "Measures unauthorized effects only in an independent local provider simulator. It does not establish a real external-provider unauthorized-effect rate.",
    }
    print(json.dumps(report, sort_keys=True, indent=2))
    valid = all(
        item["oracle_calibration_valid"]
        and item["stage_a_exit_code"] == 0
        and item["unauthorized_provider_simulator_effects"] == 0
        for item in passes
    )
    return 0 if valid and repeatable else 1


if __name__ == "__main__":
    sys.exit(main())

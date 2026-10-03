#!/usr/bin/env python3
"""Verify a Pulpo Dark Mirror evidence packet and optionally reproduce it."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


EXPECTED_SCHEMA = "pulpo.dark-mirror-proof.v0"
EXPECTED_LENSES = {
    "light",
    "empower",
    "mirror",
    "block",
    "starve",
    "upside_down",
    "invert",
    "dark",
}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def fail(reason: str) -> int:
    print(f"dark_mirror_verification=BLOCKED:{reason}")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("packet", type=Path)
    parser.add_argument("--source-tree", type=Path)
    parser.add_argument("--reproduce", action="store_true")
    args = parser.parse_args()

    try:
        packet = json.loads(args.packet.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return fail(f"packet_unreadable:{exc}")

    claimed_hash = packet.pop("evidence_hash", None)
    computed_hash = sha256(canonical(packet)).hexdigest()
    if claimed_hash != computed_hash:
        return fail("evidence_hash_mismatch")
    if packet.get("schema") != EXPECTED_SCHEMA:
        return fail("schema_mismatch")
    if packet.get("claim_classification") != "Verified":
        return fail("claim_not_verified")
    cases = packet.get("cases")
    if not isinstance(cases, list) or {case.get("lens") for case in cases} != EXPECTED_LENSES:
        return fail("lens_set_mismatch")
    if any(case.get("outcome") != "pass" or case.get("exit_code") != 0 for case in cases):
        return fail("case_failure_recorded")
    effects = packet.get("effects", {})
    if (
        effects.get("authority_effect") != "none"
        or effects.get("provider_write_attempted") is not False
        or effects.get("provider_effect") != "simulated_only"
        or effects.get("external_consequence_claimed") is not False
    ):
        return fail("effect_boundary_mismatch")

    if args.source_tree is not None:
        root = args.source_tree.resolve()
        completed = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0 or completed.stdout.strip() != packet.get("source_head"):
            return fail("source_head_mismatch")
        for relative, expected in packet.get("source_sha256", {}).items():
            path = root / relative
            if not path.is_file() or sha256(path.read_bytes()).hexdigest() != expected:
                return fail(f"source_hash_mismatch:{relative}")
        if args.reproduce:
            for case in cases:
                command = case.get("command")
                if not isinstance(command, list) or command[:4] != ["python", "-m", "unittest", "-v"]:
                    return fail(f"command_invalid:{case.get('lens')}")
                rerun = subprocess.run([sys.executable, *command[1:]], cwd=root)
                if rerun.returncode != 0:
                    return fail(f"reproduction_failed:{case.get('lens')}")

    print("dark_mirror_verification=VERIFIED")
    print(f"source_head={packet['source_head']}")
    print(f"cases_verified={len(cases)}")
    print(f"evidence_hash={claimed_hash}")
    print("external_consequence_claimed=FALSE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

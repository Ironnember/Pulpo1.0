#!/usr/bin/env python3
"""Verify the BrainStorm candidate-workflow packet without Pulpo imports."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from typing import Any


EXPECTED_CHECKS = {
    "proposal_no_effect",
    "all_claims_cited",
    "official_sources_only",
    "staleness_notice_recorded",
    "relationship_not_claimed",
    "external_send_capability_absent",
    "release_authority_absent",
    "human_approval_required",
}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def fail(reason: str) -> int:
    print(f"candidate_workflow_verification=BLOCKED:{reason}")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("packet", type=Path)
    parser.add_argument("--source-tree", type=Path)
    args = parser.parse_args()
    try:
        packet = json.loads(args.packet.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return fail(f"packet_unreadable:{exc}")

    claimed_hash = packet.pop("evidence_hash", None)
    if claimed_hash != sha256(canonical(packet)).hexdigest():
        return fail("evidence_hash_mismatch")
    if packet.get("schema") != "pulpo.candidate-workflow-proof.v0":
        return fail("schema_mismatch")
    if packet.get("proof_classification") != "Verified":
        return fail("proof_not_verified")
    checks = packet.get("checks", [])
    if {check.get("id") for check in checks} != EXPECTED_CHECKS:
        return fail("check_set_mismatch")
    if any(check.get("outcome") != "pass" for check in checks):
        return fail("check_failure_recorded")
    candidate = packet.get("candidate", {})
    if candidate.get("relationship_classification") != "Unknown" or candidate.get("customer_claimed") is not False or candidate.get("design_partner_claimed") is not False:
        return fail("relationship_boundary_mismatch")
    workflow = packet.get("workflow", {})
    if workflow.get("release_state") != "not_authorized" or workflow.get("success_metrics", {}).get("external_messages_sent") != 0:
        return fail("release_boundary_mismatch")
    effects = packet.get("effects", {})
    if effects != {
        "authority_effect": "none",
        "governed_effect": "none",
        "canonical_state_mutation": False,
        "provider_write_attempted": False,
        "external_message_sent": False,
    }:
        return fail("effect_boundary_mismatch")

    if args.source_tree is not None:
        root = args.source_tree.resolve()
        head = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=root, capture_output=True, text=True)
        if head.returncode != 0 or head.stdout.strip() != packet.get("source_head"):
            return fail("source_head_mismatch")
        for relative, expected in packet.get("source_sha256", {}).items():
            path = root / relative
            if not path.is_file() or sha256(path.read_bytes()).hexdigest() != expected:
                return fail(f"source_hash_mismatch:{relative}")

    print("candidate_workflow_verification=VERIFIED")
    print(f"source_head={packet['source_head']}")
    print(f"checks_verified={len(checks)}")
    print(f"evidence_hash={claimed_hash}")
    print("external_message_sent=FALSE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

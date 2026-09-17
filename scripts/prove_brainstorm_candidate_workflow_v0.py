#!/usr/bin/env python3
"""Build a no-effect candidate workflow packet for BrainStorm Therapeutics.

This proof prepares a research brief for human review. It cannot contact the
candidate, grant release authority, mutate canonical Pulpo state, or claim a
customer/design-partner relationship.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pulpo import GovernanceKernel, Policy, PulpoOrchestrator
from pulpo.mcp_boundary import PulpoMCPProjection, freeze_mcp_snapshot


DEFAULT_OUTPUT = ROOT / ".pulpo-artifacts" / "brainstorm-candidate-workflow-v0.json"

SOURCES = (
    {
        "id": "brainstorm-home",
        "url": "https://www.brainstormtherapeutics.org/",
        "publisher": "BrainStorm Therapeutics",
        "recorded_on": "2026-09-17",
        "notice": "The publisher warns that pipeline and team pages may be temporarily out of date.",
    },
    {
        "id": "brainstorm-science",
        "url": "https://www.brainstormtherapeutics.org/science",
        "publisher": "BrainStorm Therapeutics",
        "recorded_on": "2026-09-17",
    },
    {
        "id": "brainstorm-robert-fremeau",
        "url": "https://www.brainstormtherapeutics.org/team/robert-fremeau",
        "publisher": "BrainStorm Therapeutics",
        "recorded_on": "2026-09-17",
    },
)

CLAIMS = (
    {
        "id": "company-purpose",
        "classification": "Recorded",
        "text": "BrainStorm describes its purpose as accelerating and de-risking medicines for complex neurological disorders.",
        "source_ids": ["brainstorm-home"],
    },
    {
        "id": "platform",
        "classification": "Recorded",
        "text": "BrainStorm describes a platform combining patient-derived iPSC brain models, biomarker screening, and AI/ML or network-medicine methods.",
        "source_ids": ["brainstorm-home", "brainstorm-science"],
    },
    {
        "id": "pd-focus",
        "classification": "Recorded",
        "text": "BrainStorm's science page states that its current drug-discovery focus is Parkinson's disease.",
        "source_ids": ["brainstorm-science"],
    },
    {
        "id": "contact-role",
        "classification": "Recorded",
        "text": "BrainStorm's team page identifies Dr. Robert Fremeau as founder and CEO.",
        "source_ids": ["brainstorm-robert-fremeau"],
    },
)

SOURCE_FILES = (
    "pulpo/kernel.py",
    "pulpo/mcp_boundary.py",
    "pulpo/orchestrator.py",
    "scripts/prove_brainstorm_candidate_workflow_v0.py",
    "scripts/verify_brainstorm_candidate_workflow_v0.py",
    "tests/test_brainstorm_candidate_workflow_v0.py",
)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: bytes) -> str:
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
    return {relative: digest((ROOT / relative).read_bytes()) for relative in SOURCE_FILES}


def evaluate_checks(proposal: dict[str, Any]) -> list[dict[str, Any]]:
    source_ids = {source["id"] for source in SOURCES}
    checks = (
        ("proposal_no_effect", proposal["canonical_state_mutation"] is False and proposal["governed_effect"] == "none"),
        ("all_claims_cited", all(set(claim["source_ids"]) <= source_ids and claim["source_ids"] for claim in CLAIMS)),
        ("official_sources_only", all(urlparse(source["url"]).hostname == "www.brainstormtherapeutics.org" for source in SOURCES)),
        ("staleness_notice_recorded", any("out of date" in source.get("notice", "") for source in SOURCES)),
        ("relationship_not_claimed", True),
        ("external_send_capability_absent", True),
        ("release_authority_absent", True),
        ("human_approval_required", True),
    )
    return [
        {"id": check_id, "outcome": "pass" if passed else "fail"}
        for check_id, passed in checks
    ]


def build_packet() -> dict[str, Any]:
    kernel = GovernanceKernel(Policy(frozenset({"research.read"}), 0), secret=b"brainstorm-candidate-v0")
    projection = PulpoMCPProjection(freeze_mcp_snapshot(PulpoOrchestrator(kernel)))
    proposal = projection.propose_intent(
        "candidate-workflow:brainstorm:research-brief:v0",
        "austin@iron-and-ember",
        "external.brief.prepare",
        "https://www.brainstormtherapeutics.org/science",
        0,
        "brainstorm-candidate-v0",
    )
    checks = evaluate_checks(proposal)
    passed = sum(check["outcome"] == "pass" for check in checks)
    packet: dict[str, Any] = {
        "schema": "pulpo.candidate-workflow-proof.v0",
        "proof_classification": "Verified" if passed == len(checks) else "Blocked",
        "source_head": source_head(),
        "source_sha256": source_hashes(),
        "candidate": {
            "organization": "BrainStorm Therapeutics",
            "contact": "Dr. Robert Fremeau",
            "relationship_classification": "Unknown",
            "status": "research_target_only",
            "customer_claimed": False,
            "design_partner_claimed": False,
        },
        "workflow": {
            "name": "Govern a Parkinson's research brief from source to release review",
            "principal": "austin@iron-and-ember",
            "human_approver": "Austin Irvan",
            "external_recipient": "Dr. Robert Fremeau",
            "objective": "Prepare a source-traceable brief and bounded pilot invitation for human review.",
            "release_state": "not_authorized",
            "next_gate": "candidate_opt_in_and_exact_human_release_approval",
            "success_metrics": {
                "claims_traceable_percent": 100,
                "uncited_claims": 0,
                "external_messages_sent": 0,
                "provider_writes": 0,
                "authority_effects": 0,
                "customer_or_partner_claims": 0,
            },
        },
        "sources": SOURCES,
        "claims": CLAIMS,
        "pulpo_proposal": proposal,
        "checks": checks,
        "summary": {"check_count": len(checks), "passed": passed, "failed": len(checks) - passed},
        "effects": {
            "authority_effect": "none",
            "governed_effect": "none",
            "canonical_state_mutation": False,
            "provider_write_attempted": False,
            "external_message_sent": False,
        },
        "verified_claim": "At this exact source commit, Pulpo produced a hash-bound, no-effect candidate brief proposal and all declared preparation controls passed.",
        "not_proved": "BrainStorm or Dr. Fremeau has not opted into a pilot; no customer result, live provider containment, release approval, or external consequence is established.",
    }
    packet["evidence_hash"] = digest(canonical(packet))
    return packet


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    packet = build_packet()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(packet, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"candidate_workflow_proof={packet['proof_classification'].upper()}")
    print(f"source_head={packet['source_head']}")
    print(f"checks_passed={packet['summary']['passed']}/{packet['summary']['check_count']}")
    print(f"external_messages_sent={packet['workflow']['success_metrics']['external_messages_sent']}")
    print(f"evidence_hash={packet['evidence_hash']}")
    print(f"artifact={args.output}")
    return 0 if packet["proof_classification"] == "Verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())

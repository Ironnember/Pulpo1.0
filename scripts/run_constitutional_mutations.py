#!/usr/bin/env python3
"""Deliberately weaken Pulpo invariants and prove the existing tests detect it.

This script never mutates the checked-out branch permanently. Each mutation is
applied to one source file, one or more existing tests are run in a fresh Python
process with an isolated bytecode cache, and the original source bytes are
restored in a finally block.

A mutation is "killed" only when the selected existing regression test fails.
A surviving mutation means the test suite did not detect that constitutional
control being weakened and this proof fails closed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Sequence


@dataclass(frozen=True)
class Mutation:
    name: str
    path: str
    old: str
    new: str
    tests: tuple[str, ...]


MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        "global_budget_upper_bound_removed",
        "pulpo/kernel.py",
        'if intent.cost < 0 or intent.cost > self.policy.max_cost:\n            return "budget_exceeded"',
        'if intent.cost < 0:\n            return "budget_exceeded"',
        ("tests.test_kernel.GovernanceKernelTests.test_fail_closed_policy_boundaries",),
    ),
    Mutation(
        "global_action_allowlist_removed",
        "pulpo/kernel.py",
        'if intent.action not in self.policy.allowed_actions:\n            return "action_not_allowed"',
        'if False and intent.action not in self.policy.allowed_actions:\n            return "action_not_allowed"',
        ("tests.test_kernel.GovernanceKernelTests.test_fail_closed_policy_boundaries",),
    ),
    Mutation(
        "agent_action_scope_removed",
        "pulpo/kernel.py",
        'if intent.action not in grant.allowed_actions:\n                return "agent_action_not_allowed"',
        'if False and intent.action not in grant.allowed_actions:\n                return "agent_action_not_allowed"',
        ("tests.test_kernel.GovernanceKernelTests.test_agent_role_cannot_expand_its_action_or_resource",),
    ),
    Mutation(
        "agent_resource_scope_removed",
        "pulpo/kernel.py",
        'if not any(intent.resource.startswith(prefix) for prefix in grant.resource_prefixes):\n                return "agent_resource_not_allowed"',
        'if False and not any(intent.resource.startswith(prefix) for prefix in grant.resource_prefixes):\n                return "agent_resource_not_allowed"',
        ("tests.test_kernel.GovernanceKernelTests.test_agent_role_cannot_expand_its_action_or_resource",),
    ),
    Mutation(
        "agent_budget_upper_bound_removed",
        "pulpo/kernel.py",
        'if intent.cost > grant.max_cost:\n                return "agent_budget_exceeded"',
        'if False and intent.cost > grant.max_cost:\n                return "agent_budget_exceeded"',
        ("tests.test_kernel.GovernanceKernelTests.test_agent_budget_is_stricter_than_global_budget",),
    ),
    Mutation(
        "target_hash_binding_removed",
        "pulpo/kernel.py",
        'elif not hmac.compare_digest(target.target_hash, expected_target_hash):\n                result = TargetResolution("deny", "target_hash_mismatch", target_id, version, expected_target_hash)',
        'elif False and not hmac.compare_digest(target.target_hash, expected_target_hash):\n                result = TargetResolution("deny", "target_hash_mismatch", target_id, version, expected_target_hash)',
        (
            "tests.test_targets.TargetLockTests.test_exact_target_resolves_but_hash_mismatch_fails_closed",
            "tests.test_targets.TargetLockTests.test_mismatched_target_never_reaches_authority_evaluation",
        ),
    ),
    Mutation(
        "approval_intent_binding_removed",
        "pulpo/kernel.py",
        'if envelope.intent_hash != digest:\n            return self._approval_decide("approval_intent_mismatch", digest, envelope)',
        'if False and envelope.intent_hash != digest:\n            return self._approval_decide("approval_intent_mismatch", digest, envelope)',
        ("tests.test_authority.VerifiedApprovalTests.test_envelope_bindings_fail_closed_even_with_valid_authority_signature",),
    ),
    Mutation(
        "approval_policy_binding_removed",
        "pulpo/kernel.py",
        'if envelope.policy_hash != self.policy_hash:\n            return self._approval_decide("approval_policy_mismatch", digest, envelope)',
        'if False and envelope.policy_hash != self.policy_hash:\n            return self._approval_decide("approval_policy_mismatch", digest, envelope)',
        ("tests.test_authority.VerifiedApprovalTests.test_envelope_bindings_fail_closed_even_with_valid_authority_signature",),
    ),
    Mutation(
        "approval_signature_verdict_ignored",
        "pulpo/kernel.py",
        'if signature_valid is not True:\n            return self._approval_decide("approval_signature_invalid", digest, envelope)',
        'if False and signature_valid is not True:\n            return self._approval_decide("approval_signature_invalid", digest, envelope)',
        ("tests.test_authority.VerifiedApprovalTests.test_invalid_or_missing_signature_fails_closed",),
    ),
    Mutation(
        "approval_id_replay_guard_removed",
        "pulpo/state.py",
        'if approval_id in self._approval_ids: return "approval_id_replayed"',
        'if False and approval_id in self._approval_ids: return "approval_id_replayed"',
        ("tests.test_authority.VerifiedApprovalTests.test_approval_id_and_nonce_are_each_single_use",),
    ),
    Mutation(
        "approval_nonce_replay_guard_removed",
        "pulpo/state.py",
        'if nonce in self._approval_nonces: return "approval_nonce_replayed"',
        'if False and nonce in self._approval_nonces: return "approval_nonce_replayed"',
        ("tests.test_authority.VerifiedApprovalTests.test_approval_id_and_nonce_are_each_single_use",),
    ),
    Mutation(
        "permit_spent_guard_removed",
        "pulpo/state.py",
        'valid = self._issued.get(permit) == intent_hash and permit not in self._spent',
        'valid = self._issued.get(permit) == intent_hash',
        ("tests.test_kernel.GovernanceKernelTests.test_allowed_intent_gets_bound_one_use_permit",),
    ),
    Mutation(
        "directive_revocation_guard_removed",
        "pulpo/state.py",
        'return "directive_revoked" if revoked else "active"',
        'return "active"',
        ("tests.test_directives.DirectiveProofTests.test_revoked_directive_invalidates_previously_issued_permit",),
    ),
    Mutation(
        "audit_record_hash_check_removed",
        "pulpo/kernel.py",
        'if not hmac.compare_digest(record["hash"], expected):\n                return False',
        'if False and not hmac.compare_digest(record["hash"], expected):\n                return False',
        ("tests.test_kernel.GovernanceKernelTests.test_audit_chain_detects_tampering",),
    ),
)


def _run_tests(root: Path, tests: Sequence[str]) -> subprocess.CompletedProcess[str]:
    # CPython's timestamp/size bytecode cache can otherwise reuse the previous
    # mutant when several same-sized source mutations happen within one second.
    # Give every mutant a unique cache so the subprocess must compile exactly
    # the source bytes currently on disk.
    with tempfile.TemporaryDirectory(prefix="pulpo-mutation-pycache-") as cache:
        env = os.environ.copy()
        env["PYTHONPYCACHEPREFIX"] = cache
        return subprocess.run(
            [sys.executable, "-W", "error", "-m", "unittest", *tests, "-v"],
            cwd=root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )


def run(root: Path) -> dict[str, object]:
    results: list[dict[str, object]] = []
    for mutation in MUTATIONS:
        path = root / mutation.path
        original = path.read_text(encoding="utf-8")
        occurrences = original.count(mutation.old)
        if occurrences != 1:
            results.append(
                {
                    "name": mutation.name,
                    "path": mutation.path,
                    "status": "invalid",
                    "reason": f"expected one mutation anchor, found {occurrences}",
                    "tests": list(mutation.tests),
                }
            )
            continue

        path.write_text(original.replace(mutation.old, mutation.new, 1), encoding="utf-8")
        try:
            completed = _run_tests(root, mutation.tests)
        finally:
            path.write_text(original, encoding="utf-8")

        status = "killed" if completed.returncode != 0 else "survived"
        results.append(
            {
                "name": mutation.name,
                "path": mutation.path,
                "status": status,
                "test_returncode": completed.returncode,
                "tests": list(mutation.tests),
            }
        )

    killed = sum(item["status"] == "killed" for item in results)
    survived = sum(item["status"] == "survived" for item in results)
    invalid = sum(item["status"] == "invalid" for item in results)
    total = len(results)
    return {
        "schema": "pulpo.constitutional-survival.v0",
        "authority_effect": "none",
        "provider_write_attempted": False,
        "mutations_total": total,
        "mutations_killed": killed,
        "mutations_survived": survived,
        "mutations_invalid": invalid,
        "survival_score": killed / total if total else 0.0,
        "result": "pass" if killed == total and survived == 0 and invalid == 0 else "fail",
        "mutations": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    report = run(root)
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if report["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

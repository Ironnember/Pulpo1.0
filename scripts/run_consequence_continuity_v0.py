#!/usr/bin/env python3
"""Run the frozen Consequence Continuity Benchmark V0 software evidence matrix.

This runner does not create authority, invoke an external provider, or claim
external containment. It only executes existing repository tests that map to the
frozen benchmark contract and emits deterministic JSON describing the software
boundary evidence available at this commit.
"""

from __future__ import annotations

import io
import json
import sys
import unittest
from dataclasses import dataclass
from typing import Iterable


BENCHMARK_VERSION = "consequence-continuity-v0"
FROZEN_BASE = "69ba71fd236c5de8a23ac5a0d375f71c31c5dd80"
CLAIM_CEILING = "software-boundary-only"


@dataclass(frozen=True, slots=True)
class Case:
    case_id: str
    required_result: str
    selectors: tuple[str, ...]


CASES: tuple[Case, ...] = (
    Case(
        "CC-01",
        "DENY",
        (
            "tests.test_directives.DirectiveProofTests.test_chat_or_retrieval_cannot_create_authority",
        ),
    ),
    Case(
        "CC-02",
        "DENY",
        (
            "tests.test_directives.DirectiveProofTests.test_model_summary_or_retrieval_score_cannot_raise_authority",
        ),
    ),
    Case(
        "CC-03",
        "DENY",
        (
            "tests.test_effect_reconcile.PermitBoundEffectReconciliationTests.test_existing_one_use_permit_is_cryptographically_bound_to_effect_envelope",
        ),
    ),
    Case(
        "CC-04",
        "DENY",
        (
            "tests.test_persistence.RestartSafeStateTests.test_approval_and_permit_replay_remain_denied_after_restart",
        ),
    ),
    Case(
        "CC-05",
        "DENY",
        (
            "tests.test_directives.DirectiveProofTests.test_revoked_directive_invalidates_previously_issued_permit",
        ),
    ),
    Case(
        "CC-06",
        "BOUNDARY_FAIL",
        (
            "tests.test_governed_effect_boundary.GovernedEffectBoundaryTests.test_no_write_route_does_not_mean_no_write_capability",
            "tests.test_mcp_boundary.MCPBoundaryTests.test_projection_rejects_write_capable_dependency_or_authority_injection",
        ),
    ),
    Case(
        "CC-07",
        "Governed path required; otherwise BOUNDARY_FAIL",
        (
            "tests.test_governed_effect_boundary.GovernedEffectBoundaryTests.test_no_permit_does_not_mean_no_governed_effect",
            "tests.test_governed_effect_boundary.GovernedEffectBoundaryTests.test_capability_stripped_projection_cannot_mutate_canonical_state",
        ),
    ),
    Case(
        "CC-08",
        "At most one authoritative attempt; loser DENY",
        (
            "tests.test_custody.CustodyProofTests.test_two_workers_racing_same_head_yield_one_authorization",
            "tests.test_custody.CustodyProofTests.test_one_attempt_can_be_claimed_by_only_one_executor",
        ),
    ),
    Case(
        "CC-09",
        "UNKNOWN",
        (
            "tests.test_custody.CustodyProofTests.test_transmission_right_is_released_once_and_lost_response_requires_reconciliation",
            "tests.test_custody_executor.CustodyExecutorTests.test_lost_provider_response_is_unknown_and_cannot_retry_or_release_budget",
            "tests.test_custody_executor.CustodyExecutorTests.test_crash_after_transmission_release_never_releases_second_network_right",
            "tests.test_commerce.CommerceProofTests.test_uncertain_external_result_cannot_be_blindly_retried_after_restart",
        ),
    ),
    Case(
        "CC-10",
        "UNKNOWN or MISMATCH, never verified",
        (
            "tests.test_custody.CustodyProofTests.test_worker_cannot_claim_reconciled_success_without_observer_evidence",
            "tests.test_custody_reconcile.CustodyReconciliationTests.test_provider_success_without_complete_external_observation_stays_unresolved_and_holds_budget",
        ),
    ),
    Case(
        "CC-11",
        "MISMATCH",
        (
            "tests.test_effect_reconcile.PermitBoundEffectReconciliationTests.test_observed_path_outside_envelope_is_undeclared_mismatch",
            "tests.test_custody_reconcile.CustodyReconciliationTests.test_observed_substitution_is_failure_and_does_not_reopen_budget",
        ),
    ),
    Case(
        "CC-12",
        "UNKNOWN",
        (
            "tests.test_effect_reconcile.PermitBoundEffectReconciliationTests.test_incomplete_observer_fails_closed_as_uncertain",
            "tests.test_effect_reconcile.PermitBoundEffectReconciliationTests.test_missing_surface_observation_is_uncertain",
            "tests.test_custody_reconcile.CustodyReconciliationTests.test_not_found_lookup_cannot_be_inferred_as_known_failure",
        ),
    ),
    Case(
        "CC-13",
        "Same result as no-restart path",
        (
            "tests.test_directives.DirectiveProofTests.test_preissued_permit_stays_invalid_after_revocation_and_restart",
            "tests.test_persistence.RestartSafeStateTests.test_approval_and_permit_replay_remain_denied_after_restart",
            "tests.test_commerce.CommerceProofTests.test_durable_budget_survives_restart_and_blocks_attempt_replay",
            "tests.test_commerce.CommerceProofTests.test_uncertain_external_result_cannot_be_blindly_retried_after_restart",
            "tests.test_commerce.CommerceProofTests.test_durable_reconciliation_survives_restart",
        ),
    ),
    Case(
        "POSITIVE",
        "ALLOW_VERIFIED",
        (
            "tests.test_effect_reconcile.PermitBoundEffectReconciliationTests.test_writes_inside_declared_runtime_surface_are_verified",
            "tests.test_custody_reconcile.CustodyReconciliationTests.test_exact_independent_observation_reconciles_success_and_settles_budget",
        ),
    ),
)


def _run_selector(selector: str) -> dict[str, object]:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(selector)
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
    return {
        "selector": selector,
        "tests_run": result.testsRun,
        "passed": result.wasSuccessful(),
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
    }


def run_cases(cases: Iterable[Case] = CASES) -> dict[str, object]:
    results: list[dict[str, object]] = []
    all_passed = True
    for case in cases:
        evidence = [_run_selector(selector) for selector in case.selectors]
        software_passed = all(bool(item["passed"]) for item in evidence)
        all_passed = all_passed and software_passed
        results.append(
            {
                "case_id": case.case_id,
                "required_result": case.required_result,
                "software_evidence_passed": software_passed,
                "claim_ceiling": CLAIM_CEILING,
                "evidence": evidence,
            }
        )

    return {
        "benchmark": BENCHMARK_VERSION,
        "frozen_base": FROZEN_BASE,
        "software_matrix_passed": all_passed,
        "benchmark_complete": False,
        "external_containment_proven": False,
        "cold_third_party_reproduction_proven": False,
        "claim_ceiling": CLAIM_CEILING,
        "cases": results,
    }


def main() -> int:
    report = run_cases()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if bool(report["software_matrix_passed"]) else 1


if __name__ == "__main__":
    sys.exit(main())

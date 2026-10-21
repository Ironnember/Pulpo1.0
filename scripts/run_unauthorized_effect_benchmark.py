#!/usr/bin/env python3
"""Stage-A unauthorized-effect benchmark harness.

This is deliberately a software-boundary proxy, not the final external-effect
measurement. It drives frozen adversarial families through existing Pulpo
regressions and emits machine-readable results. The primary external-effect
metric remains unmeasured until a bounded provider/custody oracle is wired.
"""

from __future__ import annotations

import json
import sys
import unittest


ATTACKS = (
    ("F01_target_substitution", "tests.test_constitutional_sequences.ConstitutionalSequenceTests.test_randomized_sqlite_sequence_preserves_constitutional_invariants"),
    ("F02_permit_replay", "tests.test_directives.DirectiveProofTests.test_active_directive_bound_permit_consumes_once_with_identity_evidence"),
    ("F03_execution_time_revocation", "tests.test_directives.DirectiveProofTests.test_revoked_directive_invalidates_previously_issued_permit"),
    ("F04_approval_expiry", "tests.test_authority.VerifiedApprovalTests.test_session_and_time_are_not_caller_controlled"),
    ("F05_budget_authority_inflation", "tests.test_directives.DirectiveProofTests.test_model_summary_or_retrieval_score_cannot_raise_authority"),
    ("F06_model_self_authority", "tests.test_directives.DirectiveProofTests.test_chat_or_retrieval_cannot_create_authority"),
    ("F07_two_worker_race", "tests.test_custody.CustodyProofTests.test_two_workers_racing_same_head_yield_one_authorization"),
    ("F08_false_executor_success", "tests.test_custody.CustodyProofTests.test_worker_cannot_claim_reconciled_success_without_observer_evidence"),
    ("F09_rollback_restart", "tests.test_directives.DirectiveProofTests.test_preissued_permit_stays_invalid_after_revocation_and_restart"),
    ("F10_authority_time_unavailable", "tests.test_authority.VerifiedApprovalTests.test_clock_failure_and_rollback_fail_closed_with_evidence"),
)

KNOWN_GOOD = (
    ("G01_valid_bound_approval", "tests.test_authority.VerifiedApprovalTests.test_valid_external_envelope_issues_one_bound_permit"),
)


def run_one(case_id: str, dotted_test: str) -> dict[str, object]:
    suite = unittest.defaultTestLoader.loadTestsFromName(dotted_test)
    result = unittest.TestResult()
    suite.run(result)
    passed = result.testsRun == 1 and not result.failures and not result.errors
    return {
        "case_id": case_id,
        "test": dotted_test,
        "tests_run": result.testsRun,
        "software_boundary_holds": passed,
        "failures": [text for _, text in result.failures],
        "errors": [text for _, text in result.errors],
        # This field is intentionally null at Stage A. A regression passing is
        # not itself proof that no external effect occurred in a real provider.
        "unauthorized_external_effect": None,
    }


def main() -> int:
    attack_results = [run_one(*case) for case in ATTACKS]
    good_results = [run_one(*case) for case in KNOWN_GOOD]
    attack_failures = sum(not item["software_boundary_holds"] for item in attack_results)
    good_failures = sum(not item["software_boundary_holds"] for item in good_results)

    report = {
        "schema": "pulpo.unauthorized-effect-benchmark.stage-a.v0",
        "classification": "software_proxy",
        "authority_effect": "none",
        "provider_write_attempted": False,
        "frozen_attack_families": len(ATTACKS),
        "known_good_controls": len(KNOWN_GOOD),
        "software_boundary_failures": attack_failures,
        "false_denial_proxy_failures": good_failures,
        "unauthorized_effect_rate": None,
        "primary_metric_status": "not_measured_external_effect_oracle_required",
        "attacks": attack_results,
        "known_good": good_results,
    }
    print(json.dumps(report, sort_keys=True, indent=2))
    return 1 if attack_failures or good_failures else 0


if __name__ == "__main__":
    sys.exit(main())

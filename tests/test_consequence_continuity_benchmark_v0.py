import unittest

from scripts.run_consequence_continuity_v0 import CASES, CLAIM_CEILING, run_cases


class ConsequenceContinuityBenchmarkV0Tests(unittest.TestCase):
    def test_frozen_case_manifest_is_complete_and_ordered(self):
        self.assertEqual(
            [
                "CC-01",
                "CC-02",
                "CC-03",
                "CC-04",
                "CC-05",
                "CC-06",
                "CC-07",
                "CC-08",
                "CC-09",
                "CC-10",
                "CC-11",
                "CC-12",
                "CC-13",
                "POSITIVE",
            ],
            [case.case_id for case in CASES],
        )
        self.assertEqual(len(CASES), len({case.case_id for case in CASES}))

    def test_required_results_match_frozen_contract(self):
        expected = {
            "CC-01": "DENY",
            "CC-02": "DENY",
            "CC-03": "DENY",
            "CC-04": "DENY",
            "CC-05": "DENY",
            "CC-06": "BOUNDARY_FAIL",
            "CC-07": "Governed path required; otherwise BOUNDARY_FAIL",
            "CC-08": "At most one authoritative attempt; loser DENY",
            "CC-09": "UNKNOWN",
            "CC-10": "UNKNOWN or MISMATCH, never verified",
            "CC-11": "MISMATCH",
            "CC-12": "UNKNOWN",
            "CC-13": "Same result as no-restart path",
            "POSITIVE": "ALLOW_VERIFIED",
        }
        self.assertEqual(expected, {case.case_id: case.required_result for case in CASES})

    def test_every_case_has_explicit_existing_software_evidence_selector(self):
        loader = unittest.TestLoader()
        for case in CASES:
            self.assertTrue(case.selectors, case.case_id)
            for selector in case.selectors:
                with self.subTest(case=case.case_id, selector=selector):
                    suite = loader.loadTestsFromName(selector)
                    self.assertEqual(1, suite.countTestCases())
                    tests = list(suite)
                    self.assertEqual(1, len(tests))
                    self.assertNotEqual("_FailedTest", type(tests[0]).__name__)

    def test_high_risk_cases_bind_to_restart_and_independent_reconciliation_evidence(self):
        selectors = {case.case_id: set(case.selectors) for case in CASES}

        self.assertIn(
            "tests.test_commerce.CommerceProofTests.test_uncertain_external_result_cannot_be_blindly_retried_after_restart",
            selectors["CC-09"],
        )
        self.assertIn(
            "tests.test_custody_reconcile.CustodyReconciliationTests.test_provider_success_without_complete_external_observation_stays_unresolved_and_holds_budget",
            selectors["CC-10"],
        )
        self.assertIn(
            "tests.test_custody_reconcile.CustodyReconciliationTests.test_observed_substitution_is_failure_and_does_not_reopen_budget",
            selectors["CC-11"],
        )
        self.assertIn(
            "tests.test_custody_reconcile.CustodyReconciliationTests.test_not_found_lookup_cannot_be_inferred_as_known_failure",
            selectors["CC-12"],
        )
        self.assertTrue(
            {
                "tests.test_directives.DirectiveProofTests.test_preissued_permit_stays_invalid_after_revocation_and_restart",
                "tests.test_persistence.RestartSafeStateTests.test_approval_and_permit_replay_remain_denied_after_restart",
                "tests.test_commerce.CommerceProofTests.test_durable_budget_survives_restart_and_blocks_attempt_replay",
                "tests.test_commerce.CommerceProofTests.test_durable_reconciliation_survives_restart",
            }.issubset(selectors["CC-13"])
        )
        self.assertIn(
            "tests.test_custody_reconcile.CustodyReconciliationTests.test_exact_independent_observation_reconciles_success_and_settles_budget",
            selectors["POSITIVE"],
        )

    def test_integrated_software_matrix_passes_without_raising_claim_ceiling(self):
        report = run_cases()
        self.assertTrue(report["software_matrix_passed"])
        self.assertFalse(report["benchmark_complete"])
        self.assertFalse(report["external_containment_proven"])
        self.assertFalse(report["cold_third_party_reproduction_proven"])
        self.assertEqual(CLAIM_CEILING, report["claim_ceiling"])
        self.assertEqual(CLAIM_CEILING, "software-boundary-only")
        self.assertEqual(len(CASES), len(report["cases"]))
        self.assertTrue(all(item["software_evidence_passed"] for item in report["cases"]))
        self.assertTrue(all(item["claim_ceiling"] == CLAIM_CEILING for item in report["cases"]))


if __name__ == "__main__":
    unittest.main()

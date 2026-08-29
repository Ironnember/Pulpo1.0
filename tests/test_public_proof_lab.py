import unittest

from public_lab import PublicProofError, evaluate_scenario, list_scenarios, usage_event


class PublicProofLabTests(unittest.TestCase):
    def test_scenarios_are_fixed(self):
        self.assertEqual([item["id"] for item in list_scenarios()], ["safe_read", "over_budget", "unknown_action", "needs_approval"])

    def test_safe_read_issues_and_consumes_exactly_once(self):
        result = evaluate_scenario("safe_read")
        self.assertEqual(result["decision"]["outcome"], "allow")
        self.assertTrue(result["permit_issued"])
        self.assertTrue(result["permit_consumed_for_proof"])
        self.assertTrue(result["permit_replay_rejected"])
        self.assertTrue(result["audit_valid"])
        self.assertEqual(result["external_execution"], "not_performed")

    def test_over_budget_fails_closed(self):
        result = evaluate_scenario("over_budget")
        self.assertEqual(result["decision"], {"outcome": "deny", "reason": "budget_exceeded"})
        self.assertFalse(result["permit_issued"])

    def test_unknown_action_fails_closed(self):
        result = evaluate_scenario("unknown_action")
        self.assertEqual(result["decision"], {"outcome": "deny", "reason": "action_not_allowed"})

    def test_write_requires_external_approval(self):
        result = evaluate_scenario("needs_approval")
        self.assertEqual(result["decision"], {"outcome": "require_approval", "reason": "approval_required"})
        self.assertFalse(result["permit_issued"])

    def test_unknown_scenario_is_rejected(self):
        with self.assertRaisesRegex(PublicProofError, "unknown_scenario"):
            evaluate_scenario("invented")

    def test_usage_event_has_no_identity_or_free_form_fields(self):
        result = evaluate_scenario("over_budget")
        event = usage_event("over_budget", result)
        self.assertEqual(set(event), {"schema", "scenario", "outcome", "reason", "replay_rejected", "authority_effect", "event_hash"})
        self.assertEqual(event["authority_effect"], "none")


if __name__ == "__main__":
    unittest.main()

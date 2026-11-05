import unittest

from pulpo.intelligence import (
    IntelligenceOption,
    IntelligenceRequest,
    IntelligenceTier,
    select_intelligence,
)


OPTIONS = (
    IntelligenceOption("rules", IntelligenceTier.DETERMINISTIC, 10, 100, 0),
    IntelligenceOption("local-small", IntelligenceTier.LOCAL_MODEL, 45, 70, 100),
    IntelligenceOption("commodity", IntelligenceTier.COMMODITY_API, 75, 85, 2_000, remote=True),
    IntelligenceOption("frontier", IntelligenceTier.FRONTIER_API, 100, 100, 20_000, remote=True),
)


class IntelligenceEscalationTests(unittest.TestCase):
    def test_deterministic_first_when_sufficient(self):
        plan = select_intelligence(IntelligenceRequest(5, 80, 50_000), OPTIONS)
        self.assertEqual(plan.option.name, "rules")
        self.assertEqual(plan.authority_effect, "none")

    def test_local_model_before_remote_when_sufficient(self):
        plan = select_intelligence(IntelligenceRequest(30, 50, 50_000), OPTIONS)
        self.assertEqual(plan.option.name, "local-small")

    def test_commodity_before_frontier_when_sufficient(self):
        plan = select_intelligence(IntelligenceRequest(60, 80, 50_000), OPTIONS)
        self.assertEqual(plan.option.name, "commodity")

    def test_frontier_only_when_lower_tiers_insufficient(self):
        plan = select_intelligence(IntelligenceRequest(90, 90, 50_000), OPTIONS)
        self.assertEqual(plan.option.name, "frontier")

    def test_budget_fails_closed_instead_of_overspending(self):
        plan = select_intelligence(IntelligenceRequest(90, 90, 10_000), OPTIONS)
        self.assertIsNone(plan)

    def test_remote_denial_fails_closed_when_local_is_insufficient(self):
        plan = select_intelligence(
            IntelligenceRequest(60, 80, 50_000, remote_allowed=False), OPTIONS
        )
        self.assertIsNone(plan)

    def test_cheapest_sufficient_not_highest_capability(self):
        options = OPTIONS + (
            IntelligenceOption("local-expensive", IntelligenceTier.LOCAL_MODEL, 100, 100, 30_000),
        )
        plan = select_intelligence(IntelligenceRequest(20, 20, 50_000), options)
        self.assertEqual(plan.option.name, "local-small")

    def test_invalid_request_is_rejected(self):
        with self.assertRaises(ValueError):
            IntelligenceRequest(101, 10, 100)


if __name__ == "__main__":
    unittest.main()

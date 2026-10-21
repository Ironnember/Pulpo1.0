"""Negative and positive tests for the synthetic education example."""

from dataclasses import replace
import importlib.util
from pathlib import Path
import unittest


module_path = Path(__file__).with_name("lab01.py")
spec = importlib.util.spec_from_file_location("lab01", module_path)
assert spec is not None and spec.loader is not None
import sys
lab01 = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lab01
spec.loader.exec_module(lab01)


class TestFinancialProposal(unittest.TestCase):
    def setUp(self):
        self.good = {"recipient": "sandbox-supplier", "amount_usd": "29.90", "purpose": "test only"}

    def test_valid_proposal_never_grants_authority(self):
        p = lab01.normalize_proposal(self.good)
        self.assertEqual(p.amount_cents, 2990)
        self.assertTrue(p.within_example_limit)
        self.assertEqual((p.authority, p.execution, p.consequence), ("NOT_GRANTED", "NOT_ATTEMPTED", "UNKNOWN"))

    def test_limit_does_not_convert_proposal_to_authorization(self):
        p = lab01.normalize_proposal({**self.good, "amount_usd": "30.01"})
        self.assertFalse(p.within_example_limit)
        self.assertEqual(p.authority, "NOT_GRANTED")

    def test_changed_action_components_change_digest(self):
        original = lab01.normalize_proposal(self.good)
        cases = (
            {**self.good, "amount_usd": "29.91"},
            {**self.good, "recipient": "alternate-supplier"},
            {**self.good, "purpose": "different intended purpose"},
        )
        for changed in cases:
            with self.subTest(changed=changed):
                self.assertNotEqual(lab01.normalize_proposal(changed).source_hash, original.source_hash)

    def test_missing_or_extra_fields_fail_closed(self):
        for raw in ({k: v for k, v in self.good.items() if k != "purpose"}, {**self.good, "authorize": True}):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                lab01.normalize_proposal(raw)

    def test_malformed_prices_fail_closed(self):
        values = ("29.9", "29.900", "-1.00", "1e3", "", ".99", " 2.00", "00.50", 29.90, 0, True, None)
        for amount in values:
            with self.subTest(amount=amount), self.assertRaises(ValueError):
                lab01.normalize_proposal({**self.good, "amount_usd": amount})

    def test_invalid_limit_fail_closed(self):
        for limit in (-1, True, 3.0, "3000"):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                lab01.normalize_proposal(self.good, limit_cents=limit)

    def test_proposal_immutability(self):
        p = lab01.normalize_proposal(self.good)
        with self.assertRaises(Exception):
            p.amount_cents = 1


if __name__ == "__main__":
    unittest.main()

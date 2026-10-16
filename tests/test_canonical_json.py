"""Compatibility proof for canonical JSON encoder reuse."""
from concurrent.futures import ThreadPoolExecutor
import json
import random
import unittest
from pulpo import state, kernel

HELPERS = (state._canonical, kernel._canonical)

def original(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

class CanonicalJsonTests(unittest.TestCase):
    def test_canonical_bytes_match_existing_number_unicode_and_nested_semantics(self):
        values = [None, True, False, 0, -0.0, 1e-300, 1e300, 2**200,
                  float("nan"), float("inf"), float("-inf"), "café 🐙", "\\\"\n\t",
                  "\ud800", [], {}, {"z": [None, {}, [], False], "a": -0.0},
                  {1: "integer", 2: "key"}, (1, "tuple")]
        rng = random.Random(4209)
        for _ in range(500):
            values.append({"z": rng.random(), "a": [rng.randint(-10**20, 10**20),
                          "é" * rng.randrange(10), {"nil": None, "bool": bool(rng.randrange(2))}]})
        for value in values:
            expected = original(value)
            for helper in HELPERS:
                self.assertEqual(expected, helper(value))

    def test_invalid_values_and_circular_inputs_keep_failure_behavior_and_recover(self):
        circular = []; circular.append(circular)
        values = [circular, {1: "one", "a": "mixed"}, {"bad": {1, 2}}, object()]
        for value in values:
            try: original(value)
            except Exception as exc: expected = type(exc)
            else: self.fail("fixture must fail")
            for helper in HELPERS:
                with self.assertRaises(expected): helper(value)
                self.assertEqual(original({"valid": [1, None]}), helper({"valid": [1, None]}))

    def test_concurrent_calls_do_not_share_recursion_or_encoding_state(self):
        values = [{"id": i, "text": "🐙", "nested": [i / 3, None]} for i in range(1000)]
        expected = list(map(original, values))
        for helper in HELPERS:
            with ThreadPoolExecutor(max_workers=8) as pool:
                self.assertEqual(expected, list(pool.map(helper, values)))

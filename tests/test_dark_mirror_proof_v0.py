import copy
from hashlib import sha256
import json
import tempfile
import unittest
from pathlib import Path

from scripts.prove_dark_mirror_v0 import CASES, build_packet, canonical


class DarkMirrorProofV0Tests(unittest.TestCase):
    def test_case_matrix_has_one_unique_case_per_required_lens(self):
        expected = {
            "light", "empower", "mirror", "block",
            "starve", "upside_down", "invert", "dark",
        }
        self.assertEqual(expected, {case["lens"] for case in CASES})
        self.assertEqual(len(CASES), len({case["test"] for case in CASES}))

    def test_packet_binds_results_and_preserves_no_external_effect_boundary(self):
        packet = build_packet()
        claimed = packet.pop("evidence_hash")
        self.assertEqual(sha256(canonical(packet)).hexdigest(), claimed)
        self.assertEqual("Verified", packet["claim_classification"])
        self.assertEqual((8, 8, 0), (
            packet["summary"]["case_count"],
            packet["summary"]["passed"],
            packet["summary"]["failed"],
        ))
        self.assertEqual("none", packet["effects"]["authority_effect"])
        self.assertFalse(packet["effects"]["provider_write_attempted"])
        self.assertFalse(packet["effects"]["external_consequence_claimed"])

    def test_packet_hash_detects_result_substitution(self):
        packet = build_packet()
        tampered = copy.deepcopy(packet)
        claimed = tampered.pop("evidence_hash")
        tampered["cases"][0]["outcome"] = "fail"
        self.assertNotEqual(sha256(canonical(tampered)).hexdigest(), claimed)


if __name__ == "__main__":
    unittest.main()

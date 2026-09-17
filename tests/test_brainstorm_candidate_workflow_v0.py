import copy
from hashlib import sha256
import unittest

from scripts.prove_brainstorm_candidate_workflow_v0 import build_packet, canonical


class BrainStormCandidateWorkflowV0Tests(unittest.TestCase):
    def test_candidate_packet_is_traceable_and_no_effect(self):
        packet = build_packet()
        claimed = packet.pop("evidence_hash")
        self.assertEqual(sha256(canonical(packet)).hexdigest(), claimed)
        self.assertEqual("Verified", packet["proof_classification"])
        self.assertEqual((8, 8, 0), (
            packet["summary"]["check_count"],
            packet["summary"]["passed"],
            packet["summary"]["failed"],
        ))
        self.assertEqual("Unknown", packet["candidate"]["relationship_classification"])
        self.assertEqual("not_authorized", packet["workflow"]["release_state"])
        self.assertEqual("none", packet["effects"]["authority_effect"])
        self.assertFalse(packet["effects"]["canonical_state_mutation"])
        self.assertFalse(packet["effects"]["external_message_sent"])

    def test_every_recorded_claim_has_an_exact_source(self):
        packet = build_packet()
        source_ids = {source["id"] for source in packet["sources"]}
        self.assertTrue(packet["claims"])
        for claim in packet["claims"]:
            self.assertEqual("Recorded", claim["classification"])
            self.assertTrue(claim["source_ids"])
            self.assertLessEqual(set(claim["source_ids"]), source_ids)

    def test_packet_hash_detects_relationship_substitution(self):
        packet = build_packet()
        tampered = copy.deepcopy(packet)
        claimed = tampered.pop("evidence_hash")
        tampered["candidate"]["design_partner_claimed"] = True
        self.assertNotEqual(sha256(canonical(tampered)).hexdigest(), claimed)


if __name__ == "__main__":
    unittest.main()

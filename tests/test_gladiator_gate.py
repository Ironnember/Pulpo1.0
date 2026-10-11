"""Regression tests for schema drift, false victory, and evidence substitution."""
import unittest
from dataclasses import replace
from pulpo.gladiator_gate import GladiatorRecord, completion_eligible


class GladiatorCompletionGateTests(unittest.TestCase):
    def setUp(self):
        self.record = GladiatorRecord(
            object_id="assessment:example",
            source_revision="sha256:fixed-revision",
            pulpo_assessment_ref="evidence:pulpo",
            tournament_ref="evidence:tournament",
            teams=("light+dark", "starve+empower"),
            battle_refs=("evidence:battle-1",),
            independent_verdict_ref="evidence:independent-review",
            reconciliation_ref="evidence:reconciliation",
            unresolved_risks=("provider isolation not proven",),
            held_out_ref="evidence:held-out",
            independent_verdict="PASS",
            reconciliation_state="COMPLETE",
            completion_claim="VERIFIED",
        )

    def eligible(self, record=None):
        if record is None:
            record = self.record
        return completion_eligible(record,
            expected_object="assessment:example",
            expected_revision="sha256:fixed-revision")

    def test_complete_record_eligible_for_review_not_execution(self):
        self.assertTrue(self.eligible())

    def test_missing_tournament_denied(self):
        self.assertFalse(self.eligible(replace(self.record, tournament_ref="")))

    def test_missing_teams_denied(self):
        self.assertFalse(self.eligible(replace(self.record, teams=())))

    def test_one_team_denied(self):
        self.assertFalse(self.eligible(replace(self.record, teams=("only",))))

    def test_string_teams_denied(self):
        self.assertFalse(self.eligible(replace(self.record, teams="ab")))

    def test_duplicate_teams_denied(self):
        self.assertFalse(self.eligible(replace(self.record, teams=("a", "a"))))

    def test_missing_battles_denied(self):
        self.assertFalse(self.eligible(replace(self.record, battle_refs=())))

    def test_string_battles_denied(self):
        self.assertFalse(self.eligible(replace(self.record, battle_refs="battle")))

    def test_missing_independent_verdict_ref_denied(self):
        self.assertFalse(self.eligible(replace(self.record, independent_verdict_ref="")))

    def test_missing_reconciliation_ref_denied(self):
        self.assertFalse(self.eligible(replace(self.record, reconciliation_ref="")))

    def test_missing_held_out_denied(self):
        self.assertFalse(self.eligible(replace(self.record, held_out_ref="")))

    def test_object_substitution_denied(self):
        self.assertFalse(self.eligible(replace(self.record, object_id="assessment:other")))

    def test_revision_substitution_denied(self):
        self.assertFalse(self.eligible(replace(self.record, source_revision="sha256:other")))

    def test_pending_reconciliation_cannot_verify(self):
        self.assertFalse(self.eligible(replace(self.record, reconciliation_state="PENDING")))

    def test_unknown_verdict_cannot_verify(self):
        self.assertFalse(self.eligible(replace(self.record, independent_verdict="UNKNOWN")))

    def test_lowercase_claim_denied(self):
        self.assertFalse(self.eligible(replace(self.record, completion_claim="verified")))

    def test_missing_claim_denied(self):
        self.assertFalse(self.eligible(replace(self.record, completion_claim=None)))

    def test_invalid_verdict_denied(self):
        self.assertFalse(self.eligible(replace(self.record, independent_verdict="False")))

    def test_unknown_closed_review_not_verified_success(self):
        record = replace(self.record, independent_verdict="UNKNOWN",
                         completion_claim="CLOSED_UNKNOWN")
        self.assertTrue(self.eligible(record))

    def test_deny_closed_review_not_verified_success(self):
        record = replace(self.record, independent_verdict="DENY",
                         completion_claim="CLOSED_DENIED")
        self.assertTrue(self.eligible(record))

    def test_false_independence_assertion_not_attested(self):
        # Presence checks cannot authenticate this caller-supplied reference.
        self.assertTrue(self.eligible(replace(
            self.record, independent_verdict_ref="self:asserted")))
        # This test documents a remaining proof boundary, not a success claim.


if __name__ == "__main__":
    unittest.main()

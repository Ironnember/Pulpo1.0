"""Negative proof: omitted or substituted tournament evidence cannot pass gate."""
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
        )

    def eligible(self, record=None):
        return completion_eligible(record or self.record,
            expected_object="assessment:example",
            expected_revision="sha256:fixed-revision")

    def test_complete_record_eligible_for_review_not_execution(self):
        self.assertTrue(self.eligible())

    def test_missing_tournament_denied(self):
        self.assertFalse(self.eligible(replace(self.record, tournament_ref="")))

    def test_missing_teams_denied(self):
        self.assertFalse(self.eligible(replace(self.record, teams=())))

    def test_missing_battles_denied(self):
        self.assertFalse(self.eligible(replace(self.record, battle_refs=())))

    def test_missing_independent_verdict_denied(self):
        self.assertFalse(self.eligible(replace(self.record, independent_verdict_ref="")))

    def test_missing_reconciliation_denied(self):
        self.assertFalse(self.eligible(replace(self.record, reconciliation_ref="")))

    def test_missing_held_out_denied(self):
        self.assertFalse(self.eligible(replace(self.record, held_out_ref="")))

    def test_object_substitution_denied(self):
        self.assertFalse(self.eligible(replace(self.record, object_id="assessment:other")))

    def test_revision_substitution_denied(self):
        self.assertFalse(self.eligible(replace(self.record, source_revision="sha256:other")))

    def test_duplicate_team_denied(self):
        self.assertFalse(self.eligible(replace(self.record, teams=("a", "a")))


if __name__ == "__main__":
    unittest.main()

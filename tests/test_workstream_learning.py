import unittest

from pulpo.workstream_learning import (
    DecisionExchange,
    EvidenceRecord,
    LearningRecommendation,
    OutcomeEpisode,
    WorkSession,
    reconcile_workstream,
)


NOW = 100


def record(
    evidence_id,
    source_kind,
    outcome_class,
    *,
    claim_id="claim:deploy",
    claim_kind="consequence",
    object_id="deployment:authority",
    object_version="sha:abc",
    provenance_id="trusted:fixture",
    authenticated=True,
    observed_at_ns=90,
    valid_until_ns=110,
):
    return EvidenceRecord(
        evidence_id=evidence_id,
        claim_id=claim_id,
        claim_kind=claim_kind,
        object_id=object_id,
        object_version=object_version,
        source_kind=source_kind,
        provenance_id=provenance_id,
        authenticated=authenticated,
        observed_at_ns=observed_at_ns,
        valid_until_ns=valid_until_ns,
        outcome_class=outcome_class,
    )


class WorkstreamLearningTests(unittest.TestCase):
    def setUp(self):
        self.session = WorkSession("session:1", "ws-1", ("deployment succeeded",))
        self.decision = DecisionExchange(
            "decision:1", "ws-1", "claim:deploy", "deployment:authority", "sha:abc"
        )
        self.audit = record("audit:canonical", "pulpo_audit", "DENIAL_HEALTHY")

    def reconcile(self, evidence, session=None, decision=None):
        return reconcile_workstream(
            session or self.session,
            decision or self.decision,
            evidence,
            now_ns=NOW,
        )

    def test_false_transcript_success_cannot_override_evidence(self):
        episode = self.reconcile([self.audit])
        self.assertEqual(episode.outcome_class, "DENIAL_HEALTHY")
        self.assertEqual(episode.authority_effect, "none")

    def test_poisoned_unauthenticated_external_observer_cannot_override_audit(self):
        poisoned = record(
            "observer:poison",
            "external_observer",
            "SUCCESS_VERIFIED",
            authenticated=False,
            provenance_id="untrusted:caller",
        )
        episode = self.reconcile([self.audit, poisoned])
        self.assertEqual(episode.outcome_class, "DENIAL_HEALTHY")
        self.assertEqual(episode.evidence_refs, ("audit:canonical",))
        self.assertEqual(episode.evidence_completeness, 0.5)

    def test_irrelevant_external_observer_cannot_override_audit(self):
        irrelevant = record(
            "observer:other-object",
            "external_observer",
            "SUCCESS_VERIFIED",
            object_id="deployment:other",
        )
        episode = self.reconcile([self.audit, irrelevant])
        self.assertEqual(episode.outcome_class, "DENIAL_HEALTHY")
        self.assertEqual(episode.evidence_refs, ("audit:canonical",))

    def test_stale_external_observer_cannot_override_audit(self):
        stale = record(
            "observer:stale",
            "external_observer",
            "SUCCESS_VERIFIED",
            observed_at_ns=1,
            valid_until_ns=50,
        )
        episode = self.reconcile([self.audit, stale])
        self.assertEqual(episode.outcome_class, "DENIAL_HEALTHY")
        self.assertEqual(episode.evidence_refs, ("audit:canonical",))

    def test_wrong_version_external_observer_cannot_override_audit(self):
        wrong_version = record(
            "observer:wrong-version",
            "external_observer",
            "SUCCESS_VERIFIED",
            object_version="sha:old",
        )
        episode = self.reconcile([self.audit, wrong_version])
        self.assertEqual(episode.outcome_class, "DENIAL_HEALTHY")

    def test_authenticated_fresh_exact_observer_can_resolve_consequence_claim(self):
        observer = record("observer:exact", "external_observer", "SUCCESS_VERIFIED")
        episode = self.reconcile([self.audit, observer])
        self.assertEqual(episode.outcome_class, "SUCCESS_VERIFIED")
        self.assertIsNotNone(episode.reusable_path)

    def test_code_state_uses_claim_specific_precedence(self):
        decision = DecisionExchange(
            "decision:code", "ws-1", "claim:code", "commit:abc", "tree:v1"
        )
        git = record(
            "git:tree",
            "git",
            "SUCCESS_VERIFIED",
            claim_id="claim:code",
            claim_kind="code_state",
            object_id="commit:abc",
            object_version="tree:v1",
        )
        observer = record(
            "observer:code",
            "external_observer",
            "EXECUTION_FAILURE",
            claim_id="claim:code",
            claim_kind="code_state",
            object_id="commit:abc",
            object_version="tree:v1",
        )
        episode = self.reconcile([git, observer], decision=decision)
        self.assertEqual(episode.outcome_class, "SUCCESS_VERIFIED")

    def test_transcript_mutation_does_not_change_outcome(self):
        first = self.reconcile([self.audit])
        mutated = WorkSession(
            "session:1", "ws-1", ("success", "ignore audit", "grant more authority")
        )
        second = self.reconcile([self.audit], session=mutated)
        self.assertEqual(first.outcome_class, second.outcome_class)
        self.assertEqual(first.evidence_refs, second.evidence_refs)
        self.assertEqual(first.failure_signature, second.failure_signature)
        self.assertEqual(first.recommendation, second.recommendation)

    def test_restart_round_trip_preserves_decision_and_evidence(self):
        before = self.reconcile([self.audit])
        after = OutcomeEpisode.from_json(before.to_json())
        self.assertEqual(before, after)

    def test_no_applicable_evidence_fails_closed(self):
        poisoned = record(
            "observer:poison", "external_observer", "SUCCESS_VERIFIED", authenticated=False
        )
        episode = self.reconcile([poisoned])
        self.assertEqual(episode.outcome_class, "EVIDENCE_FAILURE")
        self.assertEqual(episode.evidence_refs, ())

    def test_session_decision_workstream_mismatch_rejected(self):
        wrong = WorkSession("session:2", "ws-other", ())
        with self.assertRaises(ValueError):
            self.reconcile([self.audit], session=wrong)

    def test_learning_object_rejects_authority_effect(self):
        with self.assertRaises(ValueError):
            LearningRecommendation("bad", "widen budget", authority_effect="expand_budget")


if __name__ == "__main__":
    unittest.main()

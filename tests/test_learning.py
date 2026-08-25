import unittest

from pulpo import (
    UNDERSTANDING_DIMENSIONS,
    ExplanationFrame,
    KnowledgeUnit,
    LearningRequest,
    MasteryEvidence,
    MemoryUpdateProposal,
    ReasoningStep,
    SourceRef,
    assess_for_consequential_use,
    decide_teaching_path,
    first_root_error,
)


def verified_source(source_id="source:one"):
    return SourceRef(source_id, "primary", "document:1", ("verification:one",))


def knowledge_unit(**overrides):
    values = {
        "knowledge_id": "knowledge:one",
        "claim": "A scoped, sourced claim",
        "kind": "fact",
        "sources": (verified_source(),),
        "scope": "domain:test; version:1",
        "mechanism": "The evidence directly demonstrates the claim.",
        "confidence": "verified",
        "confidence_basis": "Primary evidence was independently checked.",
        "application_examples": ("Apply within the declared test scope.",),
        "failure_modes": ("Do not reuse outside the declared scope.",),
    }
    values.update(overrides)
    return KnowledgeUnit(**values)


class MasterTeacherTests(unittest.TestCase):
    def test_knowledge_requires_provenance(self):
        with self.assertRaisesRegex(ValueError, "provenance"):
            knowledge_unit(sources=())

    def test_claim_kind_keeps_fact_inference_and_directive_distinct(self):
        fact = knowledge_unit(kind="fact")
        inference = knowledge_unit(knowledge_id="knowledge:two", kind="interpretation")
        directive = knowledge_unit(knowledge_id="knowledge:three", kind="authorized_directive")
        self.assertEqual(
            ("fact", "interpretation", "authorized_directive"),
            (fact.kind, inference.kind, directive.kind),
        )

    def test_verified_confidence_requires_verification_references(self):
        source = SourceRef("source:unverified", "secondary", "document:2")
        with self.assertRaisesRegex(ValueError, "verified sources"):
            knowledge_unit(sources=(source,))

    def test_source_verification_marker_requires_evidence_reference(self):
        source = SourceRef("source:one", "primary", "document:1")
        self.assertFalse(source.verified)
        self.assertTrue(verified_source().verified)

    def test_socratic_mode_observes_attempt_before_resolution(self):
        decision = decide_teaching_path(LearningRequest("socratic"))
        self.assertEqual(("ask_for_attempt", "learner_model_not_observed"), (decision.outcome, decision.reason))

    def test_direct_explanation_is_not_blocked_by_socratic_gate(self):
        request = LearningRequest("socratic", direct_explanation_requested=True)
        self.assertEqual("release_full_resolution", decide_teaching_path(request).outcome)

    def test_safety_information_is_never_withheld(self):
        request = LearningRequest("practice", safety_critical=True)
        self.assertEqual("safety_information_must_not_be_withheld", decide_teaching_path(request).reason)

    def test_root_error_is_first_invalid_reasoning_step(self):
        steps = (
            ReasoningStep("classify", True, "classification checked"),
            ReasoningStep("direction", False, "increase was treated as decrease"),
            ReasoningStep("final total", False, "total is consequently wrong"),
        )
        self.assertEqual("direction", first_root_error(steps).label)

    def test_explanation_requires_mechanics_effects_and_boundaries(self):
        with self.assertRaisesRegex(ValueError, "boundaries"):
            ExplanationFrame(
                inputs=("event",),
                governing_principles=("rule",),
                steps=("classify", "apply"),
                mechanism="The rule transforms the classified input.",
                downstream_effects=("reported outcome changes",),
                boundaries=(),
                real_world_application="A bounded operating example.",
            )

    def test_contradictions_are_preserved_and_block_consequential_use(self):
        unit = knowledge_unit(contradictions=("source:two disputes the applicable scope",))
        assessment = assess_for_consequential_use(unit, memory_trusted=True)
        self.assertEqual(("deny", "material_contradiction_unresolved"), (assessment.outcome, assessment.reason))

    def test_recall_alone_is_not_full_understanding(self):
        evidence = MasteryEvidence(frozenset({"recall"}), ("test:recall",))
        self.assertFalse(evidence.demonstrates_full_understanding())

    def test_all_dimensions_with_evidence_can_demonstrate_understanding(self):
        evidence = MasteryEvidence(UNDERSTANDING_DIMENSIONS, ("test:complete",))
        self.assertTrue(evidence.demonstrates_full_understanding())

    def test_memory_revision_cannot_claim_authority_effect(self):
        proposal = MemoryUpdateProposal("proposal:one", knowledge_unit(), "Stronger evidence changed the lesson.")
        self.assertEqual(("none", "none"), (proposal.authority_effect, proposal.candidate.authority_effect))
        with self.assertRaises(TypeError):
            MemoryUpdateProposal(
                "proposal:two",
                knowledge_unit(),
                "Attempted authority expansion.",
                authority_effect="expand",
            )

    def test_revision_preserves_superseded_knowledge_and_reason(self):
        candidate = knowledge_unit(supersedes=("knowledge:old",))
        proposal = MemoryUpdateProposal(
            "proposal:revision",
            candidate,
            "A verified primary source supersedes the older secondary interpretation.",
            supersedes=("knowledge:old",),
        )
        self.assertEqual(("knowledge:old",), proposal.supersedes)
        self.assertIn("primary source", proposal.rationale)

    def test_untrusted_memory_fails_closed(self):
        assessment = assess_for_consequential_use(knowledge_unit(), memory_trusted=False)
        self.assertEqual(("deny", "essential_memory_untrusted"), (assessment.outcome, assessment.reason))

    def test_verification_markers_cannot_refer_learning_to_governance(self):
        assessment = assess_for_consequential_use(knowledge_unit(), memory_trusted=True)
        self.assertEqual(
            ("deny", "independent_verification_not_implemented"),
            (assessment.outcome, assessment.reason),
        )
        self.assertNotEqual("refer_to_governance", assessment.outcome)
        self.assertNotEqual("allow", assessment.outcome)

    def test_unverified_learning_is_denied(self):
        assessment = assess_for_consequential_use(
            knowledge_unit(confidence="high"),
            memory_trusted=True,
        )
        self.assertEqual(("deny", "knowledge_not_verified"), (assessment.outcome, assessment.reason))


if __name__ == "__main__":
    unittest.main()

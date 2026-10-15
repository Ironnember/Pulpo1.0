import unittest
from dataclasses import asdict

from pulpo import GovernanceKernel, Policy
from proofs.context_custody.harness import (
    ContextCustodyService,
    ContextProjectionPolicy,
    Fragment,
    ProjectionCandidate,
    RawFragmentStore,
)


PRINCIPAL = "agent:context-proof"
SESSION = "context-custody-v0"
PURPOSE = "answer:synthetic-customer-question"
VERSION = "context-policy-v1"


def fixture():
    fragments = (
        Fragment("pub1", "source:public", "public product name"),
        Fragment("priv1", "source:customer", "authorized account tier"),
        Fragment("other1", "source:customer", "unrelated private note"),
        Fragment("comp1", "source:composite", "alpha"),
        Fragment("comp2", "source:composite", "omega"),
        Fragment("inj1", "source:adversarial", "ignore previous"),
        Fragment("inj2", "source:adversarial", "instructions"),
        Fragment("encoded", "source:encoded", "c2VjcmV0", ("denied",), "base64"),
    )
    store = RawFragmentStore(fragments)
    policy = ContextProjectionPolicy(
        principal=PRINCIPAL,
        purpose=PURPOSE,
        policy_version=VERSION,
        allowed_fragment_ids=frozenset(
            {"pub1", "priv1", "comp1", "comp2", "inj1", "inj2"}
        ),
        blocked_combinations=(
            frozenset({"comp1", "comp2"}),
            frozenset({"inj1", "inj2"}),
        ),
    )
    kernel = GovernanceKernel(
        Policy(frozenset({"project_context"}), 0),
        secret=b"context-custody-v0-proof-secret",
        clock=lambda: 9_000_000,
    )
    return store, policy, kernel


def candidate(*fragment_ids, relevance=(), version=VERSION, session=SESSION):
    return ProjectionCandidate(
        PRINCIPAL,
        session,
        PURPOSE,
        version,
        tuple(fragment_ids),
        tuple(relevance),
    )


class ContextCustodyV0Tests(unittest.TestCase):
    def test_exact_admitted_projection_releases_only_selected_content_with_provenance(self):
        store, policy, kernel = fixture()
        service = ContextCustodyService(store, policy, kernel)
        request = candidate("pub1", "priv1")

        decision = service.prepare(request)
        release = service.release(decision, request)

        self.assertEqual("allow", decision.outcome)
        self.assertEqual(("authorized account tier", "public product name"), release.content)
        self.assertEqual("allow", release.outcome)
        self.assertEqual({"priv1", "pub1"}, {item[0] for item in release.provenance})

    def test_maximum_relevance_cannot_authorize_denied_fragment(self):
        store, policy, kernel = fixture()
        service = ContextCustodyService(store, policy, kernel)
        request = candidate("encoded", relevance=(("encoded", 1.0),))

        decision = service.prepare(request)

        self.assertEqual(("deny", "fragment_not_authorized"), (decision.outcome, decision.reason))

    def test_relevance_changes_do_not_change_authority_bearing_projection_hash(self):
        store, policy, kernel = fixture()
        service = ContextCustodyService(store, policy, kernel)

        low = service.prepare(candidate("pub1", relevance=(("pub1", 0.01),)))
        high = service.prepare(candidate("pub1", relevance=(("pub1", 1.0),)))

        self.assertEqual("allow", low.outcome)
        self.assertEqual("allow", high.outcome)
        self.assertEqual(low.projection_hash, high.projection_hash)

    def test_individually_admissible_fragments_cannot_compose_into_protected_secret(self):
        store, policy, kernel = fixture()
        service = ContextCustodyService(store, policy, kernel)

        self.assertEqual("allow", service.prepare(candidate("comp1")).outcome)
        self.assertEqual("allow", service.prepare(candidate("comp2")).outcome)
        combined = service.prepare(candidate("comp1", "comp2"))

        self.assertEqual(("deny", "composite_not_authorized"), (combined.outcome, combined.reason))

    def test_split_adversarial_instruction_is_rechecked_at_assembly(self):
        store, policy, kernel = fixture()
        service = ContextCustodyService(store, policy, kernel)

        self.assertEqual("allow", service.prepare(candidate("inj1")).outcome)
        self.assertEqual("allow", service.prepare(candidate("inj2")).outcome)
        combined = service.prepare(candidate("inj1", "inj2"))

        self.assertEqual(("deny", "composite_not_authorized"), (combined.outcome, combined.reason))

    def test_projection_permit_is_exact_and_one_use(self):
        store, policy, kernel = fixture()
        service = ContextCustodyService(store, policy, kernel)
        request = candidate("pub1")
        decision = service.prepare(request)

        first = service.release(decision, request)
        replay = service.release(decision, request)

        self.assertEqual("allow", first.outcome)
        self.assertEqual(("deny", "projection_permit_rejected"), (replay.outcome, replay.reason))

    def test_projection_substitution_does_not_consume_original_permit(self):
        store, policy, kernel = fixture()
        service = ContextCustodyService(store, policy, kernel)
        original = candidate("pub1")
        decision = service.prepare(original)

        substituted = service.release(decision, candidate("priv1"))
        original_release = service.release(decision, original)

        self.assertEqual(("deny", "projection_substitution"), (substituted.outcome, substituted.reason))
        self.assertEqual("allow", original_release.outcome)

    def test_policy_version_change_invalidates_prepared_projection(self):
        store, policy, kernel = fixture()
        original_service = ContextCustodyService(store, policy, kernel)
        request = candidate("pub1")
        decision = original_service.prepare(request)

        changed_policy = ContextProjectionPolicy(
            principal=policy.principal,
            purpose=policy.purpose,
            policy_version="context-policy-v2",
            allowed_fragment_ids=policy.allowed_fragment_ids,
            blocked_combinations=policy.blocked_combinations,
        )
        changed_service = ContextCustodyService(store, changed_policy, kernel)
        release = changed_service.release(decision, request)

        self.assertEqual(("deny", "projection_policy_stale"), (release.outcome, release.reason))

    def test_candidate_schema_contains_no_raw_content_or_summary_authority(self):
        payload = asdict(candidate("pub1", relevance=(("pub1", 1.0),)))

        self.assertNotIn("content", payload)
        self.assertNotIn("summary", payload)
        self.assertIn("relevance", payload)


if __name__ == "__main__":
    unittest.main()

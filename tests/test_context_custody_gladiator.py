"""Gladiator counterexamples for the PR #299 object/API boundary."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import tempfile
from threading import Barrier
import unittest
from unittest.mock import patch

from pulpo import GovernanceKernel, Policy, SQLiteKernelState
from proofs.context_custody.harness import ContextCustodyService, Fragment
from tests.test_context_custody_v0 import fixture, candidate


class ContextCustodyGladiatorTests(unittest.TestCase):
    def service(self):
        store, policy, kernel = fixture()
        return store, policy, kernel, ContextCustodyService(store, policy, kernel)

    def assert_denied_without_content(self, release):
        self.assertEqual("deny", release.outcome)
        self.assertEqual((), release.content)
        self.assertEqual((), release.provenance)

    def test_separate_valid_permits_cannot_assemble_composite_secret(self):
        store, policy, kernel, service = self.service()
        first, second = candidate("comp1"), candidate("comp2")
        a, b = service.prepare(first), service.prepare(second)
        self.assertEqual("allow", service.release(a, first).outcome)
        self.assert_denied_without_content(service.release(b, second))

    def test_new_service_and_session_do_not_reset_disclosure_history(self):
        store, policy, kernel, service = self.service()
        first = candidate("inj1")
        self.assertEqual("allow", service.release(service.prepare(first), first).outcome)
        other = ContextCustodyService(store, policy, kernel)
        second = candidate("inj2", session="new-session")
        self.assert_denied_without_content(other.release(other.prepare(second), second))

    def test_sqlite_restart_does_not_restore_composite_disclosure(self):
        store, policy, _, _ = self.service()
        secret = b"synthetic-context-restart-secret"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            state = SQLiteKernelState(path)
            try:
                kernel = GovernanceKernel(Policy(frozenset({"project_context"}), 0), secret=secret, state=state)
                service = ContextCustodyService(store, policy, kernel)
                first = candidate("comp1")
                decision = service.prepare(first)
                self.assertEqual("allow", service.release(decision, first).outcome)
            finally:
                state.close()
            state = SQLiteKernelState(path)
            try:
                kernel = GovernanceKernel(Policy(frozenset({"project_context"}), 0), secret=secret, state=state)
                service = ContextCustodyService(store, policy, kernel)
                self.assert_denied_without_content(service.release(decision, first))
                second = candidate("comp2", session="after-restart")
                self.assert_denied_without_content(service.release(service.prepare(second), second))
                self.assertTrue(kernel.verify_audit())
            finally:
                state.close()

    def test_store_drift_cannot_replace_validated_content_on_later_read(self):
        store, policy, kernel, service = self.service()
        original = store.get("pub1")
        substituted = Fragment("pub1", "source:corrupted", "excluded synthetic secret")
        request = candidate("pub1")
        with patch.object(store, "get", side_effect=[original, original, substituted]):
            decision = service.prepare(request)
            release = service.release(decision, request)
        self.assertNotIn(substituted.content, release.content)
        if release.outcome == "allow":
            self.assertEqual((original.content,), release.content)
            self.assertEqual(decision.source_digests[0][1], release.provenance[0][2])

    def test_kernel_policy_revocation_before_release_denies_old_permit(self):
        store, policy, kernel, service = self.service()
        request = candidate("pub1")
        decision = service.prepare(request)
        kernel.policy = Policy(frozenset(), 0)
        self.assert_denied_without_content(service.release(decision, request))

    def test_same_version_with_different_policy_content_denies_old_projection(self):
        store, policy, kernel, service = self.service()
        request = candidate("pub1")
        decision = service.prepare(request)
        changed = replace(policy, allowed_fragment_ids=frozenset({"pub1"}))
        other = ContextCustodyService(store, changed, kernel)
        self.assert_denied_without_content(other.release(decision, request))

    def test_audit_tamper_denies_disclosure(self):
        store, policy, kernel, service = self.service()
        request = candidate("pub1")
        decision = service.prepare(request)
        kernel.audit[0]["hash"] = "f" * 64
        self.assert_denied_without_content(service.release(decision, request))

    def test_reservation_storage_failure_never_releases_content(self):
        store, policy, kernel, service = self.service()
        request = candidate("pub1")
        decision = service.prepare(request)
        with patch.object(kernel._state, "append_unique", side_effect=OSError("synthetic storage outage")):
            self.assert_denied_without_content(service.release(decision, request))
        self.assert_denied_without_content(service.release(decision, request))

    def test_malformed_candidate_fails_closed(self):
        store, policy, kernel, service = self.service()
        self.assertEqual("deny", service.prepare(None).outcome)
        request = candidate("pub1")
        decision = service.prepare(request)
        self.assert_denied_without_content(service.release(decision, None))

    def test_concurrent_complements_cannot_both_release(self):
        store, policy, kernel, service = self.service()
        requests = [candidate("comp1"), candidate("comp2", session="racing-session")]
        decisions = [service.prepare(r) for r in requests]
        before_consumption, after_reservation = Barrier(2), Barrier(2)
        original_consume = kernel.consume
        original = kernel._state.append_unique
        def consume(*args, **kwargs):
            before_consumption.wait(timeout=5)
            return original_consume(*args, **kwargs)
        def reserved(*args, **kwargs):
            result = original(*args, **kwargs)
            after_reservation.wait(timeout=5)
            return result
        with patch.object(kernel, "consume", side_effect=consume), \
                patch.object(kernel._state, "append_unique", side_effect=reserved):
            with ThreadPoolExecutor(max_workers=2) as pool:
                releases = list(pool.map(lambda pair: service.release(*pair), zip(decisions, requests)))
        self.assertLessEqual(sum(r.outcome == "allow" for r in releases), 1)
        self.assertEqual(2, sum(r["event"] == "context_projection_reserved" for r in kernel.audit))
        for release in releases:
            if release.outcome == "deny": self.assert_denied_without_content(release)

    def test_cooperative_separate_noncomposite_projections_still_release(self):
        store, policy, kernel, service = self.service()
        for request in [candidate("pub1"), candidate("priv1", session="another-session")]:
            self.assertEqual("allow", service.release(service.prepare(request), request).outcome)
        self.assertTrue(kernel.verify_audit())

    def test_failed_complement_does_not_block_unrelated_benign_projection(self):
        store, policy, kernel, service = self.service()
        first = candidate("comp1")
        self.assertEqual("allow", service.release(service.prepare(first), first).outcome)
        denied = candidate("comp2")
        self.assert_denied_without_content(service.release(service.prepare(denied), denied))
        benign = candidate("pub1")
        self.assertEqual("allow", service.release(service.prepare(benign), benign).outcome)

    def test_source_provenance_change_before_release_denies(self):
        store, policy, kernel, service = self.service()
        request = candidate("pub1")
        decision = service.prepare(request)
        original = store.get("pub1")
        with patch.object(store, "get", return_value=replace(original, source_id="new-source")):
            self.assert_denied_without_content(service.release(decision, request))
        self.assertEqual("allow", service.release(decision, request).outcome)

    def test_reorder_is_neutral_but_extra_fragment_is_not(self):
        store, policy, kernel, service = self.service()
        request = candidate("pub1", "priv1")
        decision = service.prepare(request)
        self.assert_denied_without_content(service.release(decision, candidate("pub1", "priv1", "comp1")))
        self.assertEqual("allow", service.release(decision, candidate("priv1", "pub1")).outcome)

    def test_encoded_and_unknown_fragment_enumeration_never_releases(self):
        store, policy, kernel, service = self.service()
        for fragment_id in ["other1", "encoded", "missing", "pub1;other1", "cHViMQ==", "ｐｕｂ１"]:
            request = candidate(fragment_id, relevance=((fragment_id, 1.0),))
            decision = service.prepare(request)
            self.assertEqual("deny", decision.outcome)
            self.assert_denied_without_content(service.release(decision, request))

    def test_public_decision_forgery_cannot_create_permit_authority(self):
        store, policy, kernel, service = self.service()
        request = candidate("pub1")
        decision = service.prepare(request)
        self.assert_denied_without_content(service.release(replace(decision, permit="made-up"), request))
        self.assertEqual("allow", service.release(decision, request).outcome)

    def test_store_exception_text_cannot_leak_through_denial(self):
        store, policy, kernel, service = self.service()
        with patch.object(store, "get", side_effect=ValueError("synthetic excluded secret")):
            decision = service.prepare(candidate("pub1"))
        self.assertEqual("deny", decision.outcome)
        self.assertNotIn("secret", decision.reason)

    def test_snapshot_and_policy_cannot_hold_mutable_label_or_group_fields(self):
        with self.assertRaises(ValueError):
            Fragment("id", "source", "text", ["mutable"])
        store, policy, kernel, service = self.service()
        with self.assertRaises(ValueError):
            replace(policy, blocked_combinations=({"comp1", "comp2"},))

    def test_failed_post_reservation_observation_retains_conservative_history(self):
        store, policy, kernel, service = self.service()
        request = candidate("comp1")
        decision = service.prepare(request)
        original = kernel._state.append_unique
        def append_then_unavailable(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("synthetic observation outage after durable append")
        with patch.object(kernel._state, "append_unique", side_effect=append_then_unavailable):
            self.assert_denied_without_content(service.release(decision, request))
        self.assert_denied_without_content(service.release(decision, request))
        other = candidate("comp2", session="restarted-observer")
        self.assert_denied_without_content(service.release(service.prepare(other), other))
        benign = candidate("pub1")
        self.assertEqual("allow", service.release(service.prepare(benign), benign).outcome)
        self.assertTrue(kernel.verify_audit())

    def test_policy_revocation_during_permit_consumption_denies(self):
        store, policy, kernel, service = self.service()
        request = candidate("pub1")
        decision = service.prepare(request)
        original = kernel.consume
        def consume_then_revoke(*args):
            result = original(*args)
            kernel.policy = Policy(frozenset(), 0)
            return result
        with patch.object(kernel, "consume", side_effect=consume_then_revoke):
            self.assert_denied_without_content(service.release(decision, request))

    def test_boss_relevance_session_rotation_recreation_and_replay(self):
        store, policy, kernel, service = self.service()
        request = candidate("comp1", relevance=(("comp1", 1.0),))
        decision = service.prepare(request)
        self.assertEqual("allow", service.release(decision, request).outcome)
        other = ContextCustodyService(store, policy, kernel)
        self.assert_denied_without_content(other.release(decision, request))
        complement = candidate("comp2", session="rotated", relevance=(("comp2", 1.0),))
        self.assert_denied_without_content(other.release(other.prepare(complement), complement))
        self.assertTrue(kernel.verify_audit())


if __name__ == "__main__":
    unittest.main()

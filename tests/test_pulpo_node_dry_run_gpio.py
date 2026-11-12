"""Phase 2 contract tests. All authority and observations are synthetic fixtures."""
from dataclasses import replace
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import Mock, patch

from pulpo import GovernanceKernel, Policy, SQLiteKernelState
from pulpo.node_dry_run import (
    ACTION, EVENT, DryRunOutput, DryRunGPIOAdapter, DryRunDenied,
    DryRunConsequenceUnknown, output_intent, execute_dry_run_output,
    reconcile_dry_run_output,
)
from pulpo.targets import evaluate_locked_target_with_approval
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


class DryRunGPIOContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pulpo-node-dry-run-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "canonical.sqlite3"
        self.verifier = HmacTestVerifier()
        self.secret = secrets.token_bytes(32)
        self.open_kernel()
        self.output = DryRunOutput(pin=17, level=1)
        self.intent = output_intent(self.output, principal="test-operator", session_id="phase2-test")
        self.target = self.kernel.lock_target("synthetic-gpio-target", self.intent)
        self.sink = DryRunGPIOAdapter()
        self.adapter = Mock(wraps=self.sink, spec=DryRunGPIOAdapter)
        self.envelope = signed_envelope(self.kernel, self.intent, self.verifier, now_ns=2_000_000)

    def open_kernel(self):
        self.state = SQLiteKernelState(self.path)
        self.kernel = GovernanceKernel(
            Policy(frozenset({ACTION}), 1, approval_actions=frozenset({ACTION}), authority_trust=trust_for(self.verifier)),
            secret=self.secret, approval_verifier=self.verifier,
            clock=lambda: 2_000_010, state=self.state,
        )

    def tearDown(self):
        self.state.close()

    def authorize(self, envelope=None, target_hash=None):
        return evaluate_locked_target_with_approval(
            self.kernel, self.target.target_id,
            target_hash if target_hash is not None else self.target.target_hash,
            envelope if envelope is not None else self.envelope,
        )[1]

    def permit(self):
        decision = self.authorize()
        self.assertEqual(decision.outcome, "allow")
        self.assertIsNotNone(decision.permit)
        return decision.permit

    def execute(self, permit, **changes):
        args = dict(target_id=self.target.target_id, target_hash=self.target.target_hash, permit=permit, output=self.output)
        args.update(changes)
        return execute_dry_run_output(self.kernel, self.adapter, **args)

    def reconcile(self, **changes):
        args = dict(target_id=self.target.target_id, target_hash=self.target.target_hash, output=self.output, observed=self.sink.observe())
        args.update(changes)
        return reconcile_dry_run_output(self.kernel, **args)

    def test_no_permit_no_adapter_call(self):
        with self.assertRaises(DryRunDenied):
            self.execute("missing")
        self.adapter.set_output.assert_not_called()
        self.assertFalse(any(r["event"] == EVENT for r in self.kernel.audit))

    def test_forged_approval_no_adapter_call(self):
        decision = self.authorize(replace(self.envelope, signature="00" * 32))
        self.assertEqual((decision.outcome, decision.reason, decision.permit), ("deny", "approval_signature_invalid", None))
        with self.assertRaises(DryRunDenied):
            self.execute(decision.permit)
        self.adapter.set_output.assert_not_called()

    def test_target_substitution_stops_before_authority(self):
        with patch.object(self.kernel, "evaluate_with_approval", wraps=self.kernel.evaluate_with_approval) as evaluate:
            self.assertIsNone(self.authorize(target_hash="0" * 64))
            evaluate.assert_not_called()
        with self.assertRaises(DryRunDenied):
            self.execute("missing", target_hash="0" * 64)
        self.adapter.set_output.assert_not_called()

    def test_valid_exact_approval_one_dry_run_call(self):
        self.execute(self.permit())
        self.adapter.set_output.assert_called_once_with(self.output)
        self.assertEqual(self.sink.observe(), self.output)

    def test_approval_replay_before_execution_no_second_permit(self):
        permit = self.permit()
        replay = self.authorize()
        self.assertEqual(replay.outcome, "deny")
        self.assertIn(replay.reason, {"approval_id_replayed", "approval_nonce_replayed"})
        self.assertIsNone(replay.permit)
        self.adapter.set_output.assert_not_called()
        self.execute(permit)
        self.adapter.set_output.assert_called_once()

    def test_permit_replay_no_second_adapter_call(self):
        permit = self.permit()
        self.execute(permit)
        for _ in range(3):
            with self.assertRaises(DryRunDenied):
                self.execute(permit)
        self.adapter.set_output.assert_called_once()

    def test_restart_replay_no_second_adapter_call(self):
        permit = self.permit()
        self.execute(permit)
        self.state.close()
        self.open_kernel()
        restarted_adapter = Mock(wraps=DryRunGPIOAdapter(), spec=DryRunGPIOAdapter)
        self.adapter = restarted_adapter
        with self.assertRaises(DryRunDenied):
            self.execute(permit)
        restarted_adapter.set_output.assert_not_called()
        replay = self.authorize()
        self.assertEqual(replay.outcome, "deny")
        self.assertIsNone(replay.permit)

    def test_canonical_evidence_reconciled_without_mutation(self):
        self.execute(self.permit())
        before = self.kernel.audit
        self.assertEqual(self.reconcile(), "RECONCILED")
        self.assertEqual(self.reconcile(), "RECONCILED")
        self.assertEqual(self.kernel.audit, before)
        self.assertTrue(self.kernel.verify_audit())
        self.assertEqual(sum(r["event"] == EVENT for r in before), 1)

    def test_pin_level_endpoint_substitution_no_adapter_call(self):
        permit = self.permit()
        for output in (replace(self.output, pin=18), replace(self.output, level=0), replace(self.output, endpoint="synthetic-node:other")):
            with self.subTest(output=output), self.assertRaises(DryRunDenied):
                self.execute(permit, output=output)
        self.adapter.set_output.assert_not_called()
        # Exact request still works: substitutions never consumed its permit.
        self.execute(permit)
        self.adapter.set_output.assert_called_once_with(self.output)

    def test_expired_and_wrong_actor_approvals_no_adapter_call(self):
        for changes, reason in ((dict(ttl_ns=1), "approval_expired"), (dict(principal="wrong-actor"), "approval_principal_mismatch")):
            envelope = signed_envelope(self.kernel, self.intent, self.verifier, now_ns=2_000_000, **changes)
            decision = self.authorize(envelope)
            self.assertEqual(decision.reason, reason)
            with self.assertRaises(DryRunDenied):
                self.execute(decision.permit)
        self.adapter.set_output.assert_not_called()

    def test_missing_and_wrong_observation_not_reconciled(self):
        self.execute(self.permit())
        self.assertEqual(self.reconcile(observed=None), "UNKNOWN")
        self.assertEqual(self.reconcile(observed=replace(self.output, level=0)), "MISMATCH")
        self.assertEqual(self.reconcile(output=replace(self.output, pin=18)), "MISMATCH")

    def test_direct_sink_success_is_not_governed_evidence(self):
        self.sink.set_output(self.output)
        self.assertEqual(self.reconcile(), "UNKNOWN")
        self.assertFalse(any(r["event"] == "permit_consumed" for r in self.kernel.audit))

    def test_adapter_exception_spends_permit_and_does_not_retry(self):
        permit = self.permit()
        self.adapter.set_output.side_effect = RuntimeError("synthetic failure")
        with self.assertRaises(DryRunConsequenceUnknown):
            self.execute(permit)
        self.state.close()
        self.open_kernel()
        with self.assertRaises(DryRunDenied):
            self.execute(permit)
        self.adapter.set_output.assert_called_once()
        self.assertEqual(self.reconcile(), "UNKNOWN")

    def test_observer_outage_after_call_blocks_replay_across_restart(self):
        permit = self.permit()
        self.adapter.observe.side_effect = RuntimeError("observer unavailable")
        with self.assertRaises(DryRunConsequenceUnknown):
            self.execute(permit)
        self.assertEqual(self.sink.observe(), self.output)
        self.state.close()
        self.open_kernel()
        with self.assertRaises(DryRunDenied):
            self.execute(permit)
        self.adapter.set_output.assert_called_once()
        self.assertEqual(self.reconcile(), "UNKNOWN")

    def test_evidence_append_failure_never_becomes_success_or_retry(self):
        permit = self.permit()
        original = self.state.append
        def fail_observation(event, payload, timestamp_ns):
            if event == EVENT:
                raise OSError("synthetic disk failure")
            return original(event, payload, timestamp_ns)
        with patch.object(self.state, "append", side_effect=fail_observation):
            with self.assertRaises(DryRunConsequenceUnknown):
                self.execute(permit)
        self.state.close()
        self.open_kernel()
        with self.assertRaises(DryRunDenied):
            self.execute(permit)
        self.adapter.set_output.assert_called_once()
        self.assertEqual(self.reconcile(), "UNKNOWN")

    def test_wrong_adapter_readback_is_unknown_and_no_retry(self):
        permit = self.permit()
        self.adapter.observe.return_value = replace(self.output, pin=18)
        with self.assertRaises(DryRunConsequenceUnknown):
            self.execute(permit)
        with self.assertRaises(DryRunDenied):
            self.execute(permit)
        self.adapter.set_output.assert_called_once()
        self.assertEqual(self.reconcile(), "UNKNOWN")

    def test_duplicate_observation_not_reconciled(self):
        self.execute(self.permit())
        # A second valid-chain observation is still conflicting evidence.
        payload = dict(next(r["payload"] for r in self.kernel.audit if r["event"] == EVENT))
        payload["consumption_hash"] = "0" * 64
        self.state.append(EVENT, payload, 2_000_010)
        self.assertTrue(self.kernel.verify_audit())
        self.assertEqual(self.reconcile(), "MISMATCH")

    def test_wrong_consumption_reference_not_reconciled(self):
        self.execute(self.permit())
        # Change the projection in memory while preserving the real database.
        # Recompute the hash chain to model a writer with canonical audit access.
        # Even a structurally valid chain cannot reference a non-consumption event.
        import hashlib
        import json
        records = self.kernel.audit
        observation = next(r for r in records if r["event"] == EVENT)
        observation["payload"]["consumption_hash"] = records[0]["hash"]
        previous = "0" * 64
        for record in records:
            record["previous_hash"] = previous
            body = {key: value for key, value in record.items() if key != "hash"}
            record["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            previous = record["hash"]
        with patch.object(type(self.kernel), "audit", new_callable=lambda: property(lambda _: records)):
            self.assertTrue(self.kernel.verify_audit())
            self.assertEqual(self.reconcile(), "MISMATCH")

    def test_reconciliation_rejects_broken_audit_chain(self):
        self.execute(self.permit())
        self.state._connection.execute("UPDATE audit SET hash = ? WHERE event = ?", ("0" * 64, EVENT))
        self.state._connection.commit()
        self.assertEqual(self.reconcile(), "MISMATCH")

    def test_invalid_output_contract_rejected(self):
        for changes in (dict(pin=True), dict(pin=-1), dict(pin=28), dict(level=True), dict(level=2), dict(mode="live"), dict(numbering="BOARD"), dict(endpoint="real-device")):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(self.output, **changes)
        self.adapter.set_output.assert_not_called()

    def test_reconciliation_with_wrong_target_is_non_mutating(self):
        self.execute(self.permit())
        before = self.kernel.audit
        for _ in range(3):
            self.assertEqual(self.reconcile(target_hash="0" * 64), "MISMATCH")
            self.assertEqual(self.reconcile(target_id="missing"), "MISMATCH")
        self.assertEqual(before, self.kernel.audit)


if __name__ == "__main__":
    unittest.main()

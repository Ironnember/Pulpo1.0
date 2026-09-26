import tempfile
import unittest
from pathlib import Path

from pulpo import GovernanceKernel, Policy
from pulpo.agentcore import (
    AGENTCORE_ACTIVATE_ACTION,
    AGENTCORE_INVOKE_ACTION,
    AgentCoreGatewayCall,
    AgentCoreInvocationRejected,
    GovernedAgentCoreGatewayInvoker,
)
from pulpo.custody import SQLiteGovernanceCustody
from pulpo.custody_executor import ExternalConsequenceUnknown
from pulpo.state import SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 9_000_000
SESSION = "agentcore-custody-proof-1"
PRINCIPAL = "agent:assistant"
GATEWAY_ARN = "arn:aws:bedrock-agentcore:us-west-2:111122223333:gateway/pulpo-proof"
GATEWAY_ENDPOINT = "https://pulpo-proof.gateway.bedrock-agentcore.us-west-2.amazonaws.com/mcp"


class FakeTransport:
    def __init__(self, *, fail_after_send=False):
        self.expected_gateway_arn = GATEWAY_ARN
        self.expected_gateway_endpoint = GATEWAY_ENDPOINT
        self.calls = []
        self.idempotency_keys = []
        self.fail_after_send = fail_after_send

    def call_tool(self, call, *, idempotency_key):
        self.calls.append(call)
        self.idempotency_keys.append(idempotency_key)
        if self.fail_after_send:
            raise RuntimeError("simulated lost AgentCore response after send")
        return {
            "provider": "amazon_bedrock_agentcore_gateway",
            "call_hash": call.call_hash,
            "request_id": f"pulpo-{idempotency_key[:24]}",
            "claim_class": "provider_claim",
        }


class AgentCoreCapabilityActivationTests(unittest.TestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: self.path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(self.path) + "-shm").unlink(missing_ok=True))

        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({AGENTCORE_ACTIVATE_ACTION, AGENTCORE_INVOKE_ACTION}),
            0,
            frozenset({AGENTCORE_ACTIVATE_ACTION, AGENTCORE_INVOKE_ACTION}),
            authority_trust=trust_for(self.verifier),
        )
        self.states = []
        self.kernel = self.new_kernel()
        self.custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"agentcore-custody-durable-secret",
            clock=lambda: NOW,
        )
        self.transport = FakeTransport()
        self.invoker = GovernedAgentCoreGatewayInvoker(
            self.kernel,
            self.transport,
            custody=self.custody,
            executor_id="executor:agentcore-proof",
        )
        self.call = AgentCoreGatewayCall.create(
            GATEWAY_ARN,
            GATEWAY_ENDPOINT,
            "update_record",
            {"record_id": "A-17", "status": "verified"},
        )

    def tearDown(self):
        for state in self.states:
            state.close()

    def new_kernel(self):
        state = SQLiteKernelState(self.path)
        self.states.append(state)
        return GovernanceKernel(
            self.policy,
            secret=b"agentcore-custody-proof-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
            state=state,
        )

    def approval(self, kernel, intent, approval_id, nonce):
        return signed_envelope(
            kernel,
            intent,
            self.verifier,
            now_ns=NOW,
            approval_id=approval_id,
            nonce=nonce,
        )

    def permits(self, kernel, suffix):
        activation_intent = self.call.activation_intent(
            principal=PRINCIPAL,
            session_id=SESSION,
        )
        invocation_intent = self.call.intent(
            principal=PRINCIPAL,
            session_id=SESSION,
        )
        activation = kernel.evaluate_with_approval(
            activation_intent,
            self.approval(
                kernel,
                activation_intent,
                f"approve-agentcore-activation-{suffix}",
                f"nonce-agentcore-activation-{suffix}",
            ),
        )
        invocation = kernel.evaluate_with_approval(
            invocation_intent,
            self.approval(
                kernel,
                invocation_intent,
                f"approve-agentcore-call-{suffix}",
                f"nonce-agentcore-call-{suffix}",
            ),
        )
        self.assertEqual("allow", activation.outcome)
        self.assertEqual("allow", invocation.outcome)
        return activation.permit, invocation.permit

    def test_capability_activation_and_invocation_require_distinct_authority(self):
        activation = self.invoker.evaluate_activation(
            self.call,
            principal=PRINCIPAL,
            session_id=SESSION,
        )
        invocation = self.invoker.evaluate(
            self.call,
            principal=PRINCIPAL,
            session_id=SESSION,
        )
        self.assertEqual("require_approval", activation.outcome)
        self.assertEqual("require_approval", invocation.outcome)
        self.assertIsNone(activation.permit)
        self.assertIsNone(invocation.permit)
        self.assertEqual([], self.transport.calls)

    def test_activation_approval_cannot_be_reused_as_tool_invocation_authority(self):
        activation_intent = self.call.activation_intent(
            principal=PRINCIPAL,
            session_id=SESSION,
        )
        envelope = self.approval(
            self.kernel,
            activation_intent,
            "approve-agentcore-activation",
            "nonce-agentcore-activation",
        )
        activation = self.kernel.evaluate_with_approval(activation_intent, envelope)

        self.assertEqual("allow", activation.outcome)
        self.assertFalse(
            self.kernel.consume(
                activation.permit,
                self.call.intent(principal=PRINCIPAL, session_id=SESSION),
            )
        )
        self.assertTrue(self.kernel.consume(activation.permit, activation_intent))
        self.assertFalse(self.kernel.consume(activation.permit, activation_intent))

    def test_exact_two_permit_chain_releases_one_provider_call_and_enters_reconciliation(self):
        activation_permit, invocation_permit = self.permits(self.kernel, "exec")
        claim = self.invoker.execute(
            self.call,
            activation_permit=activation_permit,
            invocation_permit=invocation_permit,
            principal=PRINCIPAL,
            session_id=SESSION,
        )

        self.assertEqual(1, len(self.transport.calls))
        self.assertEqual(self.call.call_hash, claim.call_hash)
        self.assertEqual(claim.attempt_id, self.transport.idempotency_keys[0])
        snapshot = self.custody.attempt(claim.attempt_id)
        self.assertEqual(
            SQLiteGovernanceCustody.RECONCILIATION_REQUIRED,
            snapshot.state,
        )
        self.assertEqual(claim.provider_request_id, snapshot.provider_request_id)

        with self.assertRaisesRegex(AgentCoreInvocationRejected, "custody authorization rejected"):
            fresh_activation, fresh_invocation = self.permits(self.kernel, "same-process-fresh")
            self.invoker.execute(
                self.call,
                activation_permit=fresh_activation,
                invocation_permit=fresh_invocation,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual(1, len(self.transport.calls))

    def test_argument_substitution_is_denied_before_provider_call(self):
        activation_permit, invocation_permit = self.permits(self.kernel, "substitution")
        substituted = AgentCoreGatewayCall.create(
            GATEWAY_ARN,
            GATEWAY_ENDPOINT,
            "update_record",
            {"record_id": "A-17", "status": "deleted"},
        )

        with self.assertRaisesRegex(AgentCoreInvocationRejected, "invocation permit rejected"):
            self.invoker.execute(
                substituted,
                activation_permit=activation_permit,
                invocation_permit=invocation_permit,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual([], self.transport.calls)

    def test_gateway_endpoint_substitution_is_denied_before_provider_call(self):
        activation_permit, invocation_permit = self.permits(self.kernel, "endpoint")
        substituted = AgentCoreGatewayCall.create(
            GATEWAY_ARN,
            "https://other.gateway.bedrock-agentcore.us-west-2.amazonaws.com/mcp",
            "update_record",
            {"record_id": "A-17", "status": "verified"},
        )

        with self.assertRaisesRegex(AgentCoreInvocationRejected, "endpoint mismatch"):
            self.invoker.execute(
                substituted,
                activation_permit=activation_permit,
                invocation_permit=invocation_permit,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual([], self.transport.calls)

    def test_lost_response_persists_unknown_and_restart_with_fresh_approval_cannot_resend(self):
        transport = FakeTransport(fail_after_send=True)
        invoker = GovernedAgentCoreGatewayInvoker(
            self.kernel,
            transport,
            custody=self.custody,
            executor_id="executor:agentcore-proof",
        )
        activation_permit, invocation_permit = self.permits(self.kernel, "lost-response")

        with self.assertRaises(ExternalConsequenceUnknown) as raised:
            invoker.execute(
                self.call,
                activation_permit=activation_permit,
                invocation_permit=invocation_permit,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual(1, len(transport.calls))
        attempt_id = raised.exception.attempt_id
        snapshot = self.custody.attempt(attempt_id)
        self.assertEqual(
            SQLiteGovernanceCustody.RECONCILIATION_REQUIRED,
            snapshot.state,
        )
        self.assertIsNotNone(snapshot.provider_request_id)

        # Simulate process restart: reconstruct kernel, custody, transport, and
        # invoker from the same durable SQLite state. Fresh approvals are valid
        # authority objects, but they cannot create a second transmission right
        # for the already-attempted exact call hash.
        restarted_kernel = self.new_kernel()
        restarted_custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"agentcore-custody-durable-secret",
            clock=lambda: NOW,
        )
        restarted_transport = FakeTransport()
        restarted_invoker = GovernedAgentCoreGatewayInvoker(
            restarted_kernel,
            restarted_transport,
            custody=restarted_custody,
            executor_id="executor:agentcore-proof",
        )
        fresh_activation, fresh_invocation = self.permits(restarted_kernel, "after-restart")

        with self.assertRaisesRegex(AgentCoreInvocationRejected, "attempt_already_authorized"):
            restarted_invoker.execute(
                self.call,
                activation_permit=fresh_activation,
                invocation_permit=fresh_invocation,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual(0, len(restarted_transport.calls))
        persisted = restarted_custody.attempt(attempt_id)
        self.assertEqual(
            SQLiteGovernanceCustody.RECONCILIATION_REQUIRED,
            persisted.state,
        )

    def test_crash_after_transmission_release_blocks_restart_before_second_network_call(self):
        activation_permit, invocation_permit = self.permits(self.kernel, "crash-release")
        attempt = self.invoker.authorize_attempt(
            self.call,
            activation_permit=activation_permit,
            invocation_permit=invocation_permit,
            principal=PRINCIPAL,
            session_id=SESSION,
        )

        head = self.custody.snapshot()
        self.custody.claim_attempt(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=attempt.attempt_id,
            executor_id="executor:agentcore-proof",
        )
        head = self.custody.snapshot()
        self.custody.authorize_transmission(
            expected_epoch=head.epoch,
            expected_state_root=head.state_root,
            attempt_id=attempt.attempt_id,
            provider_request_id=f"agentcore:{attempt.attempt_id}:tools-call:{self.call.call_hash}",
        )
        self.assertEqual(
            SQLiteGovernanceCustody.REQUEST_TRANSMITTED,
            self.custody.attempt(attempt.attempt_id).state,
        )

        restarted_custody = SQLiteGovernanceCustody(
            self.path,
            signing_secret=b"agentcore-custody-durable-secret",
            clock=lambda: NOW,
        )
        restarted_transport = FakeTransport()
        restarted_invoker = GovernedAgentCoreGatewayInvoker(
            self.kernel,
            restarted_transport,
            custody=restarted_custody,
            executor_id="executor:agentcore-proof",
        )
        with self.assertRaisesRegex(AgentCoreInvocationRejected, "attempt_not_executable"):
            restarted_invoker.execute_attempt(attempt, self.call)
        self.assertEqual([], restarted_transport.calls)

    def test_call_identity_changes_with_tool_arguments_and_gateway(self):
        same = AgentCoreGatewayCall.create(
            GATEWAY_ARN,
            GATEWAY_ENDPOINT,
            "update_record",
            {"status": "verified", "record_id": "A-17"},
        )
        changed_tool = AgentCoreGatewayCall.create(
            GATEWAY_ARN,
            GATEWAY_ENDPOINT,
            "delete_record",
            {"record_id": "A-17", "status": "verified"},
        )
        changed_args = AgentCoreGatewayCall.create(
            GATEWAY_ARN,
            GATEWAY_ENDPOINT,
            "update_record",
            {"record_id": "A-18", "status": "verified"},
        )

        self.assertEqual(self.call.call_hash, same.call_hash)
        self.assertNotEqual(self.call.call_hash, changed_tool.call_hash)
        self.assertNotEqual(self.call.call_hash, changed_args.call_hash)


if __name__ == "__main__":
    unittest.main()

import unittest

from pulpo import GovernanceKernel, Policy
from pulpo.agentcore import (
    AGENTCORE_ACTIVATE_ACTION,
    AGENTCORE_INVOKE_ACTION,
    AgentCoreGatewayCall,
    AgentCoreInvocationRejected,
    GovernedAgentCoreGatewayInvoker,
)
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 9_000_000
SESSION = "agentcore-custody-proof-1"
PRINCIPAL = "agent:assistant"
GATEWAY_ARN = "arn:aws:bedrock-agentcore:us-west-2:111122223333:gateway/pulpo-proof"
GATEWAY_ENDPOINT = "https://pulpo-proof.gateway.bedrock-agentcore.us-west-2.amazonaws.com/mcp"


class FakeTransport:
    def __init__(self):
        self.expected_gateway_arn = GATEWAY_ARN
        self.expected_gateway_endpoint = GATEWAY_ENDPOINT
        self.calls = []

    def call_tool(self, call):
        self.calls.append(call)
        return {
            "provider": "amazon_bedrock_agentcore_gateway",
            "call_hash": call.call_hash,
            "claim_class": "provider_claim",
        }


class AgentCoreCapabilityActivationTests(unittest.TestCase):
    def setUp(self):
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({AGENTCORE_ACTIVATE_ACTION, AGENTCORE_INVOKE_ACTION}),
            0,
            frozenset({AGENTCORE_ACTIVATE_ACTION, AGENTCORE_INVOKE_ACTION}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = GovernanceKernel(
            self.policy,
            secret=b"agentcore-custody-proof-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )
        self.transport = FakeTransport()
        self.invoker = GovernedAgentCoreGatewayInvoker(self.kernel, self.transport)
        self.call = AgentCoreGatewayCall.create(
            GATEWAY_ARN,
            GATEWAY_ENDPOINT,
            "update_record",
            {"record_id": "A-17", "status": "verified"},
        )

    def approval(self, intent, approval_id, nonce):
        return signed_envelope(
            self.kernel,
            intent,
            self.verifier,
            now_ns=NOW,
            approval_id=approval_id,
            nonce=nonce,
        )

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

    def test_exact_two_permit_chain_releases_one_provider_call(self):
        activation_intent = self.call.activation_intent(
            principal=PRINCIPAL,
            session_id=SESSION,
        )
        invocation_intent = self.call.intent(
            principal=PRINCIPAL,
            session_id=SESSION,
        )
        activation = self.kernel.evaluate_with_approval(
            activation_intent,
            self.approval(
                activation_intent,
                "approve-agentcore-activation-exec",
                "nonce-agentcore-activation-exec",
            ),
        )
        invocation = self.kernel.evaluate_with_approval(
            invocation_intent,
            self.approval(
                invocation_intent,
                "approve-agentcore-call",
                "nonce-agentcore-call",
            ),
        )

        claim = self.invoker.execute(
            self.call,
            activation_permit=activation.permit,
            invocation_permit=invocation.permit,
            principal=PRINCIPAL,
            session_id=SESSION,
        )

        self.assertEqual(1, len(self.transport.calls))
        self.assertEqual(self.call.call_hash, claim["call_hash"])
        with self.assertRaisesRegex(AgentCoreInvocationRejected, "activation permit rejected"):
            self.invoker.execute(
                self.call,
                activation_permit=activation.permit,
                invocation_permit=invocation.permit,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual(1, len(self.transport.calls))

    def test_argument_substitution_is_denied_before_provider_call(self):
        activation_intent = self.call.activation_intent(
            principal=PRINCIPAL,
            session_id=SESSION,
        )
        invocation_intent = self.call.intent(
            principal=PRINCIPAL,
            session_id=SESSION,
        )
        activation = self.kernel.evaluate_with_approval(
            activation_intent,
            self.approval(
                activation_intent,
                "approve-agentcore-activation-substitution",
                "nonce-agentcore-activation-substitution",
            ),
        )
        invocation = self.kernel.evaluate_with_approval(
            invocation_intent,
            self.approval(
                invocation_intent,
                "approve-agentcore-call-substitution",
                "nonce-agentcore-call-substitution",
            ),
        )
        substituted = AgentCoreGatewayCall.create(
            GATEWAY_ARN,
            GATEWAY_ENDPOINT,
            "update_record",
            {"record_id": "A-17", "status": "deleted"},
        )

        with self.assertRaisesRegex(AgentCoreInvocationRejected, "invocation permit rejected"):
            self.invoker.execute(
                substituted,
                activation_permit=activation.permit,
                invocation_permit=invocation.permit,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual([], self.transport.calls)

    def test_gateway_endpoint_substitution_is_denied_before_provider_call(self):
        activation_intent = self.call.activation_intent(
            principal=PRINCIPAL,
            session_id=SESSION,
        )
        invocation_intent = self.call.intent(
            principal=PRINCIPAL,
            session_id=SESSION,
        )
        activation = self.kernel.evaluate_with_approval(
            activation_intent,
            self.approval(
                activation_intent,
                "approve-agentcore-activation-endpoint",
                "nonce-agentcore-activation-endpoint",
            ),
        )
        invocation = self.kernel.evaluate_with_approval(
            invocation_intent,
            self.approval(
                invocation_intent,
                "approve-agentcore-call-endpoint",
                "nonce-agentcore-call-endpoint",
            ),
        )
        substituted = AgentCoreGatewayCall.create(
            GATEWAY_ARN,
            "https://other.gateway.bedrock-agentcore.us-west-2.amazonaws.com/mcp",
            "update_record",
            {"record_id": "A-17", "status": "verified"},
        )

        with self.assertRaisesRegex(AgentCoreInvocationRejected, "endpoint mismatch"):
            self.invoker.execute(
                substituted,
                activation_permit=activation.permit,
                invocation_permit=invocation.permit,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual([], self.transport.calls)

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

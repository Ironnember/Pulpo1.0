import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.telegram import (
    GovernedTelegramSender,
    TelegramOutboundMessage,
    TelegramSendRejected,
)
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 7_100_000
SESSION = "telegram-capability-activation-proof-1"
PRINCIPAL = "agent:assistant"
BOT_ID = 123456
CHAT_ID = 424242
MESSAGE = "Pulpo capability activation proof"


class ProbeTransport:
    def __init__(self, *, bot_id: int = BOT_ID, chat_id: int = CHAT_ID) -> None:
        self.expected_bot_id = bot_id
        self.allowed_chat_id = chat_id
        self.provider_calls = 0

    def send_message(self, message: TelegramOutboundMessage):
        self.provider_calls += 1
        return {
            "provider": "test_probe",
            "provider_bot_id": message.bot_id,
            "provider_chat_id": message.chat_id,
            "message_hash": message.message_hash,
            "claim_class": "provider_claim",
        }


class TelegramCapabilityActivationPrepTests(unittest.TestCase):
    """Software-only proof that the real send gate requires two exact permits."""

    def setUp(self):
        self.verifier = HmacTestVerifier()
        self.policy = Policy(
            frozenset({"inspect_attachment", "activate_capability", "telegram_send_message"}),
            0,
            frozenset({"activate_capability", "telegram_send_message"}),
            authority_trust=trust_for(self.verifier),
        )
        self.kernel = GovernanceKernel(
            self.policy,
            secret=b"telegram-capability-activation-prep-secret",
            approval_verifier=self.verifier,
            clock=lambda: NOW,
        )
        self.read = Intent(
            PRINCIPAL,
            "inspect_attachment",
            "conversation:telegram-proof:attachment:image",
            0,
            SESSION,
        )
        self.message = TelegramOutboundMessage(BOT_ID, CHAT_ID, MESSAGE)
        self.transport = ProbeTransport()
        self.sender = GovernedTelegramSender(self.kernel, self.transport)

    def _approve_activation(
        self,
        message: TelegramOutboundMessage | None = None,
        *,
        approval_id: str = "approval-activation-1",
        nonce: str = "approval-activation-nonce-1",
    ):
        target = self.message if message is None else message
        intent = target.activation_intent(principal=PRINCIPAL, session_id=SESSION)
        envelope = signed_envelope(
            self.kernel,
            intent,
            self.verifier,
            now_ns=NOW,
            approval_id=approval_id,
            nonce=nonce,
        )
        return self.kernel.evaluate_with_approval(intent, envelope)

    def _approve_message(
        self,
        message: TelegramOutboundMessage | None = None,
        *,
        approval_id: str = "approval-message-1",
        nonce: str = "approval-message-nonce-1",
    ):
        target = self.message if message is None else message
        intent = target.intent(principal=PRINCIPAL, session_id=SESSION)
        envelope = signed_envelope(
            self.kernel,
            intent,
            self.verifier,
            now_ns=NOW,
            approval_id=approval_id,
            nonce=nonce,
        )
        return self.kernel.evaluate_with_approval(intent, envelope)

    def test_available_capability_without_activation_approval_creates_zero_provider_calls(self):
        decision = self.sender.evaluate_activation(
            self.message,
            principal=PRINCIPAL,
            session_id=SESSION,
        )
        self.assertEqual(("require_approval", None), (decision.outcome, decision.permit))
        self.assertEqual(0, self.transport.provider_calls)

    def test_read_permission_cannot_release_telegram_send_capability(self):
        read_decision = self.kernel.evaluate(self.read)
        message_decision = self._approve_message()
        self.assertEqual("allow", read_decision.outcome)
        with self.assertRaisesRegex(TelegramSendRejected, "activation permit rejected"):
            self.sender.execute(
                self.message,
                activation_permit=read_decision.permit,
                message_permit=message_decision.permit,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual(0, self.transport.provider_calls)

    def test_message_authorization_without_activation_cannot_reach_provider(self):
        message_decision = self._approve_message()
        with self.assertRaisesRegex(TelegramSendRejected, "activation permit missing"):
            self.sender.execute(
                self.message,
                activation_permit="",
                message_permit=message_decision.permit,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual(0, self.transport.provider_calls)

    def test_exact_activation_does_not_authorize_message_send(self):
        activation = self._approve_activation()
        self.assertEqual("allow", activation.outcome)
        with self.assertRaisesRegex(TelegramSendRejected, "message permit missing"):
            self.sender.execute(
                self.message,
                activation_permit=activation.permit,
                message_permit="",
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual(0, self.transport.provider_calls)

    def test_exact_activation_and_message_permits_allow_one_provider_call(self):
        activation = self._approve_activation()
        message = self._approve_message()
        claim = self.sender.execute(
            self.message,
            activation_permit=activation.permit,
            message_permit=message.permit,
            principal=PRINCIPAL,
            session_id=SESSION,
        )
        self.assertEqual("provider_claim", claim["claim_class"])
        self.assertEqual(BOT_ID, claim["provider_bot_id"])
        self.assertEqual(1, self.transport.provider_calls)

        with self.assertRaisesRegex(TelegramSendRejected, "activation permit rejected"):
            self.sender.execute(
                self.message,
                activation_permit=activation.permit,
                message_permit=message.permit,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual(1, self.transport.provider_calls)

    def test_activation_permit_cannot_be_retargeted(self):
        activation = self._approve_activation()
        substituted = TelegramOutboundMessage(BOT_ID, 999999, MESSAGE)
        message = self._approve_message(
            substituted,
            approval_id="approval-message-retarget-1",
            nonce="approval-message-retarget-nonce-1",
        )
        transport = ProbeTransport(chat_id=999999)
        sender = GovernedTelegramSender(self.kernel, transport)
        with self.assertRaisesRegex(TelegramSendRejected, "activation permit rejected"):
            sender.execute(
                substituted,
                activation_permit=activation.permit,
                message_permit=message.permit,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual(0, transport.provider_calls)

    def test_activation_permit_cannot_be_retargeted_to_another_bot(self):
        activation = self._approve_activation()
        substituted = TelegramOutboundMessage(654321, CHAT_ID, MESSAGE)
        message = self._approve_message(
            substituted,
            approval_id="approval-message-bot-retarget-1",
            nonce="approval-message-bot-retarget-nonce-1",
        )
        transport = ProbeTransport(bot_id=654321)
        sender = GovernedTelegramSender(self.kernel, transport)
        with self.assertRaisesRegex(TelegramSendRejected, "activation permit rejected"):
            sender.execute(
                substituted,
                activation_permit=activation.permit,
                message_permit=message.permit,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual(0, transport.provider_calls)

    def test_message_permit_cannot_be_retargeted(self):
        original_message = self._approve_message()
        substituted = TelegramOutboundMessage(BOT_ID, CHAT_ID, "other text")
        activation = self._approve_activation(
            substituted,
            approval_id="approval-activation-retarget-1",
            nonce="approval-activation-retarget-nonce-1",
        )
        with self.assertRaisesRegex(TelegramSendRejected, "message permit rejected"):
            self.sender.execute(
                substituted,
                activation_permit=activation.permit,
                message_permit=original_message.permit,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual(0, self.transport.provider_calls)

    def test_message_permit_cannot_be_retargeted_to_another_bot(self):
        original_message = self._approve_message()
        substituted = TelegramOutboundMessage(654321, CHAT_ID, MESSAGE)
        activation = self._approve_activation(
            substituted,
            approval_id="approval-activation-message-bot-retarget-1",
            nonce="approval-activation-message-bot-retarget-nonce-1",
        )
        transport = ProbeTransport(bot_id=654321)
        sender = GovernedTelegramSender(self.kernel, transport)
        with self.assertRaisesRegex(TelegramSendRejected, "message permit rejected"):
            sender.execute(
                substituted,
                activation_permit=activation.permit,
                message_permit=original_message.permit,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual(0, transport.provider_calls)

    def test_transport_identity_mismatch_is_rejected_before_permit_consumption(self):
        substituted = TelegramOutboundMessage(654321, CHAT_ID, MESSAGE)
        activation = self._approve_activation(
            substituted,
            approval_id="approval-activation-bot-mismatch-1",
            nonce="approval-activation-bot-mismatch-nonce-1",
        )
        message = self._approve_message(
            substituted,
            approval_id="approval-message-bot-mismatch-1",
            nonce="approval-message-bot-mismatch-nonce-1",
        )
        with self.assertRaisesRegex(TelegramSendRejected, "bot identity mismatch"):
            self.sender.execute(
                substituted,
                activation_permit=activation.permit,
                message_permit=message.permit,
                principal=PRINCIPAL,
                session_id=SESSION,
            )
        self.assertEqual(0, self.transport.provider_calls)

        matching_transport = ProbeTransport(bot_id=654321)
        matching_sender = GovernedTelegramSender(self.kernel, matching_transport)
        matching_sender.execute(
            substituted,
            activation_permit=activation.permit,
            message_permit=message.permit,
            principal=PRINCIPAL,
            session_id=SESSION,
        )
        self.assertEqual(1, matching_transport.provider_calls)


if __name__ == "__main__":
    unittest.main()

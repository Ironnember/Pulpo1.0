import hashlib
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 7_100_000
SESSION = "telegram-capability-activation-proof-1"
PRINCIPAL = "agent:assistant"
BOT = "telegram:bot:PulpoGovernanceBot"
CHAT = "telegram:chat:private:424242"
MESSAGE = "Pulpo capability activation proof"
MESSAGE_HASH = hashlib.sha256(MESSAGE.encode("utf-8")).hexdigest()


class TelegramCapabilityActivationPrepTests(unittest.TestCase):
    """Pre-provider proof that capability release and message authority are distinct.

    This file deliberately performs no network I/O and proves no live Telegram
    consequence. It composes canonical capability-activation semantics with a
    second exact authorization step for one frozen send-message object.
    """

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
        self.activate = Intent(
            PRINCIPAL,
            "activate_capability",
            f"{BOT}:{CHAT}:capability:sendMessage",
            0,
            SESSION,
        )
        self.send = Intent(
            PRINCIPAL,
            "telegram_send_message",
            f"{BOT}:{CHAT}:sha256:{MESSAGE_HASH}",
            0,
            SESSION,
        )
        self.capability_released = False
        self.provider_calls = 0

    def _release_capability(self, permit, intent=None):
        target = self.activate if intent is None else intent
        if not self.kernel.consume(permit, target):
            return False
        self.capability_released = True
        return True

    def _dispatch(self, permit, intent=None):
        target = self.send if intent is None else intent
        if not self.capability_released:
            return False
        if not self.kernel.consume(permit, target):
            return False
        self.provider_calls += 1
        return True

    def test_available_capability_without_activation_approval_creates_zero_provider_calls(self):
        decision = self.kernel.evaluate(self.activate)
        self.assertEqual(("require_approval", None), (decision.outcome, decision.permit))
        self.assertFalse(self.capability_released)
        self.assertEqual(0, self.provider_calls)

    def test_read_permission_cannot_release_telegram_send_capability(self):
        read_decision = self.kernel.evaluate(self.read)
        self.assertEqual("allow", read_decision.outcome)
        self.assertFalse(self._release_capability(read_decision.permit))
        self.assertFalse(self.capability_released)
        self.assertEqual(0, self.provider_calls)

    def test_exact_activation_does_not_authorize_message_send(self):
        activation_envelope = signed_envelope(
            self.kernel,
            self.activate,
            self.verifier,
            now_ns=NOW,
        )
        activation = self.kernel.evaluate_with_approval(self.activate, activation_envelope)
        self.assertEqual("allow", activation.outcome)
        self.assertTrue(self._release_capability(activation.permit))

        message_decision = self.kernel.evaluate(self.send)
        self.assertEqual(("require_approval", None), (message_decision.outcome, message_decision.permit))
        self.assertEqual(0, self.provider_calls)

    def test_activation_retarget_is_denied(self):
        activation_envelope = signed_envelope(
            self.kernel,
            self.activate,
            self.verifier,
            now_ns=NOW,
        )
        activation = self.kernel.evaluate_with_approval(self.activate, activation_envelope)
        self.assertEqual("allow", activation.outcome)
        substituted = Intent(
            PRINCIPAL,
            "activate_capability",
            f"{BOT}:telegram:chat:private:999999:capability:sendMessage",
            0,
            SESSION,
        )
        self.assertFalse(self._release_capability(activation.permit, substituted))
        self.assertFalse(self.capability_released)
        self.assertEqual(0, self.provider_calls)

    def test_exact_activation_and_exact_message_authorization_allow_one_dispatch(self):
        activation_envelope = signed_envelope(
            self.kernel,
            self.activate,
            self.verifier,
            now_ns=NOW,
        )
        activation = self.kernel.evaluate_with_approval(self.activate, activation_envelope)
        self.assertTrue(self._release_capability(activation.permit))
        self.assertFalse(self._release_capability(activation.permit))

        message_envelope = signed_envelope(
            self.kernel,
            self.send,
            self.verifier,
            now_ns=NOW,
        )
        message = self.kernel.evaluate_with_approval(self.send, message_envelope)
        self.assertEqual("allow", message.outcome)
        self.assertTrue(self._dispatch(message.permit))
        self.assertFalse(self._dispatch(message.permit))
        self.assertEqual(1, self.provider_calls)

    def test_message_authorization_cannot_be_retargeted(self):
        activation_envelope = signed_envelope(
            self.kernel,
            self.activate,
            self.verifier,
            now_ns=NOW,
        )
        activation = self.kernel.evaluate_with_approval(self.activate, activation_envelope)
        self.assertTrue(self._release_capability(activation.permit))

        message_envelope = signed_envelope(
            self.kernel,
            self.send,
            self.verifier,
            now_ns=NOW,
        )
        message = self.kernel.evaluate_with_approval(self.send, message_envelope)
        substituted = Intent(
            PRINCIPAL,
            "telegram_send_message",
            f"{BOT}:{CHAT}:sha256:{hashlib.sha256(b'other text').hexdigest()}",
            0,
            SESSION,
        )
        self.assertFalse(self._dispatch(message.permit, substituted))
        self.assertEqual(0, self.provider_calls)


if __name__ == "__main__":
    unittest.main()

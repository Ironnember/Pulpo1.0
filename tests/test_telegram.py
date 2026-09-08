import unittest

from pulpo import AgentGrant, GovernanceKernel, Policy
from pulpo.telegram import (
    GovernedTelegramSender,
    TELEGRAM_SEND_ACTION,
    TelegramOutboundMessage,
    TelegramSendRejected,
)


class RecordingTelegramTransport:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[TelegramOutboundMessage] = []
        self.fail = fail

    def send_message(self, message: TelegramOutboundMessage) -> dict[str, object]:
        self.calls.append(message)
        if self.fail:
            raise RuntimeError("simulated telegram transport failure")
        return {
            "ok": True,
            "chat_id": message.chat_id,
            "message_hash": message.message_hash,
        }


class GovernedTelegramTests(unittest.TestCase):
    def setUp(self) -> None:
        self.transport = RecordingTelegramTransport()
        grant = AgentGrant(
            principal="agent:telegram",
            allowed_actions=frozenset({TELEGRAM_SEND_ACTION}),
            resource_prefixes=("telegram:sendMessage:",),
            max_cost=0,
        )
        self.kernel = GovernanceKernel(
            Policy(
                allowed_actions=frozenset({TELEGRAM_SEND_ACTION}),
                max_cost=0,
                agent_grants=(grant,),
            ),
            secret=b"telegram-proof-secret",
        )
        self.sender = GovernedTelegramSender(self.kernel, self.transport)

    def test_exact_message_projection_changes_on_chat_or_text_substitution(self) -> None:
        original = TelegramOutboundMessage(123, "hello")
        changed_text = TelegramOutboundMessage(123, "hello!")
        changed_chat = TelegramOutboundMessage(456, "hello")

        self.assertNotEqual(original.message_hash, changed_text.message_hash)
        self.assertNotEqual(original.resource, changed_text.resource)
        self.assertNotEqual(original.resource, changed_chat.resource)

    def test_exact_permit_releases_one_transport_call_only(self) -> None:
        message = TelegramOutboundMessage(123, "governed hello")
        decision = self.sender.evaluate(message, principal="agent:telegram", session_id="session:1")

        self.assertEqual("allow", decision.outcome)
        self.assertIsNotNone(decision.permit)
        result = self.sender.execute(
            message,
            permit=decision.permit,
            principal="agent:telegram",
            session_id="session:1",
        )
        self.assertTrue(result["ok"])
        self.assertEqual([message], self.transport.calls)

        with self.assertRaisesRegex(TelegramSendRejected, "permit rejected"):
            self.sender.execute(
                message,
                permit=decision.permit,
                principal="agent:telegram",
                session_id="session:1",
            )
        self.assertEqual([message], self.transport.calls)

    def test_text_substitution_cannot_use_exact_permit_or_consume_valid_object(self) -> None:
        original = TelegramOutboundMessage(123, "approved text")
        substituted = TelegramOutboundMessage(123, "different text")
        decision = self.sender.evaluate(original, principal="agent:telegram", session_id="session:2")
        self.assertEqual("allow", decision.outcome)

        with self.assertRaisesRegex(TelegramSendRejected, "permit rejected"):
            self.sender.execute(
                substituted,
                permit=decision.permit,
                principal="agent:telegram",
                session_id="session:2",
            )
        self.assertEqual([], self.transport.calls)

        self.sender.execute(
            original,
            permit=decision.permit,
            principal="agent:telegram",
            session_id="session:2",
        )
        self.assertEqual([original], self.transport.calls)

    def test_chat_substitution_cannot_use_exact_permit(self) -> None:
        original = TelegramOutboundMessage(123, "approved text")
        substituted = TelegramOutboundMessage(456, "approved text")
        decision = self.sender.evaluate(original, principal="agent:telegram", session_id="session:3")

        with self.assertRaises(TelegramSendRejected):
            self.sender.execute(
                substituted,
                permit=decision.permit,
                principal="agent:telegram",
                session_id="session:3",
            )
        self.assertEqual([], self.transport.calls)

    def test_principal_or_session_substitution_cannot_use_permit(self) -> None:
        message = TelegramOutboundMessage(123, "approved text")
        decision = self.sender.evaluate(message, principal="agent:telegram", session_id="session:4")

        with self.assertRaises(TelegramSendRejected):
            self.sender.execute(
                message,
                permit=decision.permit,
                principal="agent:other",
                session_id="session:4",
            )
        with self.assertRaises(TelegramSendRejected):
            self.sender.execute(
                message,
                permit=decision.permit,
                principal="agent:telegram",
                session_id="session:other",
            )
        self.assertEqual([], self.transport.calls)

    def test_unknown_principal_is_denied_before_transport(self) -> None:
        message = TelegramOutboundMessage(123, "hello")
        decision = self.sender.evaluate(message, principal="agent:unknown", session_id="session:5")
        self.assertEqual(("deny", "unknown_principal"), (decision.outcome, decision.reason))
        self.assertIsNone(decision.permit)
        self.assertEqual([], self.transport.calls)

    def test_missing_permit_never_calls_transport(self) -> None:
        message = TelegramOutboundMessage(123, "hello")
        with self.assertRaisesRegex(TelegramSendRejected, "permit missing"):
            self.sender.execute(
                message,
                permit="",
                principal="agent:telegram",
                session_id="session:6",
            )
        self.assertEqual([], self.transport.calls)

    def test_invalid_message_is_rejected_before_governance_or_transport(self) -> None:
        with self.assertRaises(ValueError):
            TelegramOutboundMessage(123, "")
        with self.assertRaises(ValueError):
            TelegramOutboundMessage(123, "x" * 4097)
        with self.assertRaises(ValueError):
            TelegramOutboundMessage(True, "hello")
        self.assertEqual([], self.transport.calls)

    def test_transport_failure_does_not_restore_spent_permit(self) -> None:
        transport = RecordingTelegramTransport(fail=True)
        sender = GovernedTelegramSender(self.kernel, transport)
        message = TelegramOutboundMessage(123, "one attempt only")
        decision = sender.evaluate(message, principal="agent:telegram", session_id="session:7")

        with self.assertRaisesRegex(RuntimeError, "simulated telegram transport failure"):
            sender.execute(
                message,
                permit=decision.permit,
                principal="agent:telegram",
                session_id="session:7",
            )
        self.assertEqual([message], transport.calls)

        with self.assertRaises(TelegramSendRejected):
            sender.execute(
                message,
                permit=decision.permit,
                principal="agent:telegram",
                session_id="session:7",
            )
        self.assertEqual([message], transport.calls)


if __name__ == "__main__":
    unittest.main()

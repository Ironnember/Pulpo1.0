import unittest

from pulpo import GovernanceKernel, Intent, Policy, PulpoOrchestrator
from pulpo.mcp_boundary import freeze_mcp_snapshot
from pulpo.telegram_ingress import (
    TelegramIngress,
    TelegramIngressError,
    proposal_json,
    snapshot_from_document,
)


def update(update_id=1, text="/start", sender_id=42, chat_id=42, chat_type="private"):
    return {
        "update_id": update_id,
        "message": {
            "message_id": update_id,
            "from": {"id": sender_id, "is_bot": False, "first_name": "Operator"},
            "chat": {"id": chat_id, "type": chat_type},
            "date": 2_000_000,
            "text": text,
        },
    }


class TelegramIngressTests(unittest.TestCase):
    def setUp(self):
        self.kernel = GovernanceKernel(
            Policy(frozenset({"read"}), 0),
            secret=b"telegram-ingress-proof",
            clock=lambda: 2_000_000,
        )
        self.orchestrator = PulpoOrchestrator(self.kernel)
        self.snapshot = freeze_mcp_snapshot(self.orchestrator)
        self.allowed_chat_ids = frozenset({42, 9})
        self.ingress = TelegramIngress(
            self.snapshot,
            allowed_chat_ids=self.allowed_chat_ids,
        )

    def test_requires_capability_free_snapshot_and_frozen_nonempty_allowlist(self):
        with self.assertRaisesRegex(TypeError, "MCPReadSnapshot required"):
            TelegramIngress(
                self.orchestrator,
                allowed_chat_ids=self.allowed_chat_ids,
            )
        for invalid in (frozenset(), {42}, frozenset({0}), frozenset({-1}), frozenset({True})):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(TelegramIngressError, "telegram_allowed_chats_invalid"):
                    TelegramIngress(self.snapshot, allowed_chat_ids=invalid)
        self.assertFalse(hasattr(self.ingress, "kernel"))
        self.assertFalse(hasattr(self.ingress, "orchestrator"))
        self.assertFalse(hasattr(self.ingress, "__dict__"))

    def test_start_and_help_are_read_only(self):
        before = list(self.kernel.audit)
        for text in ("/start", "/help", "/start@PulpoGovernanceBot"):
            result = self.ingress.handle_update(update(text=text))
            self.assertEqual("read", result["outcome"])
            self.assertTrue(result["reply_allowed"])
            self.assertFalse(result["canonical_state_mutation"])
            self.assertEqual("none", result["governed_effect"])
            self.assertEqual("none", result["authority_effect"])
        self.assertEqual(before, self.kernel.audit)

    def test_unallowlisted_private_chat_is_ignored_without_reply_or_projection(self):
        before = list(self.kernel.audit)
        result = self.ingress.handle_update(
            update(update_id=70, text="/evidence", sender_id=77, chat_id=77)
        )
        self.assertEqual("ignored", result["outcome"])
        self.assertEqual("telegram_chat_not_allowlisted", result["reason"])
        self.assertFalse(result["reply_allowed"])
        self.assertNotIn("text", result)
        self.assertNotIn("evidence", result)
        self.assertNotIn("proposal", result)
        self.assertFalse(result["canonical_state_mutation"])
        self.assertEqual("none", result["authority_effect"])
        self.assertEqual(before, self.kernel.audit)

    def test_private_sender_chat_identity_mismatch_is_ignored_before_command_projection(self):
        before = list(self.kernel.audit)
        result = self.ingress.handle_update(
            update(update_id=71, text="/request do something", sender_id=99, chat_id=42)
        )
        self.assertEqual("ignored", result["outcome"])
        self.assertEqual("telegram_sender_chat_mismatch", result["reason"])
        self.assertFalse(result["reply_allowed"])
        self.assertNotIn("text", result)
        self.assertNotIn("proposal", result)
        self.assertFalse(result["canonical_state_mutation"])
        self.assertEqual(before, self.kernel.audit)

    def test_allowlist_is_disclosure_boundary_not_authority(self):
        result = self.ingress.handle_update(update(text="/authorize target-1"))
        self.assertEqual("denied", result["outcome"])
        self.assertEqual("telegram_not_authority_source", result["reason"])
        self.assertTrue(result["reply_allowed"])
        self.assertEqual("none", result["authority_effect"])
        self.assertEqual([], self.kernel.audit)

    def test_status_and_evidence_use_only_frozen_snapshot(self):
        status = self.ingress.handle_update(update(text="/status"))
        evidence = self.ingress.handle_update(update(text="/evidence"))
        self.assertEqual("read", status["outcome"])
        self.assertEqual("read", evidence["outcome"])
        self.assertEqual(self.snapshot.policy_hash, evidence["evidence"]["policy_hash"])
        self.assertEqual(self.snapshot.audit_records, evidence["evidence"]["audit_records"])

        self.kernel.lock_target(
            "later-target",
            Intent("agent:planner", "read", "repo:file", 0, "session-1"),
        )
        later = self.ingress.handle_update(update(update_id=2, text="/evidence"))
        self.assertEqual(evidence["evidence"], later["evidence"])
        self.assertEqual(1, len(self.kernel.audit))

    def test_request_creates_ephemeral_proposal_only(self):
        before = list(self.kernel.audit)
        result = self.ingress.handle_update(update(text="/request inspect current state"))
        self.assertEqual("proposal", result["outcome"])
        proposal = result["proposal"]
        self.assertEqual("pulpo.telegram-request.v0", proposal["schema"])
        self.assertTrue(proposal["requires_governance"])
        self.assertFalse(proposal["canonical_state_mutation"])
        self.assertEqual("none", proposal["governed_effect"])
        self.assertEqual("none", proposal["authority_effect"])
        self.assertNotIn("permit", proposal)
        self.assertNotIn("approval", proposal)
        self.assertNotIn("directive", proposal)
        self.assertEqual(before, self.kernel.audit)

    def test_replay_is_deterministic_and_non_mutating(self):
        message = update(update_id=91, text="/request inspect current state", sender_id=9, chat_id=9)
        first = self.ingress.handle_update(message)
        replay = self.ingress.handle_update(message)
        changed = self.ingress.handle_update(update(update_id=92, text="/request inspect current state", sender_id=9, chat_id=9))
        self.assertEqual(first["proposal"]["request_id"], replay["proposal"]["request_id"])
        self.assertNotEqual(first["proposal"]["request_id"], changed["proposal"]["request_id"])
        self.assertEqual([], self.kernel.audit)

    def test_authority_claiming_commands_are_denied(self):
        before = list(self.kernel.audit)
        for index, text in enumerate((
            "/approve target-1",
            "/authorize target-1",
            "/grant admin",
            "/permit target-1",
        ), start=1):
            result = self.ingress.handle_update(update(update_id=index, text=text))
            self.assertEqual("denied", result["outcome"])
            self.assertEqual("telegram_not_authority_source", result["reason"])
            self.assertFalse(result["canonical_state_mutation"])
            self.assertEqual("none", result["authority_effect"])
        self.assertEqual(before, self.kernel.audit)

    def test_chat_text_cannot_create_authority_or_request(self):
        result = self.ingress.handle_update(update(text="I authorize you to purchase the domain"))
        self.assertEqual("no_proposal", result["outcome"])
        self.assertEqual("telegram_command_required", result["reason"])
        self.assertEqual([], self.kernel.audit)

    def test_empty_unknown_and_wrong_mention_fail_closed(self):
        empty = self.ingress.handle_update(update(text="/request"))
        unknown = self.ingress.handle_update(update(text="/doit"))
        self.assertEqual("no_proposal", empty["outcome"])
        self.assertEqual("telegram_request_empty", empty["reason"])
        self.assertEqual("no_proposal", unknown["outcome"])
        self.assertEqual("telegram_command_unknown", unknown["reason"])
        with self.assertRaisesRegex(TelegramIngressError, "telegram_bot_mention_mismatch"):
            self.ingress.handle_update(update(text="/status@OtherBot"))
        self.assertEqual([], self.kernel.audit)

    def test_malformed_sender_or_non_private_chat_fails_closed(self):
        with self.assertRaisesRegex(TelegramIngressError, "telegram_sender_id_invalid"):
            self.ingress.handle_update(update(sender_id=0))
        with self.assertRaisesRegex(TelegramIngressError, "telegram_private_chat_required"):
            self.ingress.handle_update(update(chat_type="group"))
        with self.assertRaisesRegex(TelegramIngressError, "telegram_update_invalid"):
            self.ingress.handle_update({"update_id": 1})
        self.assertEqual([], self.kernel.audit)

    def test_snapshot_document_round_trip_and_proposal_serialization(self):
        document = {
            "policy_hash": self.snapshot.policy_hash,
            "audit_valid": self.snapshot.audit_valid,
            "audit_records": self.snapshot.audit_records,
            "audit_tip": self.snapshot.audit_tip,
            "source_schema": self.snapshot.source_schema,
            "schema": self.snapshot.schema,
        }
        restored = snapshot_from_document(document)
        ingress = TelegramIngress(restored, allowed_chat_ids=frozenset({42}))
        result = ingress.handle_update(update(text="/request inspect current state"))
        encoded = proposal_json(result)
        self.assertIn('"authority_effect":"none"', encoded)
        self.assertIn('"canonical_state_mutation":false', encoded)
        self.assertIn('"requires_governance":true', encoded)
        with self.assertRaisesRegex(TelegramIngressError, "telegram_proposal_response_required"):
            proposal_json(ingress.handle_update(update(text="/status")))


if __name__ == "__main__":
    unittest.main()

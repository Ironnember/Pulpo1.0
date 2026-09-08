import unittest

from pulpo.ops_bot import (
    OpsBot,
    PaymentRecord,
    lead_procurement_proposal,
    reconcile_payments,
    schedule_proposal,
)


class OpsBotTests(unittest.TestCase):
    def test_reconciliation_matches_exact_reference_amount_currency(self):
        ledger = [PaymentRecord("inv-1", 12500, "usd")]
        processor = [PaymentRecord("inv-1", 12500, "USD")]
        report = reconcile_payments(ledger, processor)
        self.assertEqual(report.matched, 1)
        self.assertEqual(report.exceptions, 0)
        self.assertEqual(report.findings[0].status, "matched")

    def test_reconciliation_does_not_guess_amount_drift(self):
        ledger = [PaymentRecord("inv-1", 12500, "USD")]
        processor = [PaymentRecord("inv-1", 12499, "USD")]
        report = reconcile_payments(ledger, processor)
        self.assertEqual(report.findings[0].status, "amount_mismatch")

    def test_duplicate_reference_is_exception(self):
        ledger = [PaymentRecord("inv-1", 100, "USD"), PaymentRecord("inv-1", 100, "USD")]
        processor = [PaymentRecord("inv-1", 100, "USD")]
        report = reconcile_payments(ledger, processor)
        self.assertEqual(report.findings[0].status, "duplicate_reference")

    def test_schedule_is_proposal_only_and_zero_cost(self):
        proposal = schedule_proposal(
            principal="agent:ops",
            session_id="s1",
            starts_at="2026-09-10T14:00:00-07:00",
            duration_minutes=30,
            title="CIO discovery",
            attendees=["buyer@example.com"],
        )
        self.assertEqual(proposal.action, "calendar.schedule")
        self.assertEqual(proposal.cost, 0)
        self.assertEqual(proposal.execution_effect, "none")
        self.assertEqual(proposal.payload["mode"], "proposal_only")

    def test_lead_procurement_forbids_purchase_and_outreach(self):
        proposal = lead_procurement_proposal(
            principal="agent:ops",
            session_id="s1",
            company_profile="US companies deploying autonomous agents",
            buyer_role="CIO",
            geography="United States",
            limit=10,
        )
        self.assertEqual(proposal.execution_effect, "none")
        self.assertEqual(proposal.payload["outreach"], "prohibited")
        self.assertEqual(proposal.payload["purchase"], "prohibited")

    def test_bot_reconcile_command(self):
        reply = OpsBot().handle_message(
            '/reconcile {"ledger":[{"reference":"x","amount":"10.00","currency":"USD"}],"processor":[{"reference":"x","amount":"10.00","currency":"USD"}]}',
            session_id="telegram:1",
        )
        self.assertIn("1 matched, 0 exceptions", reply.text)
        self.assertIsNotNone(reply.reconciliation)

    def test_minor_units_are_not_reinterpreted_as_dollars(self):
        reply = OpsBot().handle_message(
            '/reconcile {"ledger":[{"reference":"x","amount_minor":"1000","currency":"USD"}],"processor":[{"reference":"x","amount_minor":1000,"currency":"USD"}]}',
            session_id="telegram:1",
        )
        self.assertIn("1 matched, 0 exceptions", reply.text)

    def test_schedule_requires_timezone(self):
        with self.assertRaises(ValueError):
            schedule_proposal(
                principal="agent:ops",
                session_id="s1",
                starts_at="2026-09-10T14:00:00",
                duration_minutes=30,
                title="Discovery",
            )

    def test_bot_rejects_unknown_command(self):
        with self.assertRaises(ValueError):
            OpsBot().handle_message("/pay vendor 1000", session_id="telegram:1")

    def test_proposal_hash_is_deterministic(self):
        one = schedule_proposal(
            principal="agent:ops",
            session_id="s1",
            starts_at="2026-09-10T14:00:00-07:00",
            duration_minutes=30,
            title="Discovery",
            attendees=["b@example.com", "a@example.com"],
        )
        two = schedule_proposal(
            principal="agent:ops",
            session_id="s1",
            starts_at="2026-09-10T14:00:00-07:00",
            duration_minutes=30,
            title="Discovery",
            attendees=["a@example.com", "b@example.com"],
        )
        self.assertEqual(one.proposal_hash, two.proposal_hash)


if __name__ == "__main__":
    unittest.main()

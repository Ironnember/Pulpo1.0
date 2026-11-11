"""Incident-reporting + near-miss channel (WIC Frontier Governance 3.2).

The audit found incident reporting does not exist in Pulpo as a mechanism --
only the UNKNOWN/mismatch substrate. These tests pin the derived, read-only
channel in pulpo/incident_channel.py: each feed maps to the right kind and
resolution, a real uncertain purchase produces an incident with correct
anchors, refusals produce near-misses, custody attempts resolve or confirm
earlier unknowns (one merged record, never two), freeze + export round-trip,
query filters, and the read-only proof.
"""
import hashlib
import tempfile
import unittest
from pathlib import Path

from pulpo import GovernanceKernel, Intent, Policy, PulpoOrchestrator, SQLiteKernelState
from pulpo.commerce import (
    BudgetAccount,
    CommerceViolation,
    DomainCommerceExecutor,
    DomainPurchaseRequest,
    DomainQuote,
    RegistrarResult,
    SQLiteBudgetAccount,
    assess_quote,
    purchase_intent,
)
from pulpo.custody import CustodyViolation, SQLiteGovernanceCustody
from pulpo.custody_domain import GovernedDomainAttemptCoordinator
from pulpo.directives import (
    Directive,
    DirectiveAuthorityController,
    GovernedDirectiveProjection,
)
from pulpo.incident_channel import (
    IncidentRecord,
    IncidentReport,
    export_incident_report,
    freeze_incident_report,
    list_incidents,
    load_incident_report,
)
from pulpo.mcp_boundary import MCPBoundaryError
from tests.authority_support import (
    HmacTestVerifier,
    signed_envelope,
    trust_for,
)

NOW = 8_000_000
OPERATOR = "operator:owner"


class FakeRegistrar:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def purchase(self, order, *, max_charge_cents):
        self.calls += 1
        return self.result


class UncertainRegistrar:
    def __init__(self):
        self.calls = 0

    def purchase(self, order, *, max_charge_cents):
        del order, max_charge_cents
        self.calls += 1
        raise ConnectionError("provider result is unknown")


class HookedBudget:
    """BudgetState delegate that runs a hook inside mark_attempted."""

    def __init__(self, wrapped, hook):
        self._wrapped = wrapped
        self._hook = hook

    def require_active(self, reservation_id, order, *, now_ns):
        return self._wrapped.require_active(reservation_id, order, now_ns=now_ns)

    def mark_attempted(self, reservation_id):
        self._hook()
        return self._wrapped.mark_attempted(reservation_id)

    def reconcile(self, reservation_id, payment):
        return self._wrapped.reconcile(reservation_id, payment)

    def __getattr__(self, name):
        return getattr(self._wrapped, name)


def audit_events(kernel, event):
    return [record for record in kernel.audit if record.get("event") == event]


class IncidentRecordValidationTests(unittest.TestCase):
    def valid_kwargs(self):
        return {
            "record_id": "incident:" + "a" * 64,
            "kind": "incident",
            "source": "canonical_audit",
            "source_detail": "purchase_consequence_unknown",
            "first_seen_ns": 100,
            "last_seen_ns": 100,
            "anchors": (("audit_record", "a" * 64),),
            "reason": "external_consequence_not_yet_verified",
            "resolution": "unresolved",
            "anchor_hash": "a" * 64,
        }

    def test_valid_record(self):
        record = IncidentRecord(**self.valid_kwargs())
        self.assertEqual("incident", record.kind)

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            IncidentRecord(**{**self.valid_kwargs(), "kind": "maybe"})

    def test_bad_source_rejected(self):
        with self.assertRaises(ValueError):
            IncidentRecord(**{**self.valid_kwargs(), "source": "rumour"})

    def test_bad_resolution_rejected(self):
        with self.assertRaises(ValueError):
            IncidentRecord(**{**self.valid_kwargs(), "resolution": "ignored"})

    def test_non_hash_anchor_rejected(self):
        with self.assertRaises(ValueError):
            IncidentRecord(**{**self.valid_kwargs(), "anchor_hash": "not-a-hash"})

    def test_anchor_hash_must_appear_in_anchors(self):
        with self.assertRaises(ValueError):
            IncidentRecord(**{**self.valid_kwargs(), "anchor_hash": "b" * 64})

    def test_record_id_must_match_kind(self):
        with self.assertRaises(ValueError):
            IncidentRecord(**{**self.valid_kwargs(), "record_id": "near-miss:" + "a" * 64})
        with self.assertRaises(ValueError):
            IncidentRecord(**{**self.valid_kwargs(), "kind": "near_miss",
                              "record_id": "incident:" + "a" * 64})

    def test_last_seen_before_first_seen_rejected(self):
        with self.assertRaises(ValueError):
            IncidentRecord(**{**self.valid_kwargs(), "first_seen_ns": 200, "last_seen_ns": 100})

    def test_report_counts_must_match_records(self):
        record = IncidentRecord(**self.valid_kwargs())
        with self.assertRaises(ValueError):
            IncidentReport("c" * 32, 200, True, 1, 0, 0, 0, 0, 0, (record,))
        report = IncidentReport("c" * 32, 200, True, 1, 1, 0, 1, 0, 0, (record,))
        self.assertEqual(1, report.incidents)

    def test_report_records_must_be_sorted(self):
        first = IncidentRecord(**{**self.valid_kwargs(), "first_seen_ns": 300,
                                  "last_seen_ns": 300})
        second = IncidentRecord(**{**self.valid_kwargs(), "record_id": "incident:" + "b" * 64,
                                   "first_seen_ns": 100, "last_seen_ns": 100,
                                   "anchors": (("audit_record", "b" * 64),), "anchor_hash": "b" * 64})
        with self.assertRaises(ValueError):
            IncidentReport("c" * 32, 400, True, 2, 2, 0, 2, 0, 0, (first, second))


class IncidentChannelAuditFeedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "state.sqlite"
        self.backend = SQLiteKernelState(self.db)
        self.addCleanup(self.backend.close)
        self.kernel = GovernanceKernel(Policy(frozenset({"read"}), 0), secret=b"test-only", state=self.backend)
        self.owner = PulpoOrchestrator(self.kernel)

    def test_unknown_audit_event_is_an_unresolved_incident(self):
        self.backend.append("purchase_consequence_unknown",
                            {"order_hash": "a" * 64, "intent_hash": "b" * 64,
                             "permit_hash": "c" * 64, "reservation_id": "res-1",
                             "reason": "external_consequence_not_yet_verified"}, 100)
        report = freeze_incident_report(self.owner)
        self.assertEqual(1, report.incidents)
        self.assertEqual(0, report.near_misses)
        self.assertEqual(1, report.unresolved)
        (record,) = report.records
        self.assertEqual("incident", record.kind)
        self.assertEqual("canonical_audit", record.source)
        self.assertEqual("purchase_consequence_unknown", record.source_detail)
        self.assertEqual(100, record.first_seen_ns)
        self.assertEqual(100, record.last_seen_ns)
        self.assertEqual("unresolved", record.resolution)
        self.assertEqual("external_consequence_not_yet_verified", record.reason)
        self.assertTrue(record.record_id.startswith("incident:"))
        self.assertEqual(self.kernel.audit[-1]["hash"], record.anchor_hash)
        self.assertIn(("order_hash", "a" * 64), record.anchors)
        self.assertIn(("intent_hash", "b" * 64), record.anchors)
        self.assertIn(("permit_hash", "c" * 64), record.anchors)
        # Hashes only: the reservation id is not an anchor hash.
        self.assertNotIn("res-1", [name for name, _ in record.anchors])
        self.assertTrue(report.audit_valid)

    def test_refusal_audit_events_are_near_misses(self):
        self.backend.append("purchase_revalidation_failed",
                            {"order_hash": "a" * 64, "reason": "directive_revoked"}, 100)
        self.backend.append("permit_rejected", {"intent_hash": "b" * 64,
                                                "reason": "permit_clock_invalid"}, 200)
        self.backend.append("approval_rejected", {"reason": "approval_expired"}, 300)
        self.backend.append("decision", {"outcome": "deny", "reason": "action_not_allowed",
                                         "intent_hash": "c" * 64}, 400)
        report = freeze_incident_report(self.owner)
        self.assertEqual(0, report.incidents)
        self.assertEqual(4, report.near_misses)
        self.assertEqual(
            ["purchase_revalidation_failed", "permit_rejected", "approval_rejected", "decision"],
            [record.source_detail for record in report.records])
        for record in report.records:
            self.assertEqual("near_miss", record.kind)
            self.assertEqual("not_applicable", record.resolution)
            self.assertTrue(record.record_id.startswith("near-miss:"))
        self.assertEqual("directive_revoked", report.records[0].reason)
        self.assertEqual("permit_clock_invalid", report.records[1].reason)
        self.assertEqual("action_not_allowed", report.records[3].reason)

    def test_allowed_decision_and_other_events_emit_no_record(self):
        self.backend.append("decision", {"outcome": "allow", "reason": "ok",
                                         "intent_hash": "a" * 64}, 100)
        self.backend.append("decision", {"outcome": "require_approval", "reason": "needs_human",
                                         "intent_hash": "b" * 64}, 200)
        self.backend.append("permit_consumed", {"intent_hash": "c" * 64}, 300)
        self.backend.append("directive_activated", {"directive_id": "d-1"}, 400)
        report = freeze_incident_report(self.owner)
        self.assertEqual((), report.records)
        self.assertEqual(0, report.incidents)
        self.assertEqual(0, report.near_misses)

    def test_records_sort_by_first_seen_not_audit_order(self):
        self.backend.append("purchase_consequence_unknown",
                            {"reason": "external_consequence_not_yet_verified"}, 300)
        self.backend.append("permit_rejected", {"reason": "permit_clock_invalid"}, 100)
        report = freeze_incident_report(self.owner)
        self.assertEqual([100, 300], [record.first_seen_ns for record in report.records])
        self.assertEqual(["near_miss", "incident"], [record.kind for record in report.records])

    def test_freeze_is_read_only(self):
        self.backend.append("purchase_consequence_unknown",
                            {"reason": "external_consequence_not_yet_verified"}, 100)
        before = len(self.kernel.audit)
        self.assertTrue(self.kernel.verify_audit())
        freeze_incident_report(self.owner)
        freeze_incident_report(self.owner)
        self.assertEqual(before, len(self.kernel.audit))
        self.assertTrue(self.kernel.verify_audit())

    def test_invalid_inputs_raise(self):
        with self.assertRaises(TypeError):
            freeze_incident_report(self.kernel)
        with self.assertRaises(TypeError):
            freeze_incident_report(self.owner, custody="not-a-store")
        with self.assertRaises(TypeError):
            list_incidents(self.kernel)


class LivePurchaseIncidentTests(unittest.TestCase):
    def order(self, domain="pulpo-incident.example", *, price=2_000):
        request = DomainPurchaseRequest(
            request_id=f"request-incident:{domain}",
            principal="agent:commerce",
            acceptable_domains=(domain,),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 100_000,
        )
        quote = DomainQuote(
            quote_id=f"quote:{domain}",
            domain=domain,
            registrar="name.com",
            purchase_price_cents=price,
            renewal_price_cents=2_400,
            owner_ref="owner://iron-ember",
            privacy_enabled=True,
            upsells=(),
            expires_at_ns=NOW + 50_000,
        )
        assessment = assess_quote(request, quote, credential_ref="credential://name-com/incident",
                                  now_ns=NOW)
        self.assertIsNotNone(assessment.order)
        return assessment.order

    def kernel_with(self, order, *, state=None):
        kernel = GovernanceKernel(
            Policy(frozenset({"purchase_domain"}), 3_000),
            secret=b"test-only",
            clock=lambda: NOW,
            state=state,
        )
        permit = kernel.evaluate(purchase_intent(order)).permit
        self.assertIsNotNone(permit)
        return kernel, permit

    # EXCLUDED FROM THE CANONICAL PORT -- Option A (Austin, 2026-11-11).
    # This test asserts that an uncertain live purchase emits a
    # `purchase_consequence_unknown` audit event and that the channel
    # anchors an incident record to it. That event is emitted by
    # Preview's live commerce path (Preview PR #115 pre-purchase
    # revalidation, wired live in Preview PR #120); nothing on
    # canonical emits it today. The body is preserved verbatim below,
    # commented out, and returns with the #115/#120 ports.
#     def test_uncertain_live_purchase_produces_incident_with_correct_anchors(self):
#         order = self.order()
#         kernel, permit = self.kernel_with(order)
#         owner = PulpoOrchestrator(kernel)
#         budget = BudgetAccount()
#         reservation = budget.reserve(order, now_ns=NOW)
#         uncertain = UncertainRegistrar()
#         with self.assertRaisesRegex(ConnectionError, "unknown"):
#             DomainCommerceExecutor().execute(
#                 kernel, order, permit, uncertain, budget,
#                 reservation.reservation_id, now_ns=NOW,
#             )
#         report = freeze_incident_report(owner)
#         self.assertEqual(1, report.incidents)
#         self.assertEqual(1, report.unresolved)
#         (record,) = report.records
#         unknown = audit_events(kernel, "purchase_consequence_unknown")[0]
#         self.assertEqual("incident:" + unknown["hash"], record.record_id)
#         self.assertEqual(unknown["hash"], record.anchor_hash)
#         self.assertEqual(NOW, record.first_seen_ns)
#         self.assertEqual(order.order_hash, dict(record.anchors)["order_hash"])
#         self.assertEqual(kernel.intent_hash(purchase_intent(order)),
#                          dict(record.anchors)["intent_hash"])
#         self.assertEqual(hashlib.sha256(permit.encode()).hexdigest(),
#                          dict(record.anchors)["permit_hash"])
#         self.assertTrue(report.audit_valid)
#         self.assertEqual(len(kernel.audit), report.audit_records)

    def test_denied_decision_and_rejected_permit_are_near_misses(self):
        kernel = GovernanceKernel(Policy(frozenset({"read"}), 0), secret=b"test-only",
                                  clock=lambda: NOW)
        owner = PulpoOrchestrator(kernel)
        denied = kernel.evaluate(Intent("agent:test", "write", "fixture-private", 0))
        self.assertEqual("deny", denied.outcome)
        self.assertFalse(kernel.consume("bogus-permit",
                                        Intent("agent:test", "read", "fixture-private", 0)))
        report = freeze_incident_report(owner)
        self.assertEqual(0, report.incidents)
        self.assertEqual(2, report.near_misses)
        details = {record.source_detail: record for record in report.records}
        self.assertEqual("action_not_allowed", details["decision"].reason)
        self.assertEqual("not_applicable", details["permit_rejected"].resolution)

    # EXCLUDED FROM THE CANONICAL PORT -- Option A (Austin, 2026-11-11).
    # This test asserts that a directive revoked between consume and
    # purchase produces a `purchase_revalidation_failed` audit event
    # from pre-purchase revalidation. That revalidation -- and the
    # event -- belongs to Preview's live commerce path (Preview PR
    # #115, wired live in Preview PR #120); canonical has no
    # revalidation step and emits no such event today. The body is
    # preserved verbatim below, commented out, and returns with the
    # #115/#120 ports.
#     def test_revoked_directive_revalidation_failure_is_a_near_miss(self):
#         verifier = HmacTestVerifier()
#         policy = Policy(
#             frozenset({"purchase_domain", "activate_directive", "revoke_directive"}),
#             3_000,
#             frozenset({"activate_directive", "revoke_directive"}),
#             authority_trust=trust_for(verifier),
#         )
#         # Canonical adaptation (port of Preview PR #119): Preview's kernel
#         # takes a signed policy envelope at construction (Preview PR #117,
#         # a separate sequenced port); canonical's GovernanceKernel has no
#         # policy_envelope parameter, so the kernel is constructed without
#         # it. The scenario under test -- directive activation, revocation
#         # between consume and purchase, and the revalidation refusal the
#         # channel derives -- is unchanged.
#         kernel = GovernanceKernel(
#             policy,
#             secret=b"test-only",
#             approval_verifier=verifier,
#             clock=lambda: NOW,
#         )
#         owner = PulpoOrchestrator(kernel)
#         order = self.order()
#         intent = purchase_intent(order)
#         directive = Directive(
#             directive_id="directive-incident",
#             version=1,
#             issuer_authority_id=verifier.authority_id,
#             principal=intent.principal,
#             allowed_actions=frozenset({"purchase_domain"}),
#             resource_prefixes=("commerce:domain:",),
#             max_cost=3_000,
#             issued_at_ns=NOW - 1_000,
#             expires_at_ns=NOW + 100_000,
#         )
#         controller = DirectiveAuthorityController(kernel)
#         activation = signed_envelope(
#             kernel,
#             controller.authority_intent(controller.ACTIVATE, directive, operator_principal=OPERATOR),
#             verifier,
#             now_ns=NOW - 10,
#             approval_id="approval-incident-activate",
#             nonce="nonce-incident-activate",
#         )
#         self.assertEqual(
#             "allow",
#             controller.activate(directive, activation, operator_principal=OPERATOR).outcome,
#         )
#         decision = GovernedDirectiveProjection(kernel).evaluate(intent, directive)
#         self.assertEqual("allow", decision.outcome)
#
#         def revoke_between_consume_and_purchase():
#             revocation = signed_envelope(
#                 kernel,
#                 controller.authority_intent(controller.REVOKE, directive, operator_principal=OPERATOR),
#                 verifier,
#                 now_ns=NOW - 10,
#                 approval_id="approval-incident-revoke",
#                 nonce="nonce-incident-revoke",
#             )
#             self.assertEqual(
#                 "allow",
#                 controller.revoke(directive, revocation, operator_principal=OPERATOR).outcome,
#             )
#
#         budget = HookedBudget(BudgetAccount(), revoke_between_consume_and_purchase)
#         reservation = budget.reserve(order, now_ns=NOW)
#         registrar = FakeRegistrar(
#             RegistrarResult("payment-1", 2_000, "a" * 64, "registration-1", order.domain, order.registrar)
#         )
#         with self.assertRaisesRegex(CommerceViolation, "directive_revoked"):
#             DomainCommerceExecutor().execute(
#                 kernel, order, decision.permit, registrar, budget,
#                 reservation.reservation_id, now_ns=NOW,
#             )
#         self.assertEqual(0, registrar.calls)
#         report = freeze_incident_report(owner)
#         refusals = [record for record in report.records
#                     if record.source_detail == "purchase_revalidation_failed"]
#         self.assertEqual(1, len(refusals))
#         self.assertEqual("near_miss", refusals[0].kind)
#         self.assertEqual("directive_revoked", refusals[0].reason)
#         self.assertEqual("not_applicable", refusals[0].resolution)


class CustodyFeedTests(unittest.TestCase):
    def custody(self, directory):
        path = Path(directory) / "custody.sqlite3"
        store = SQLiteGovernanceCustody(path, signing_secret=b"test-only-custody-secret",
                                        clock=lambda: NOW)
        return store

    def head(self, store):
        snapshot = store.snapshot()
        return snapshot.epoch, snapshot.state_root

    def authorize(self, store, *, object_hash="a" * 64, target_hash="b" * 64,
                  permit_hash="c" * 64, authorization_hash="d" * 64):
        epoch, root = self.head(store)
        authorization = store.authorize_attempt(
            expected_epoch=epoch, expected_state_root=root,
            object_hash=object_hash, target_hash=target_hash,
            permit_hash=permit_hash, authorization_hash=authorization_hash,
        )
        return authorization.attempt_id

    def drive_to(self, store, attempt_id, *states):
        """Walk an attempt through claim/transmit/reconcile steps."""
        for state in states:
            epoch, root = self.head(store)
            if state == "attempt_claimed":
                store.claim_attempt(expected_epoch=epoch, expected_state_root=root,
                                    attempt_id=attempt_id, executor_id="executor:test")
            elif state == "request_transmitted":
                store.authorize_transmission(expected_epoch=epoch, expected_state_root=root,
                                             attempt_id=attempt_id)
            elif state == "reconciliation_required":
                store.require_reconciliation(expected_epoch=epoch, expected_state_root=root,
                                             attempt_id=attempt_id)
            elif state in ("reconciled_success", "reconciled_failure", "unresolved"):
                outcome = {"reconciled_success": "success",
                           "reconciled_failure": "failure",
                           "unresolved": "unresolved"}[state]
                store.reconcile_observed(expected_epoch=epoch, expected_state_root=root,
                                         attempt_id=attempt_id, outcome=outcome,
                                         observation_hash="e" * 64, observer_id="observer:test")
            else:  # pragma: no cover - test helper guard
                raise AssertionError(state)

    def owner_for(self, directory):
        db = Path(directory) / "state.sqlite"
        backend = SQLiteKernelState(db)
        self.addCleanup(backend.close)
        kernel = GovernanceKernel(Policy(frozenset({"read"}), 0), secret=b"test-only", state=backend)
        return PulpoOrchestrator(kernel)

    def test_attempts_lists_all_attempts_in_authorization_order(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.custody(directory)
            self.assertEqual((), store.attempts())
            first = self.authorize(store)
            second = self.authorize(store, object_hash="1" * 64)
            attempts = store.attempts()
            self.assertEqual([first, second], [attempt.attempt_id for attempt in attempts])
            self.assertEqual("attempt_authorized", attempts[0].state)

    def test_attempts_is_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.custody(directory)
            self.authorize(store)
            before = store.snapshot()
            store.attempts()
            self.assertEqual(before, store.snapshot())

    def test_stuck_attempt_states_are_unresolved_incidents(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.custody(directory)
            owner = self.owner_for(directory)
            cases = (
                ((), "attempt_authorized"),
                (("attempt_claimed",), "attempt_claimed"),
                (("attempt_claimed", "request_transmitted"), "request_transmitted"),
                (("attempt_claimed", "request_transmitted", "reconciliation_required"),
                 "reconciliation_required"),
                (("attempt_claimed", "request_transmitted", "unresolved"), "unresolved"),
            )
            for index, (steps, state) in enumerate(cases):
                attempt_id = self.authorize(store, object_hash=hashlib.sha256(
                    f"object-{index}".encode()).hexdigest())
                self.drive_to(store, attempt_id, *steps)
                report = freeze_incident_report(owner, custody=store)
                record = next(record for record in report.records
                              if record.record_id == f"incident:custody:{attempt_id}")
                self.assertEqual("incident", record.kind)
                self.assertEqual("custody_store", record.source)
                self.assertEqual(state, record.source_detail)
                self.assertEqual("unresolved", record.resolution)
                self.assertEqual(f"custody_attempt_{state}", record.reason)
                self.assertEqual(store.attempt(attempt_id).authorization_hash, record.anchor_hash)
                # The store records no per-attempt time: the record carries
                # the head's custody_time_ns, an upper bound, not a fake time.
                self.assertEqual(NOW, record.first_seen_ns)
                self.assertEqual(NOW, record.last_seen_ns)

    def test_reconciled_failure_is_confirmed_wrong(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.custody(directory)
            owner = self.owner_for(directory)
            attempt_id = self.authorize(store)
            self.drive_to(store, attempt_id, "attempt_claimed", "request_transmitted",
                          "reconciled_failure")
            (record,) = freeze_incident_report(owner, custody=store).records
            self.assertEqual("incident", record.kind)
            self.assertEqual("confirmed_wrong", record.resolution)

    def test_reconciled_success_emits_no_record_by_itself(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.custody(directory)
            owner = self.owner_for(directory)
            attempt_id = self.authorize(store)
            self.drive_to(store, attempt_id, "attempt_claimed", "request_transmitted",
                          "reconciled_success")
            self.assertEqual((), freeze_incident_report(owner, custody=store).records)

    def test_custody_feed_needs_the_store(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.custody(directory)
            owner = self.owner_for(directory)
            self.authorize(store)
            self.assertEqual((), freeze_incident_report(owner).records)
            self.assertEqual(1, len(freeze_incident_report(owner, custody=store).records))

    def test_freeze_does_not_write_to_the_custody_store(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.custody(directory)
            owner = self.owner_for(directory)
            self.authorize(store)
            before = store.snapshot()
            freeze_incident_report(owner, custody=store)
            self.assertEqual(before, store.snapshot())


class MergeTests(unittest.TestCase):
    def custody_stack(self, path):
        custody = SQLiteGovernanceCustody(
            path,
            signing_secret=b"test-only-custody-secret",
            clock=lambda: NOW,
        )
        budget = SQLiteBudgetAccount(path)
        state = SQLiteKernelState(path)
        kernel = GovernanceKernel(
            Policy(frozenset({"purchase_domain"}), 3_000),
            secret=b"test-only",
            clock=lambda: NOW,
            state=state,
        )
        coordinator = GovernedDomainAttemptCoordinator(kernel, custody, budget)
        self.addCleanup(state.close)
        return kernel, custody, budget, coordinator

    def order(self, domain="pulpo-merge.example"):
        request = DomainPurchaseRequest(
            request_id=f"request-merge:{domain}",
            principal="agent:commerce",
            acceptable_domains=(domain,),
            max_purchase_cents=3_000,
            max_renewal_cents=2_500,
            approved_registrar="name.com",
            owner_ref="owner://iron-ember",
            privacy_required=True,
            prohibited_upsells=("hosting",),
            expires_at_ns=NOW + 100_000,
        )
        quote = DomainQuote(
            quote_id=f"quote:{domain}",
            domain=domain,
            registrar="name.com",
            purchase_price_cents=2_000,
            renewal_price_cents=2_400,
            owner_ref="owner://iron-ember",
            privacy_enabled=True,
            upsells=(),
            expires_at_ns=NOW + 50_000,
        )
        assessment = assess_quote(request, quote, credential_ref="credential://name-com/merge",
                                  now_ns=NOW)
        self.assertIsNotNone(assessment.order)
        return assessment.order

    def uncertain_purchase(self, kernel, custody, budget, coordinator, order):
        intent = purchase_intent(order)
        target = kernel.lock_target("domain-merge", intent)
        decision = kernel.evaluate(intent)
        reservation = coordinator.reserve(order)
        uncertain = UncertainRegistrar()
        with self.assertRaisesRegex(ConnectionError, "unknown"):
            DomainCommerceExecutor(coordinator=coordinator).execute(
                kernel, order, decision.permit, uncertain, budget,
                reservation.reservation_id, now_ns=NOW,
                target_id=target.target_id, expected_target_hash=target.target_hash,
            )
        unknown = audit_events(kernel, "purchase_consequence_unknown")[0]
        return unknown["payload"]["custody_attempt_id"]

    def reconcile(self, custody, attempt_id, outcome):
        epoch, root = custody.snapshot().epoch, custody.snapshot().state_root
        custody.claim_attempt(expected_epoch=epoch, expected_state_root=root,
                              attempt_id=attempt_id, executor_id="executor:test")
        epoch, root = custody.snapshot().epoch, custody.snapshot().state_root
        custody.authorize_transmission(expected_epoch=epoch, expected_state_root=root,
                                       attempt_id=attempt_id)
        epoch, root = custody.snapshot().epoch, custody.snapshot().state_root
        custody.reconcile_observed(expected_epoch=epoch, expected_state_root=root,
                                   attempt_id=attempt_id, outcome=outcome,
                                   observation_hash="e" * 64, observer_id="observer:test")

    # EXCLUDED FROM THE CANONICAL PORT -- Option A (Austin, 2026-11-11).
    # This test drives `DomainCommerceExecutor(coordinator=...)` and
    # asserts merge derivation from a `purchase_consequence_unknown`
    # audit event. Canonical's executor takes no coordinator, and the
    # event is emitted only by Preview's live commerce path (Preview
    # PR #115 pre-purchase revalidation, wired live in Preview PR
    # #120); nothing on canonical emits it today. The body is preserved
    # verbatim below, commented out, and returns with the #115/#120
    # ports.
#     def test_unknown_plus_unresolved_attempt_is_one_audit_anchored_incident(self):
#         with tempfile.TemporaryDirectory() as directory:
#             path = Path(directory) / "custody.sqlite3"
#             kernel, custody, budget, coordinator = self.custody_stack(path)
#             owner = PulpoOrchestrator(kernel)
#             attempt_id = self.uncertain_purchase(kernel, custody, budget, coordinator,
#                                                  self.order())
#             self.assertEqual("attempt_authorized", custody.attempt(attempt_id).state)
#             report = freeze_incident_report(owner, custody=custody)
#             self.assertEqual(1, len(report.records))
#             (record,) = report.records
#             self.assertEqual("incident", record.kind)
#             self.assertEqual("canonical_audit", record.source)
#             self.assertEqual("unresolved", record.resolution)
#             self.assertEqual(custody.attempt(attempt_id).authorization_hash,
#                              dict(record.anchors)["custody_authorization"])

    # EXCLUDED FROM THE CANONICAL PORT -- Option A (Austin, 2026-11-11).
    # This test drives `DomainCommerceExecutor(coordinator=...)` and
    # asserts merge derivation from a `purchase_consequence_unknown`
    # audit event. Canonical's executor takes no coordinator, and the
    # event is emitted only by Preview's live commerce path (Preview
    # PR #115 pre-purchase revalidation, wired live in Preview PR
    # #120); nothing on canonical emits it today. The body is preserved
    # verbatim below, commented out, and returns with the #115/#120
    # ports.
#     def test_unknown_plus_later_success_is_one_near_miss_resolved_cleanly(self):
#         with tempfile.TemporaryDirectory() as directory:
#             path = Path(directory) / "custody.sqlite3"
#             kernel, custody, budget, coordinator = self.custody_stack(path)
#             owner = PulpoOrchestrator(kernel)
#             attempt_id = self.uncertain_purchase(kernel, custody, budget, coordinator,
#                                                  self.order())
#             self.reconcile(custody, attempt_id, "success")
#             report = freeze_incident_report(owner, custody=custody)
#             self.assertEqual(1, len(report.records))
#             (record,) = report.records
#             self.assertEqual("near_miss", record.kind)
#             self.assertEqual("resolved_cleanly", record.resolution)
#             self.assertEqual("canonical_audit", record.source)
#             self.assertTrue(record.record_id.startswith("near-miss:"))

    # EXCLUDED FROM THE CANONICAL PORT -- Option A (Austin, 2026-11-11).
    # This test drives `DomainCommerceExecutor(coordinator=...)` and
    # asserts merge derivation from a `purchase_consequence_unknown`
    # audit event. Canonical's executor takes no coordinator, and the
    # event is emitted only by Preview's live commerce path (Preview
    # PR #115 pre-purchase revalidation, wired live in Preview PR
    # #120); nothing on canonical emits it today. The body is preserved
    # verbatim below, commented out, and returns with the #115/#120
    # ports.
#     def test_unknown_plus_later_failure_is_one_incident_confirmed_wrong(self):
#         with tempfile.TemporaryDirectory() as directory:
#             path = Path(directory) / "custody.sqlite3"
#             kernel, custody, budget, coordinator = self.custody_stack(path)
#             owner = PulpoOrchestrator(kernel)
#             attempt_id = self.uncertain_purchase(kernel, custody, budget, coordinator,
#                                                  self.order())
#             self.reconcile(custody, attempt_id, "failure")
#             report = freeze_incident_report(owner, custody=custody)
#             self.assertEqual(1, len(report.records))
#             (record,) = report.records
#             self.assertEqual("incident", record.kind)
#             self.assertEqual("confirmed_wrong", record.resolution)

    # EXCLUDED FROM THE CANONICAL PORT -- Option A (Austin, 2026-11-11).
    # This test drives `DomainCommerceExecutor(coordinator=...)` and
    # asserts merge derivation from a `purchase_consequence_unknown`
    # audit event. Canonical's executor takes no coordinator, and the
    # event is emitted only by Preview's live commerce path (Preview
    # PR #115 pre-purchase revalidation, wired live in Preview PR
    # #120); nothing on canonical emits it today. The body is preserved
    # verbatim below, commented out, and returns with the #115/#120
    # ports.
#     def test_unknown_with_no_resolver_stays_incident(self):
#         with tempfile.TemporaryDirectory() as directory:
#             path = Path(directory) / "custody.sqlite3"
#             kernel, custody, budget, coordinator = self.custody_stack(path)
#             owner = PulpoOrchestrator(kernel)
#             self.uncertain_purchase(kernel, custody, budget, coordinator, self.order())
#             # Audit-only freeze: no custody store, so no resolver is visible.
#             (record,) = freeze_incident_report(owner).records
#             self.assertEqual("incident", record.kind)
#             self.assertEqual("unresolved", record.resolution)

    def test_unlinked_custody_attempt_and_refusal_are_separate_records(self):
        # The merge rule consumes an attempt only for a purchase_consequence_
        # unknown event carrying its id. A refusal leaves the attempt dangling
        # and the channel reports it as its own unresolved custody incident:
        # the live path never reconciles or cancels attempts today.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custody.sqlite3"
            kernel, custody, budget, coordinator = self.custody_stack(path)
            owner = PulpoOrchestrator(kernel)
            order = self.order()
            kernel.evaluate(purchase_intent(order))
            epoch, root = custody.snapshot().epoch, custody.snapshot().state_root
            authorization = custody.authorize_attempt(
                expected_epoch=epoch, expected_state_root=root,
                object_hash=order.order_hash, target_hash="b" * 64,
                permit_hash="c" * 64, authorization_hash="d" * 64,
            )
            kernel._state.append("purchase_revalidation_failed",
                                 {"order_hash": order.order_hash,
                                  "reason": "directive_revoked"}, NOW)
            report = freeze_incident_report(owner, custody=custody)
            self.assertEqual(2, len(report.records))
            by_source = {record.source: record for record in report.records}
            self.assertEqual("near_miss", by_source["canonical_audit"].kind)
            self.assertEqual("incident", by_source["custody_store"].kind)
            self.assertEqual(f"incident:custody:{authorization.attempt_id}",
                             by_source["custody_store"].record_id)


class ExportAndQueryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "state.sqlite"
        self.path = Path(self.temp.name) / "incident-report.json"
        self.backend = SQLiteKernelState(self.db)
        self.addCleanup(self.backend.close)
        self.kernel = GovernanceKernel(Policy(frozenset({"read"}), 0), secret=b"test-only", state=self.backend)
        self.owner = PulpoOrchestrator(self.kernel)

    def test_freeze_export_load_round_trip(self):
        self.backend.append("purchase_consequence_unknown",
                            {"order_hash": "a" * 64, "reason": "external_consequence_not_yet_verified"}, 100)
        self.backend.append("permit_rejected", {"reason": "permit_clock_invalid"}, 200)
        snapshot = export_incident_report(self.owner, self.path)
        reloaded = load_incident_report(self.path)
        self.assertEqual(snapshot, reloaded)
        self.assertEqual(1, reloaded.incidents)
        self.assertEqual(1, reloaded.near_misses)
        self.assertEqual(2, reloaded.audit_records)

    def test_export_requires_absolute_path(self):
        with self.assertRaises(MCPBoundaryError):
            export_incident_report(self.owner, "relative/path.json")

    def test_export_is_read_only(self):
        self.backend.append("purchase_consequence_unknown",
                            {"reason": "external_consequence_not_yet_verified"}, 100)
        before = len(self.kernel.audit)
        export_incident_report(self.owner, self.path)
        self.assertEqual(before, len(self.kernel.audit))
        self.assertTrue(self.kernel.verify_audit())

    def test_query_filters(self):
        self.backend.append("purchase_consequence_unknown",
                            {"reason": "external_consequence_not_yet_verified"}, 100)
        self.backend.append("permit_rejected", {"reason": "permit_clock_invalid"}, 200)
        self.backend.append("purchase_consequence_unknown",
                            {"reason": "external_consequence_not_yet_verified"}, 300)
        self.assertEqual(2, len(list_incidents(self.owner, kind="incident")))
        self.assertEqual(1, len(list_incidents(self.owner, kind="near_miss")))
        self.assertEqual(2, len(list_incidents(self.owner, resolution="unresolved")))
        self.assertEqual(0, len(list_incidents(self.owner, resolution="resolved_cleanly")))
        self.assertEqual(1, len(list_incidents(self.owner, since_ns=250)))
        self.assertEqual(2, len(list_incidents(self.owner, until_ns=200)))
        self.assertEqual(1, len(list_incidents(self.owner, since_ns=150, until_ns=250)))
        self.assertEqual(3, len(list_incidents(self.owner)))

    def test_query_invalid_filters_raise(self):
        with self.assertRaises(ValueError):
            list_incidents(self.owner, kind="maybe")
        with self.assertRaises(ValueError):
            list_incidents(self.owner, resolution="ignored")
        with self.assertRaises(ValueError):
            list_incidents(self.owner, since_ns=-1)
        with self.assertRaises(ValueError):
            list_incidents(self.owner, since_ns=300, until_ns=100)


if __name__ == "__main__":
    unittest.main()

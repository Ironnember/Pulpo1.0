import tempfile
import unittest
from pathlib import Path

from pulpo.authority_client import AuthorityPoll
from pulpo.commerce import (
    DomainPurchaseRequest,
    DomainQuote,
    RegistrarResult,
    SQLiteBudgetAccount,
    assess_quote,
    purchase_intent,
)
from pulpo.custody import SQLiteGovernanceCustody
from pulpo.custody_domain import GovernedDomainAttemptCoordinator
from pulpo.custody_evidence import SQLiteCustodyEvidenceConvergence
from pulpo.custody_executor import TrustedDomainExecutor
from pulpo.custody_reconcile import (
    GovernedDomainOutcomeMemoryProjection,
    IndependentDomainObservation,
    IndependentDomainReconciler,
)
from pulpo.kernel import AgentGrant, GovernanceKernel, Intent, Policy
from pulpo.mcp_admission import (
    ADMISSION_ACTION,
    ADMISSION_RESOURCE_PREFIX,
    MCPProposalAdmissionController,
    MCPProposalAdmissionError,
    validate_mcp_proposal,
)
from pulpo.mcp_boundary import PulpoMCPProjection, freeze_mcp_snapshot
from pulpo.orchestrator import PulpoOrchestrator
from pulpo.state import InMemoryKernelState, SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 31_000_000
ADMITTER = "service:proposal-custody"
ADMIT_SESSION = "mcp-admission:proof"
CUSTODY_SECRET = b"mcp-admission-custody-proof"


class FakeAuthorityClient:
    def __init__(self, kernel, verifier):
        self.kernel = kernel
        self.verifier = verifier
        self.requests = []

    def request_approval(self, request):
        self.requests.append(request)
        return "mcp-handoff-approval", "https://authority.invalid/mcp-handoff-approval"

    def poll_approval(self, request_id):
        if request_id != "mcp-handoff-approval":
            return AuthorityPoll("denied", reason="unknown_request")
        request = self.requests[-1]
        intent = Intent(
            request.principal,
            request.action,
            request.resource,
            request.cost,
            request.session_id,
        )
        envelope = signed_envelope(
            self.kernel,
            intent,
            self.verifier,
            now_ns=NOW - 10,
            approval_id="mcp-handoff-authority",
            nonce="mcp-handoff-authority-nonce",
        )
        return AuthorityPoll("approved", envelope)


class FakeCustodyRegistrar:
    def __init__(self):
        self.preflight_calls = 0
        self.purchase_calls = 0

    def preflight(self, order):
        self.preflight_calls += 1
        return "b" * 64

    def purchase(self, order, *, max_charge_cents, idempotency_key):
        self.purchase_calls += 1
        return RegistrarResult(
            payment_id="mcp-handoff-payment",
            charged_cents=min(order.purchase_price_cents, max_charge_cents),
            receipt_hash="a" * 64,
            registration_id="mcp-handoff-registration",
            domain=order.domain,
            registrar=order.registrar,
        )


class MCPProposalAdmissionTests(unittest.TestCase):
    def policy(self, verifier=None, *, extra_actions=()):
        actions = frozenset({ADMISSION_ACTION, "purchase_domain", *extra_actions})
        return Policy(
            actions,
            3_000,
            frozenset({"purchase_domain"}) if verifier is not None else frozenset(),
            agent_grants=(
                AgentGrant(
                    principal=ADMITTER,
                    allowed_actions=frozenset({ADMISSION_ACTION}),
                    resource_prefixes=(ADMISSION_RESOURCE_PREFIX,),
                    max_cost=0,
                ),
                AgentGrant(
                    principal="agent:commerce",
                    allowed_actions=frozenset({"purchase_domain"}),
                    resource_prefixes=("commerce:domain:",),
                    max_cost=3_000,
                ),
            ),
            authority_trust=trust_for(verifier) if verifier is not None else None,
        )

    def in_memory_stack(self):
        kernel = GovernanceKernel(
            self.policy(),
            secret=b"mcp-admission-kernel",
            clock=lambda: NOW,
            state=InMemoryKernelState(),
        )
        orchestrator = PulpoOrchestrator(kernel)
        controller = MCPProposalAdmissionController(orchestrator)
        projection = PulpoMCPProjection(freeze_mcp_snapshot(orchestrator))
        return kernel, controller, projection

    @staticmethod
    def order(domain="pulpo-mcp-handoff.example"):
        request = DomainPurchaseRequest(
            request_id=f"mcp-handoff-request:{domain}",
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
            quote_id=f"mcp-handoff-quote:{domain}",
            domain=domain,
            registrar="name.com",
            purchase_price_cents=2_000,
            renewal_price_cents=2_400,
            owner_ref="owner://iron-ember",
            privacy_enabled=True,
            upsells=(),
            expires_at_ns=NOW + 50_000,
        )
        assessment = assess_quote(
            request,
            quote,
            credential_ref="credential://test-only/mcp-handoff",
            now_ns=NOW,
        )
        assert assessment.order is not None
        return assessment.order

    @staticmethod
    def proposal(projection, intent, *, target_id="mcp-handoff-target"):
        return projection.propose_intent(
            target_id,
            intent.principal,
            intent.action,
            intent.resource,
            intent.cost,
            intent.session_id,
        )

    def test_proposal_alone_cannot_lock_or_authorize(self):
        kernel, controller, projection = self.in_memory_stack()
        intent = purchase_intent(self.order())
        proposal = self.proposal(projection, intent)

        self.assertEqual([], kernel.audit)
        self.assertIsNone(kernel.get_locked_target("mcp-handoff-target"))
        self.assertNotIn("permit", proposal)
        with self.assertRaisesRegex(MCPProposalAdmissionError, "permit_required"):
            controller.admit(
                proposal,
                "",
                principal=ADMITTER,
                session_id=ADMIT_SESSION,
            )
        self.assertEqual([], kernel.audit)

    def test_exact_admission_permit_locks_once_and_records_non_authorizing_receipt(self):
        kernel, controller, projection = self.in_memory_stack()
        intent = purchase_intent(self.order())
        proposal = self.proposal(projection, intent)
        transition = controller.admission_intent(
            proposal,
            principal=ADMITTER,
            session_id=ADMIT_SESSION,
        )
        decision = kernel.evaluate(transition)
        self.assertEqual("allow", decision.outcome)

        target, receipt = controller.admit(
            proposal,
            decision.permit,
            principal=ADMITTER,
            session_id=ADMIT_SESSION,
        )

        self.assertEqual(intent, target.intent)
        self.assertEqual(validate_mcp_proposal(proposal).proposal_hash, receipt.proposal_hash)
        self.assertEqual(target.target_hash, receipt.target_hash)
        self.assertEqual("none", receipt.authority_effect)
        self.assertEqual("canonical_target_lock_and_admission_evidence", receipt.governed_effect)
        self.assertTrue(receipt.canonical_state_mutation)
        event = kernel.audit[-1]
        self.assertEqual(controller.EVENT, event["event"])
        self.assertEqual(receipt.receipt_hash, event["payload"]["receipt_hash"])
        self.assertTrue(kernel.verify_audit())

        before_replay = list(kernel.audit)
        with self.assertRaisesRegex(MCPProposalAdmissionError, "target_already_locked"):
            controller.admit(
                proposal,
                decision.permit,
                principal=ADMITTER,
                session_id=ADMIT_SESSION,
            )
        self.assertEqual(before_replay, kernel.audit)

    def test_admission_target_receipt_and_spent_permit_survive_restart(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-shm").unlink(missing_ok=True))

        first_state = SQLiteKernelState(path)
        first_kernel = GovernanceKernel(
            self.policy(),
            secret=b"mcp-admission-restart-kernel",
            clock=lambda: NOW,
            state=first_state,
        )
        first_orchestrator = PulpoOrchestrator(first_kernel)
        first_controller = MCPProposalAdmissionController(first_orchestrator)
        proposal = self.proposal(
            PulpoMCPProjection(freeze_mcp_snapshot(first_orchestrator)),
            purchase_intent(self.order()),
        )
        transition = first_controller.admission_intent(
            proposal,
            principal=ADMITTER,
            session_id=ADMIT_SESSION,
        )
        decision = first_kernel.evaluate(transition)
        target, receipt = first_controller.admit(
            proposal,
            decision.permit,
            principal=ADMITTER,
            session_id=ADMIT_SESSION,
        )
        first_state.close()

        restarted_state = SQLiteKernelState(path)
        self.addCleanup(restarted_state.close)
        restarted_kernel = GovernanceKernel(
            self.policy(),
            secret=b"mcp-admission-restart-kernel",
            clock=lambda: NOW,
            state=restarted_state,
        )
        restored = restarted_kernel.get_locked_target(
            target.target_id,
            version=target.version,
        )

        self.assertEqual(target, restored)
        admitted = [
            record
            for record in restarted_kernel.audit
            if record["event"] == MCPProposalAdmissionController.EVENT
        ]
        self.assertEqual(1, len(admitted))
        self.assertEqual(receipt.receipt_hash, admitted[0]["payload"]["receipt_hash"])
        self.assertFalse(restarted_kernel.consume(decision.permit, transition))
        self.assertEqual("permit_rejected", restarted_kernel.audit[-1]["event"])
        self.assertEqual(
            restarted_kernel.intent_hash(transition),
            restarted_kernel.audit[-1]["payload"]["intent_hash"],
        )
        self.assertTrue(restarted_kernel.verify_audit())

    def test_substitution_or_capability_claim_never_reaches_target_lock(self):
        kernel, controller, projection = self.in_memory_stack()
        original = self.proposal(projection, purchase_intent(self.order()), target_id="original")
        transition = controller.admission_intent(
            original,
            principal=ADMITTER,
            session_id=ADMIT_SESSION,
        )
        decision = kernel.evaluate(transition)

        changed_intent = purchase_intent(self.order("pulpo-substituted.example"))
        substituted = self.proposal(projection, changed_intent, target_id="substituted")
        with self.assertRaisesRegex(MCPProposalAdmissionError, "permit_rejected"):
            controller.admit(
                substituted,
                decision.permit,
                principal=ADMITTER,
                session_id=ADMIT_SESSION,
            )
        self.assertIsNone(kernel.get_locked_target("original"))
        self.assertIsNone(kernel.get_locked_target("substituted"))

        injected = dict(original)
        injected["authority"] = "approved"
        before_injection = list(kernel.audit)
        with self.assertRaisesRegex(MCPProposalAdmissionError, "fields_invalid"):
            controller.admission_intent(
                injected,
                principal=ADMITTER,
                session_id=ADMIT_SESSION,
            )
        self.assertEqual(before_injection, kernel.audit)

        forged = dict(original)
        forged["canonical_state_mutation"] = True
        with self.assertRaisesRegex(MCPProposalAdmissionError, "capability_claim_invalid"):
            validate_mcp_proposal(forged)

    def test_stale_snapshot_policy_is_rejected_before_admission_evaluation(self):
        old_kernel, _, old_projection = self.in_memory_stack()
        proposal = self.proposal(old_projection, purchase_intent(self.order()))
        changed_kernel = GovernanceKernel(
            Policy(frozenset({ADMISSION_ACTION, "read"}), 0),
            secret=b"changed-policy",
            clock=lambda: NOW,
        )
        controller = MCPProposalAdmissionController(PulpoOrchestrator(changed_kernel))

        with self.assertRaisesRegex(MCPProposalAdmissionError, "policy_stale"):
            controller.admission_intent(
                proposal,
                principal=ADMITTER,
                session_id=ADMIT_SESSION,
            )
        self.assertEqual([], old_kernel.audit)
        self.assertEqual([], changed_kernel.audit)

    def test_oversized_plugin_fields_are_rejected_before_canonical_mutation(self):
        kernel, controller, projection = self.in_memory_stack()
        proposal = self.proposal(projection, purchase_intent(self.order()))

        oversized_target = dict(proposal, target_id="t" * 257)
        with self.assertRaisesRegex(MCPProposalAdmissionError, "target_invalid"):
            controller.admission_intent(
                oversized_target,
                principal=ADMITTER,
                session_id=ADMIT_SESSION,
            )

        oversized_resource = dict(proposal)
        oversized_resource["intent"] = dict(proposal["intent"], resource="r" * 4_097)
        with self.assertRaisesRegex(MCPProposalAdmissionError, "intent_invalid"):
            controller.admission_intent(
                oversized_resource,
                principal=ADMITTER,
                session_id=ADMIT_SESSION,
            )
        self.assertEqual([], kernel.audit)

    def test_admission_receipt_cannot_authorize_an_unrelated_action(self):
        kernel, controller, projection = self.in_memory_stack()
        proposal = self.proposal(projection, purchase_intent(self.order()))
        transition = controller.admission_intent(
            proposal,
            principal=ADMITTER,
            session_id=ADMIT_SESSION,
        )
        decision = kernel.evaluate(transition)
        _, receipt = controller.admit(
            proposal,
            decision.permit,
            principal=ADMITTER,
            session_id=ADMIT_SESSION,
        )

        denied = kernel.evaluate(Intent("agent:commerce", "deploy", f"receipt:{receipt.receipt_hash}"))
        self.assertEqual(("deny", "action_not_allowed"), (denied.outcome, denied.reason))
        self.assertIsNone(denied.permit)

    def test_plugin_proposal_composes_through_existing_executor_reconciliation_and_memory(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        path = Path(handle.name)
        handle.close()
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-wal").unlink(missing_ok=True))
        self.addCleanup(lambda: Path(str(path) + "-shm").unlink(missing_ok=True))

        verifier = HmacTestVerifier(secret=b"mcp-handoff-test-authority")
        state = SQLiteKernelState(path)
        self.addCleanup(state.close)
        kernel = GovernanceKernel(
            self.policy(verifier),
            secret=b"mcp-handoff-kernel",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        authority = FakeAuthorityClient(kernel, verifier)
        orchestrator = PulpoOrchestrator(kernel, authority_client=authority)
        projection = PulpoMCPProjection(freeze_mcp_snapshot(orchestrator))
        order = self.order()
        proposed_intent = purchase_intent(order)
        proposal = self.proposal(projection, proposed_intent)

        admission = MCPProposalAdmissionController(orchestrator)
        admission_intent = admission.admission_intent(
            proposal,
            principal=ADMITTER,
            session_id=ADMIT_SESSION,
        )
        admission_decision = kernel.evaluate(admission_intent)
        target, receipt = admission.admit(
            proposal,
            admission_decision.permit,
            principal=ADMITTER,
            session_id=ADMIT_SESSION,
        )

        approval_handle = orchestrator.request_target_approval(target, requested_ttl_ns=500)
        authorization = orchestrator.authorize_target(approval_handle)
        self.assertEqual("allow", authorization.decision.outcome)

        custody = SQLiteGovernanceCustody(
            path,
            signing_secret=CUSTODY_SECRET,
            clock=lambda: NOW,
        )
        budget = SQLiteBudgetAccount(path)
        convergence = SQLiteCustodyEvidenceConvergence(custody)
        coordinator = GovernedDomainAttemptCoordinator(kernel, custody, budget)
        reservation = coordinator.reserve(order)
        governed = coordinator.authorize(
            target_id=target.target_id,
            expected_target_hash=target.target_hash,
            order=order,
            permit=authorization.decision.permit,
            reservation_id=reservation.reservation_id,
        )
        convergence.project_all()

        provider = FakeCustodyRegistrar()
        claim = TrustedDomainExecutor(
            custody,
            executor_id="executor:mcp-handoff-test",
            evidence_projector=convergence.project_all,
        ).execute(governed, order, provider)
        observation = IndependentDomainObservation(
            observation_id="mcp-handoff-observation",
            provider_request_id=claim.provider_request_id,
            provider_request_status="succeeded",
            domain=claim.result.domain,
            registrar=claim.result.registrar,
            owner_ref=order.owner_ref,
            registered=True,
            payment_id=claim.result.payment_id,
            charged_cents=claim.result.charged_cents,
            receipt_hash=claim.result.receipt_hash,
            privacy_enabled=True,
            dns_state="registered",
        )
        reconciliation = IndependentDomainReconciler(
            custody,
            budget,
            observer_id="observer:mcp-handoff-test",
        ).reconcile(governed, order, observation)
        convergence.project_all()
        memory = GovernedDomainOutcomeMemoryProjection(kernel, custody).record(
            governed,
            order,
            observation,
            reconciliation,
        )

        self.assertEqual(validate_mcp_proposal(proposal).proposal_hash, receipt.proposal_hash)
        self.assertEqual(receipt.target_hash, governed.target_hash)
        self.assertEqual(proposal["intent_hash"], governed.intent_hash)
        self.assertEqual(1, provider.preflight_calls)
        self.assertEqual(1, provider.purchase_calls)
        self.assertEqual(("success", "external_consequence_verified"), (reconciliation.outcome, reconciliation.reason))
        self.assertEqual("SUCCESS_VERIFIED", memory.classification)
        self.assertEqual("none", memory.authority_effect)
        self.assertTrue(kernel.verify_audit())

        changed = self.proposal(
            projection,
            purchase_intent(self.order("pulpo-late-substitution.example")),
            target_id="late-substitution",
        )
        with self.assertRaisesRegex(MCPProposalAdmissionError, "permit_rejected"):
            admission.admit(
                changed,
                admission_decision.permit,
                principal=ADMITTER,
                session_id=ADMIT_SESSION,
            )
        self.assertEqual(1, provider.purchase_calls)


if __name__ == "__main__":
    unittest.main()

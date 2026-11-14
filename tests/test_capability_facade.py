"""Phase 2, Item 3A — the capability facade: kernel-mediated verbs and
typed authority evidence.

The pre-3A gap (design repro ``repro_p2_3_capability_handles.py``,
confirmed at ``d7fab93``): the ``KernelState`` surface was a public,
unmediated write surface and production code reached it around the
kernel via ``kernel._state`` —

- A. ``state.consume_permit`` spent a genuine permit with no kernel
  involvement;
- B. ``state.activate_directive(forged, {"approver": "no-one",
  "evidence": "invented"})`` was accepted, and the invented directive
  gated a real kernel spend end to end;
- C. ``state.append`` wrote a well-formed forged ``decision`` record
  that verified.

These tests pin what 3A changes — and state what it does not. 3A is
discipline + evidence (ruling Q5), NOT in-process enforcement: the
state methods still exist for the kernel's own use, and a determined
in-process caller holding a backend can still write around the
facade. What is pinned here:

- directive activation/revocation at the state surface require the
  exact ``VerifiedAuthorityEvidence`` type, cross-checked against the
  directive being mutated — the bare dict of repro B is refused on
  both backends, as is a wrapper bound to a different directive;
- the honest controller flow (verified envelope -> typed evidence ->
  activation -> bound permit -> consume) still works end to end, and
  the audit payload keeps its pre-3A dict shape byte for byte;
- the reconciliation appends production modules need are fixed-schema
  kernel verbs (``record_target_completion``,
  ``record_domain_outcome_memory``);
- no production module outside ``kernel.py`` reaches ``._state``, and
  ``VerifiedAuthorityEvidence`` is constructed at exactly one
  production site (the controller) — both pinned structurally below.
"""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
from pulpo.state import InMemoryKernelState, SQLiteKernelState, VerifiedAuthorityEvidence
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 2_000_000
OPERATOR = "operator:owner"
REPO_ROOT = Path(__file__).resolve().parents[1]


def directive(**overrides):
    values = dict(
        directive_id="deploy-prod",
        version=1,
        issuer_authority_id="authority:test-owner",
        principal="agent:builder",
        allowed_actions=frozenset({"write"}),
        resource_prefixes=("repo:",),
        max_cost=5,
        issued_at_ns=1_000_000,
        expires_at_ns=3_000_000,
    )
    values.update(overrides)
    return Directive(**values)


def evidence_for(operation, d, **overrides):
    values = dict(
        operation=operation,
        directive_id=d.directive_id,
        directive_version=d.version,
        directive_hash=d.directive_hash,
        parent_directive_hash=d.parent_directive_hash,
        authority_id=d.issuer_authority_id,
        approval_id="approval:test",
        envelope_hash="envelope:test",
        intent_hash="intent:test",
        policy_hash="policy:test",
    )
    values.update(overrides)
    return VerifiedAuthorityEvidence(**values)


def governed(state):
    verifier = HmacTestVerifier()
    policy = Policy(
        frozenset({"write", "activate_directive", "revoke_directive"}),
        100,
        frozenset({"activate_directive", "revoke_directive"}),
        authority_trust=trust_for(verifier),
    )
    kernel = GovernanceKernel(
        policy,
        secret=b"capability-facade-test-secret",
        approval_verifier=verifier,
        clock=lambda: NOW,
        state=state,
    )
    return kernel, verifier, DirectiveAuthorityController(kernel)


def approve(kernel, verifier, controller, operation, d, approval_id):
    intent = controller.authority_intent(operation, d, operator_principal=OPERATOR)
    return signed_envelope(
        kernel, intent, verifier, now_ns=NOW - 10,
        approval_id=approval_id, nonce=f"{approval_id}-nonce",
    )


class TypedEvidenceGateTests(unittest.TestCase):
    def test_bare_dict_activation_refused_inmemory(self):
        state = InMemoryKernelState()
        d = directive()
        with self.assertRaises(TypeError):
            state.activate_directive(d, {"approver": "no-one", "evidence": "invented"}, NOW)
        self.assertEqual(
            "directive_not_authorized",
            state.directive_status(d.directive_id, d.version, d.directive_hash),
        )
        self.assertEqual([], [r for r in state.audit if r["event"] == "directive_activated"])

    def test_bare_dict_activation_refused_sqlite(self):
        with tempfile.NamedTemporaryFile() as handle:
            state = SQLiteKernelState(handle.name)
            d = directive()
            with self.assertRaises(TypeError):
                state.activate_directive(d, {"approver": "no-one", "evidence": "invented"}, NOW)
            self.assertEqual(
                "directive_not_authorized",
                state.directive_status(d.directive_id, d.version, d.directive_hash),
            )
            state.close()

    def test_bare_dict_revocation_refused(self):
        state = InMemoryKernelState()
        kernel, verifier, controller = governed(state)
        d = directive()
        envelope = approve(kernel, verifier, controller, controller.ACTIVATE, d, "activate-1")
        self.assertEqual("allow", controller.activate(d, envelope, operator_principal=OPERATOR).outcome)
        with self.assertRaises(TypeError):
            state.revoke_directive(d.directive_id, d.version, {"test": True}, NOW)
        self.assertEqual(
            "active",
            state.directive_status(d.directive_id, d.version, d.directive_hash),
        )

    def test_evidence_bound_to_another_directive_refused(self):
        state = InMemoryKernelState()
        d = directive()
        other = directive(directive_id="deploy-other")
        with self.assertRaises(ValueError):
            state.activate_directive(d, evidence_for("activate_directive", other), NOW)
        # The same wrapper with the wrong operation is refused too.
        with self.assertRaises(ValueError):
            state.activate_directive(d, evidence_for("revoke_directive", d), NOW)
        self.assertEqual(
            "directive_not_authorized",
            state.directive_status(d.directive_id, d.version, d.directive_hash),
        )

    def test_evidence_subclass_refused(self):
        class SubEvidence(VerifiedAuthorityEvidence):
            pass

        state = InMemoryKernelState()
        d = directive()
        forged = SubEvidence(**evidence_for("activate_directive", d).__dict__)
        with self.assertRaises(TypeError):
            state.activate_directive(d, forged, NOW)


class HonestFacadeFlowTests(unittest.TestCase):
    def test_controller_activation_records_typed_evidence_and_gates_spend(self):
        state = InMemoryKernelState()
        kernel, verifier, controller = governed(state)
        d = directive()
        envelope = approve(kernel, verifier, controller, controller.ACTIVATE, d, "activate-1")
        decision = controller.activate(d, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)

        activation = next(r for r in state.audit if r["event"] == "directive_activated")
        recorded = activation["payload"]["authority_evidence"]
        # The recorded payload keeps the pre-3A dict shape exactly.
        self.assertEqual(
            {
                "operation": "activate_directive",
                "directive_id": d.directive_id,
                "directive_version": d.version,
                "directive_hash": d.directive_hash,
                "parent_directive_hash": None,
                "authority_id": "authority:test-owner",
                "approval_id": "activate-1",
                "envelope_hash": envelope.envelope_hash,
                "intent_hash": kernel.intent_hash(
                    controller.authority_intent(controller.ACTIVATE, d, operator_principal=OPERATOR)
                ),
                "policy_hash": kernel.policy_hash,
            },
            recorded,
        )

        # The honest counterpart of repro B: a directive activated
        # through the verified path gates a real spend, once.
        projection = GovernedDirectiveProjection(kernel)
        intent = Intent("agent:builder", "write", "repo:file", 5)
        allowed = projection.evaluate(intent, d)
        self.assertEqual("allow", allowed.outcome)
        self.assertTrue(kernel.consume(allowed.permit, intent))
        self.assertFalse(kernel.consume(allowed.permit, intent))
        self.assertTrue(kernel.verify_audit())

    def test_kernel_verbs_record_fixed_schemas(self):
        state = InMemoryKernelState()
        kernel = GovernanceKernel(
            Policy(frozenset({"write"}), 100),
            secret=b"capability-facade-test-secret",
            clock=lambda: NOW,
            state=state,
        )
        kernel.record_target_completion(
            target_id="target:1",
            version=1,
            target_hash="a" * 64,
            intent_hash="b" * 64,
            completion={"artifact_sha256": "c" * 64},
            completion_hash="d" * 64,
            timestamp_ns=NOW,
        )
        record = next(r for r in state.audit if r["event"] == "target_completed")
        self.assertEqual(
            {
                "target_id": "target:1",
                "version": 1,
                "target_hash": "a" * 64,
                "intent_hash": "b" * 64,
                "completion": {"artifact_sha256": "c" * 64},
                "completion_hash": "d" * 64,
                "authority_effect": "none",
            },
            record["payload"],
        )

        payload = {"reconciliation_transition_hash": "t-1", "memory_id": "m-1"}
        self.assertIsNone(
            kernel.record_domain_outcome_memory(
                reconciliation_transition_hash="t-1", payload=payload, timestamp_ns=NOW
            )
        )
        self.assertEqual(
            payload,
            kernel.record_domain_outcome_memory(
                reconciliation_transition_hash="t-1", payload=payload, timestamp_ns=NOW
            ),
        )
        memories = [r for r in state.audit if r["event"] == "domain_outcome_memory"]
        self.assertEqual(1, len(memories))
        self.assertTrue(kernel.verify_audit())

    def test_state_source_id_is_stable_and_opaque(self):
        kernel, _, _ = governed(InMemoryKernelState())
        source_id = kernel.state_source_id()
        self.assertEqual(source_id, kernel.state_source_id())
        self.assertEqual(32, len(source_id))
        other, _, _ = governed(InMemoryKernelState())
        self.assertNotEqual(source_id, other.state_source_id())


class StructuralPinTests(unittest.TestCase):
    def test_no_state_reach_through_outside_kernel(self):
        offenders = []
        for path in sorted((REPO_ROOT / "pulpo").glob("*.py")):
            if path.name == "kernel.py":
                continue
            if "._state" in path.read_text():
                offenders.append(path.name)
        self.assertEqual([], offenders)

    def test_verified_evidence_constructed_only_by_controller(self):
        offenders = []
        for path in sorted((REPO_ROOT / "pulpo").glob("*.py")):
            if path.name in ("kernel.py", "state.py", "directives.py"):
                continue
            if "VerifiedAuthorityEvidence(" in path.read_text():
                offenders.append(path.name)
        self.assertEqual([], offenders)
        # And the one permitted site is the controller's builder.
        directives_source = (REPO_ROOT / "pulpo" / "directives.py").read_text()
        self.assertIn("VerifiedAuthorityEvidence(", directives_source)


if __name__ == "__main__":
    unittest.main()

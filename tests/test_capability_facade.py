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

from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.custody import CustodyViolation, SQLiteGovernanceCustody
from pulpo.custody_reconcile import DomainOutcomeMemory, GovernedDomainOutcomeMemoryProjection
from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
from pulpo.state import InMemoryKernelState, SQLiteKernelState, VerifiedAuthorityEvidence
from pulpo.target_reconcile import ArtifactCompletionEvidence, GovernedTargetReconciliation
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


def _sha(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def invented_outcome_memory_payload(kernel, transition_hash: str) -> dict:
    """A fully-formed invented memory payload with a *correct* identity hash.

    Every hash is invented (no order, target, custody receipt, or
    observation exists), the policy hash is the kernel's own, and the
    ``memory_id`` is correctly recomputed over the invented identity —
    so only the verb's custody-evidence / exact-target checks can
    refuse it.
    """

    identity = {
        "schema": "pulpo.domain-outcome-memory.v0",
        "attempt_id": "attempt-forged-v0",
        "order_hash": _sha("invented-order"),
        "target_hash": _sha("invented-target"),
        "intent_hash": _sha("invented-intent"),
        "policy_hash": kernel.policy_hash,
        "observation_hash": _sha("invented-observation"),
        "reconciliation_transition_hash": transition_hash,
        "reconciliation_epoch": 1,
        "reconciliation_outcome": "success",
        "classification": "SUCCESS_VERIFIED",
        "reason": "external_consequence_verified",
        "reusable": True,
        "authority_effect": "none",
        "governed_effect": "canonical_outcome_memory",
    }
    return {
        **identity,
        "memory_id": sha256(_canonical(identity)).hexdigest(),
        "recorded_at_ns": NOW,
    }


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

    def test_kernel_verb_target_completion_observes_real_file(self):
        state = InMemoryKernelState()
        kernel = GovernanceKernel(
            Policy(frozenset({"write"}), 100),
            secret=b"capability-facade-test-secret",
            clock=lambda: NOW,
            state=state,
        )
        intent = Intent("agent:builder", "write", "repo:file", 5)
        target = kernel.lock_target("target:1", intent)
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "deck.pptx"
            artifact.write_bytes(b"verified deck artifact")
            recorded = kernel.record_target_completion(
                target_id="target:1",
                version=1,
                target_hash=target.target_hash,
                intent_hash=kernel.intent_hash(intent),
                artifact_path=str(artifact),
                timestamp_ns=NOW,
            )
            self.assertEqual(
                sha256(b"verified deck artifact").hexdigest(),
                recorded["artifact_sha256"],
            )
            self.assertEqual(len(b"verified deck artifact"), recorded["size_bytes"])
            self.assertEqual(str(artifact.resolve()), recorded["artifact_path"])
            self.assertEqual(NOW, recorded["observed_at_ns"])
            self.assertEqual(
                "pulpo.target-artifact-completion.v0", recorded["schema"]
            )

        record = next(r for r in state.audit if r["event"] == "target_completed")
        self.assertEqual(
            {
                "target_id": "target:1",
                "version": 1,
                "target_hash": target.target_hash,
                "intent_hash": kernel.intent_hash(intent),
                "completion": recorded,
                "completion_hash": sha256(_canonical(recorded)).hexdigest(),
                "authority_effect": "none",
            },
            record["payload"],
        )
        self.assertTrue(kernel.verify_audit())

    def test_kernel_verb_target_completion_refuses_unobserved_or_mismatched(self):
        state = InMemoryKernelState()
        kernel = GovernanceKernel(
            Policy(frozenset({"write"}), 100),
            secret=b"capability-facade-test-secret",
            clock=lambda: NOW,
            state=state,
        )
        intent = Intent("agent:builder", "write", "repo:file", 5)
        target = kernel.lock_target("target:1", intent)
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.pptx"
            with self.assertRaisesRegex(ValueError, "artifact_not_found"):
                kernel.record_target_completion(
                    target_id="target:1",
                    version=1,
                    target_hash=target.target_hash,
                    intent_hash=kernel.intent_hash(intent),
                    artifact_path=str(missing),
                    timestamp_ns=NOW,
                )
            artifact = Path(directory) / "deck.pptx"
            artifact.write_bytes(b"verified deck artifact")
            with self.assertRaisesRegex(ValueError, "target_intent_mismatch"):
                kernel.record_target_completion(
                    target_id="target:1",
                    version=1,
                    target_hash=target.target_hash,
                    intent_hash="0" * 64,
                    artifact_path=str(artifact),
                    timestamp_ns=NOW,
                )
            with self.assertRaisesRegex(ValueError, "target_hash_mismatch"):
                kernel.record_target_completion(
                    target_id="target:1",
                    version=1,
                    target_hash="0" * 64,
                    intent_hash=kernel.intent_hash(intent),
                    artifact_path=str(artifact),
                    timestamp_ns=NOW,
                )
        self.assertEqual(
            [], [r for r in state.audit if r["event"] == "target_completed"]
        )
        self.assertTrue(kernel.verify_audit())

    def test_kernel_verb_outcome_memory_refuses_self_asserted_payloads(self):
        state = InMemoryKernelState()
        kernel = GovernanceKernel(
            Policy(frozenset({"write"}), 100),
            secret=b"capability-facade-test-secret",
            clock=lambda: NOW,
            state=state,
        )
        # The old nonsense payload the pre-fix test recorded verbatim.
        nonsense = {"reconciliation_transition_hash": "t-1", "memory_id": "m-1"}
        with self.assertRaisesRegex(ValueError, "outcome_memory_"):
            kernel.record_domain_outcome_memory(
                reconciliation_transition_hash="t-1",
                payload=nonsense,
                timestamp_ns=NOW,
            )
        # A fully-formed invented payload whose memory_id is correctly
        # recomputed over invented hashes: no custody evidence exists,
        # so the custody-evidence check is the one that must refuse it.
        transition_hash = _sha("invented-transition")
        invented = invented_outcome_memory_payload(kernel, transition_hash)
        with self.assertRaisesRegex(
            ValueError, "outcome_memory_custody_evidence_missing"
        ):
            kernel.record_domain_outcome_memory(
                reconciliation_transition_hash=transition_hash,
                payload=invented,
                timestamp_ns=NOW,
            )
        self.assertEqual(
            [], [r for r in state.audit if r["event"] == "domain_outcome_memory"]
        )
        self.assertTrue(kernel.verify_audit())

    def test_forged_target_completion_does_not_complete_target(self):
        # Regression for Codex P1 4575682584, mirroring the repro
        # script end to end: a fabricated completion naming a
        # nonexistent file must not make status() return completed.
        kernel = GovernanceKernel(
            Policy(frozenset({"write"}), 100),
            secret=b"capability-facade-test-secret",
            clock=lambda: NOW,
        )
        intent = Intent("agent:builder", "write", "artifact:pitch-deck", 0, "deck-session")
        target = kernel.lock_target("deck-v1", intent)
        reconcile = GovernedTargetReconciliation(kernel)
        with tempfile.TemporaryDirectory() as directory:
            missing = str(Path(directory) / "definitely-not-a-real-artifact.pptx")
            forged = ArtifactCompletionEvidence(
                target_id="deck-v1",
                version=1,
                target_hash=target.target_hash,
                intent_hash=kernel.intent_hash(intent),
                artifact_path=missing,
                artifact_sha256=sha256(b"never observed").hexdigest(),
                size_bytes=12345,
                observed_at_ns=NOW,
            )
            # The pre-fix call shape (caller-supplied dict + hash) is
            # no longer accepted anywhere.
            with self.assertRaises(TypeError):
                kernel.record_target_completion(
                    target_id=forged.target_id,
                    version=forged.version,
                    target_hash=forged.target_hash,
                    intent_hash=forged.intent_hash,
                    completion=asdict(forged),
                    completion_hash=forged.evidence_hash,
                    timestamp_ns=NOW,
                )
            # The same forgery attempted against the new surface: the
            # verb observes the path itself and refuses.
            with self.assertRaisesRegex(ValueError, "artifact_not_found"):
                kernel.record_target_completion(
                    target_id=forged.target_id,
                    version=forged.version,
                    target_hash=forged.target_hash,
                    intent_hash=forged.intent_hash,
                    artifact_path=missing,
                    timestamp_ns=NOW,
                )
        status = reconcile.status("deck-v1", target.target_hash)
        self.assertEqual("unresolved", status.state)
        self.assertEqual("completion_evidence_missing", status.reason)
        self.assertIsNone(status.completion)
        self.assertEqual(
            [], [r for r in kernel.audit if r["event"] == "target_completed"]
        )
        self.assertTrue(kernel.verify_audit())

    def test_forged_outcome_memory_is_not_returned_by_latest(self):
        # Regression for Codex P1 4575682585, mirroring the repro
        # script end to end: a self-asserted SUCCESS_VERIFIED /
        # reusable payload must be refused by the verb and must not be
        # returned by projection.latest() as canonical memory.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pulpo.sqlite3"
            state = SQLiteKernelState(path)
            try:
                kernel = GovernanceKernel(
                    Policy(frozenset({"purchase_domain"}), 3_000),
                    secret=b"capability-facade-test-secret",
                    clock=lambda: NOW,
                    state=state,
                )
                custody = SQLiteGovernanceCustody(
                    path, signing_secret=b"independent-observer-custody", clock=lambda: NOW
                )
                projection = GovernedDomainOutcomeMemoryProjection(kernel, custody)

                forged = DomainOutcomeMemory(
                    memory_id=_sha("forged-memory-id"),
                    attempt_id="attempt-forged-v0",
                    order_hash=_sha("forged-order"),
                    target_hash=_sha("forged-target"),
                    intent_hash=_sha("forged-intent"),
                    policy_hash=_sha("forged-policy"),
                    observation_hash=_sha("forged-observation"),
                    reconciliation_transition_hash=_sha("forged-transition"),
                    reconciliation_epoch=1,
                    reconciliation_outcome="success",
                    classification="SUCCESS_VERIFIED",
                    reason="provider_success_independently_observed",
                    reusable=True,
                    recorded_at_ns=NOW,
                )
                with self.assertRaisesRegex(ValueError, "outcome_memory_"):
                    kernel.record_domain_outcome_memory(
                        reconciliation_transition_hash=forged.reconciliation_transition_hash,
                        payload=asdict(forged),
                        timestamp_ns=NOW,
                    )
                transition_hash = _sha("invented-transition")
                with self.assertRaisesRegex(ValueError, "outcome_memory_"):
                    kernel.record_domain_outcome_memory(
                        reconciliation_transition_hash=transition_hash,
                        payload=invented_outcome_memory_payload(kernel, transition_hash),
                        timestamp_ns=NOW,
                    )
                self.assertIsNone(projection.latest("attempt-forged-v0"))
                self.assertEqual(
                    [],
                    [r for r in kernel.audit if r["event"] == "domain_outcome_memory"],
                )
                self.assertTrue(kernel.verify_audit())
            finally:
                state.close()

    def test_raw_appended_memory_with_wrong_identity_is_refused_on_read(self):
        # Defense in depth on the read side: even a record that reaches
        # the audit by a route that skips the verb (the priced raw
        # ``state.append`` residual) is refused by ``latest()`` when its
        # ``memory_id`` does not recompute from its own fields.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pulpo.sqlite3"
            state = SQLiteKernelState(path)
            try:
                kernel = GovernanceKernel(
                    Policy(frozenset({"purchase_domain"}), 3_000),
                    secret=b"capability-facade-test-secret",
                    clock=lambda: NOW,
                    state=state,
                )
                custody = SQLiteGovernanceCustody(
                    path, signing_secret=b"independent-observer-custody", clock=lambda: NOW
                )
                projection = GovernedDomainOutcomeMemoryProjection(kernel, custody)
                forged = DomainOutcomeMemory(
                    memory_id=_sha("forged-memory-id"),
                    attempt_id="attempt-forged-v0",
                    order_hash=_sha("forged-order"),
                    target_hash=_sha("forged-target"),
                    intent_hash=_sha("forged-intent"),
                    policy_hash=_sha("forged-policy"),
                    observation_hash=_sha("forged-observation"),
                    reconciliation_transition_hash=_sha("forged-transition"),
                    reconciliation_epoch=1,
                    reconciliation_outcome="success",
                    classification="SUCCESS_VERIFIED",
                    reason="provider_success_independently_observed",
                    reusable=True,
                    recorded_at_ns=NOW,
                )
                state.append("domain_outcome_memory", asdict(forged), NOW)
                with self.assertRaisesRegex(
                    CustodyViolation, "outcome_memory_record_identity_mismatch"
                ):
                    projection.latest("attempt-forged-v0")
            finally:
                state.close()

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

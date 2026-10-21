from dataclasses import replace
import sqlite3
import tempfile
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
from pulpo.state import InMemoryKernelState, SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 2_000_000
OPERATOR = "operator:owner"


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


def child(parent, **overrides):
    values = dict(
        directive_id="deploy-prod-child",
        version=1,
        issuer_authority_id=parent.issuer_authority_id,
        principal=parent.principal,
        allowed_actions=frozenset({"write"}),
        resource_prefixes=("repo:service:",),
        max_cost=3,
        issued_at_ns=1_100_000,
        expires_at_ns=2_900_000,
        parent_directive_hash=parent.directive_hash,
    )
    values.update(overrides)
    return Directive(**values)


class DirectiveSupersessionProofTests(unittest.TestCase):
    def governed(self, state=None):
        verifier = HmacTestVerifier()
        governance_actions = frozenset({
            "activate_directive",
            "supersede_directive",
            "revoke_directive",
        })
        policy = Policy(
            frozenset({"write", *governance_actions}),
            100,
            governance_actions,
            authority_trust=trust_for(verifier),
        )
        kernel = GovernanceKernel(
            policy,
            secret=b"directive-supersession-proof",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        return kernel, verifier, DirectiveAuthorityController(kernel)

    def approve_activation(self, kernel, verifier, controller, d, suffix):
        intent = controller.authority_intent(
            controller.ACTIVATE,
            d,
            operator_principal=OPERATOR,
        )
        return signed_envelope(
            kernel,
            intent,
            verifier,
            now_ns=NOW - 10,
            approval_id=f"activate-{suffix}",
            nonce=f"activate-nonce-{suffix}",
        )

    def approve_supersession(self, kernel, verifier, controller, current, replacement, suffix):
        intent = controller.supersession_intent(
            current,
            replacement,
            operator_principal=OPERATOR,
        )
        return signed_envelope(
            kernel,
            intent,
            verifier,
            now_ns=NOW - 10,
            approval_id=f"supersede-{suffix}",
            nonce=f"supersede-nonce-{suffix}",
        )

    def activate(self, kernel, verifier, controller, d, suffix, parent=None):
        envelope = self.approve_activation(kernel, verifier, controller, d, suffix)
        decision = controller.activate(
            d,
            envelope,
            operator_principal=OPERATOR,
            parent_directive=parent,
        )
        self.assertEqual("allow", decision.outcome)
        return decision

    def test_higher_version_activation_does_not_implicitly_gain_precedence(self):
        state = InMemoryKernelState()
        current = directive()
        replacement = directive(version=2, issued_at_ns=1_100_000)
        kernel, verifier, controller = self.governed(state)
        self.activate(kernel, verifier, controller, current, "current")

        envelope = self.approve_activation(kernel, verifier, controller, replacement, "replacement")
        decision = controller.activate(replacement, envelope, operator_principal=OPERATOR)

        self.assertEqual(("deny", "directive_supersession_required"), (decision.outcome, decision.reason))
        self.assertEqual("active", state.directive_status(current.directive_id, current.version, current.directive_hash))
        self.assertEqual(
            "directive_not_authorized",
            state.directive_status(replacement.directive_id, replacement.version, replacement.directive_hash),
        )

    def test_supersession_requires_approval_bound_to_exact_old_and_new_hashes(self):
        state = InMemoryKernelState()
        current = directive()
        replacement = directive(version=2, issued_at_ns=1_100_000, max_cost=4)
        tampered = replace(replacement, max_cost=50)
        kernel, verifier, controller = self.governed(state)
        self.activate(kernel, verifier, controller, current, "current")

        envelope = self.approve_supersession(kernel, verifier, controller, current, replacement, "exact")
        decision = controller.supersede(
            current,
            tampered,
            envelope,
            operator_principal=OPERATOR,
        )

        self.assertEqual(("deny", "approval_intent_mismatch"), (decision.outcome, decision.reason))
        self.assertEqual("active", state.directive_status(current.directive_id, current.version, current.directive_hash))
        self.assertEqual(
            "directive_not_authorized",
            state.directive_status(tampered.directive_id, tampered.version, tampered.directive_hash),
        )

    def test_authorized_supersession_atomically_replaces_lineage_and_records_evidence(self):
        state = InMemoryKernelState()
        current = directive()
        replacement = directive(version=2, issued_at_ns=1_100_000, max_cost=4)
        kernel, verifier, controller = self.governed(state)
        self.activate(kernel, verifier, controller, current, "current")
        envelope = self.approve_supersession(kernel, verifier, controller, current, replacement, "exact")

        decision = controller.supersede(
            current,
            replacement,
            envelope,
            operator_principal=OPERATOR,
        )

        self.assertEqual("allow", decision.outcome)
        self.assertEqual(
            "directive_superseded",
            state.directive_status(current.directive_id, current.version, current.directive_hash),
        )
        self.assertEqual(
            "active",
            state.directive_status(replacement.directive_id, replacement.version, replacement.directive_hash),
        )
        event = [record for record in state.audit if record["event"] == "directive_superseded"][-1]
        self.assertEqual(current.directive_hash, event["payload"]["superseded_directive_hash"])
        self.assertEqual(replacement.directive_hash, event["payload"]["replacement_directive_hash"])
        self.assertEqual(
            replacement.directive_hash,
            event["payload"]["authority_evidence"]["replacement_directive_hash"],
        )
        self.assertEqual(
            current.directive_hash,
            event["payload"]["authority_evidence"]["superseded_directive_hash"],
        )

    def test_superseded_directive_cannot_authorize_or_spend_preissued_permit(self):
        state = InMemoryKernelState()
        current = directive()
        replacement = directive(version=2, issued_at_ns=1_100_000, max_cost=4)
        kernel, verifier, controller = self.governed(state)
        self.activate(kernel, verifier, controller, current, "current")
        projection = GovernedDirectiveProjection(kernel)
        intent = Intent("agent:builder", "write", "repo:file", 1)

        old_decision = projection.evaluate(intent, current)
        self.assertEqual("allow", old_decision.outcome)
        self.assertIsNotNone(old_decision.permit)

        envelope = self.approve_supersession(kernel, verifier, controller, current, replacement, "exact")
        self.assertEqual(
            "allow",
            controller.supersede(
                current,
                replacement,
                envelope,
                operator_principal=OPERATOR,
            ).outcome,
        )

        stale = projection.evaluate(intent, current)
        self.assertEqual(("deny", "directive_superseded"), (stale.outcome, stale.reason))
        self.assertFalse(kernel.consume(old_decision.permit, intent))
        rejected = [record for record in state.audit if record["event"] == "permit_rejected"][-1]
        self.assertEqual("directive_superseded", rejected["payload"]["directive_status"])

        replacement_decision = projection.evaluate(intent, replacement)
        self.assertEqual("allow", replacement_decision.outcome)
        self.assertTrue(kernel.consume(replacement_decision.permit, intent))

    def test_supersession_and_preissued_permit_denial_survive_restart(self):
        with tempfile.NamedTemporaryFile() as handle:
            state = SQLiteKernelState(handle.name)
            current = directive()
            replacement = directive(version=2, issued_at_ns=1_100_000, max_cost=4)
            kernel, verifier, controller = self.governed(state)
            self.activate(kernel, verifier, controller, current, "current")
            projection = GovernedDirectiveProjection(kernel)
            intent = Intent("agent:builder", "write", "repo:file", 1)
            old_decision = projection.evaluate(intent, current)
            self.assertEqual("allow", old_decision.outcome)

            envelope = self.approve_supersession(kernel, verifier, controller, current, replacement, "exact")
            self.assertEqual(
                "allow",
                controller.supersede(
                    current,
                    replacement,
                    envelope,
                    operator_principal=OPERATOR,
                ).outcome,
            )
            state.close()

            restarted = SQLiteKernelState(handle.name)
            restarted_kernel, _, _ = self.governed(restarted)
            restarted_projection = GovernedDirectiveProjection(restarted_kernel)
            self.assertEqual(
                "directive_superseded",
                restarted_projection.evaluate(intent, current).reason,
            )
            self.assertFalse(restarted_kernel.consume(old_decision.permit, intent))
            rejected = [record for record in restarted.audit if record["event"] == "permit_rejected"][-1]
            self.assertEqual("directive_superseded", rejected["payload"]["directive_status"])
            self.assertEqual(
                "allow",
                restarted_projection.evaluate(intent, replacement).outcome,
            )
            self.assertTrue(restarted_kernel.verify_audit())
            restarted.close()

    def test_child_of_superseded_parent_and_preissued_child_permit_fail_closed(self):
        state = InMemoryKernelState()
        parent = directive()
        parent_replacement = directive(version=2, issued_at_ns=1_100_000, max_cost=4)
        derived = child(parent)
        kernel, verifier, controller = self.governed(state)
        self.activate(kernel, verifier, controller, parent, "parent")
        self.activate(kernel, verifier, controller, derived, "child", parent=parent)
        projection = GovernedDirectiveProjection(kernel)
        intent = Intent("agent:builder", "write", "repo:service:file", 1)
        child_decision = projection.evaluate(intent, derived)
        self.assertEqual("allow", child_decision.outcome)

        envelope = self.approve_supersession(
            kernel,
            verifier,
            controller,
            parent,
            parent_replacement,
            "parent",
        )
        self.assertEqual(
            "allow",
            controller.supersede(
                parent,
                parent_replacement,
                envelope,
                operator_principal=OPERATOR,
            ).outcome,
        )

        denied = projection.evaluate(intent, derived)
        self.assertEqual(("deny", "directive_parent_superseded"), (denied.outcome, denied.reason))
        self.assertFalse(kernel.consume(child_decision.permit, intent))
        rejected = [record for record in state.audit if record["event"] == "permit_rejected"][-1]
        self.assertEqual("directive_parent_superseded", rejected["payload"]["directive_status"])

    def test_replacement_must_preserve_lineage_identity_and_advance_version(self):
        state = InMemoryKernelState()
        current = directive()
        kernel, verifier, controller = self.governed(state)
        self.activate(kernel, verifier, controller, current, "current")

        cases = [
            (directive(directive_id="other", version=2), "directive_lineage_mismatch"),
            (directive(version=1, max_cost=4), "directive_replacement_version_not_newer"),
            (directive(version=2, issuer_authority_id="authority:other"), "directive_replacement_issuer_mismatch"),
            (directive(version=2, principal="agent:other"), "directive_replacement_principal_mismatch"),
            (
                directive(version=2, parent_directive_hash="f" * 64),
                "directive_replacement_parent_mismatch",
            ),
        ]
        for index, (replacement, expected) in enumerate(cases, start=1):
            with self.subTest(expected=expected):
                envelope = self.approve_supersession(
                    kernel,
                    verifier,
                    controller,
                    current,
                    replacement,
                    f"case-{index}",
                )
                decision = controller.supersede(
                    current,
                    replacement,
                    envelope,
                    operator_principal=OPERATOR,
                )
                self.assertEqual(("deny", expected), (decision.outcome, decision.reason))
                self.assertEqual(
                    "active",
                    state.directive_status(current.directive_id, current.version, current.directive_hash),
                )

    def test_independent_directive_ids_do_not_gain_implicit_cross_lineage_precedence(self):
        state = InMemoryKernelState()
        first = directive(directive_id="lineage-a")
        second = directive(directive_id="lineage-b")
        kernel, verifier, controller = self.governed(state)
        self.activate(kernel, verifier, controller, first, "first")
        self.activate(kernel, verifier, controller, second, "second")

        self.assertEqual("active", state.directive_status(first.directive_id, first.version, first.directive_hash))
        self.assertEqual("active", state.directive_status(second.directive_id, second.version, second.directive_hash))

    def test_sqlite_existing_directive_table_migrates_supersession_column(self):
        with tempfile.NamedTemporaryFile() as handle:
            connection = sqlite3.connect(handle.name)
            connection.executescript("""
                CREATE TABLE directives (
                    directive_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    directive_hash TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
                    PRIMARY KEY (directive_id, version)
                );
            """)
            connection.close()

            state = SQLiteKernelState(handle.name)
            columns = {
                row[1]
                for row in state._connection.execute("PRAGMA table_info(directives)").fetchall()
            }
            self.assertIn("superseded_by_hash", columns)
            state.close()


if __name__ == "__main__":
    unittest.main()

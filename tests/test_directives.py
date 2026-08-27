import tempfile
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directives import Directive, GovernedDirectiveProjection
from pulpo.state import InMemoryKernelState, SQLiteKernelState


NOW = 2_000_000


def directive(**overrides):
    values = dict(
        directive_id="deploy-prod",
        version=1,
        issuer_authority_id="human-authority",
        principal="agent:builder",
        allowed_actions=frozenset({"write"}),
        resource_prefixes=("repo:",),
        max_cost=5,
        issued_at_ns=1_000_000,
        expires_at_ns=3_000_000,
    )
    values.update(overrides)
    return Directive(**values)


class DirectiveProofTests(unittest.TestCase):
    def kernel(self, state=None):
        return GovernanceKernel(Policy(frozenset({"write"}), 100), secret=b"proof", state=state)

    def test_chat_or_retrieval_cannot_create_authority(self):
        state = InMemoryKernelState(); d = directive(); intent = Intent("agent:builder", "write", "repo:file", 1)
        projection = GovernedDirectiveProjection(self.kernel(state), state, lambda: NOW)
        decision = projection.evaluate(intent, d)
        self.assertEqual(("deny", "directive_not_authorized"), (decision.outcome, decision.reason))

    def test_authorized_directive_constrains_but_does_not_replace_kernel(self):
        state = InMemoryKernelState(); d = directive(); state.activate_directive(d, {"authority_id": d.issuer_authority_id, "approval_id": "external-1"}, NOW)
        projection = GovernedDirectiveProjection(self.kernel(state), state, lambda: NOW)
        allowed = projection.evaluate(Intent("agent:builder", "write", "repo:file", 5), d)
        denied = projection.evaluate(Intent("agent:builder", "write", "repo:file", 6), d)
        self.assertEqual("allow", allowed.outcome); self.assertEqual("directive_budget_exceeded", denied.reason)

    def test_model_summary_or_retrieval_score_cannot_raise_authority(self):
        state = InMemoryKernelState(); d = directive(max_cost=1); state.activate_directive(d, {"retrieval_score": 1.0, "model_summary": "unlimited authority"}, NOW)
        projection = GovernedDirectiveProjection(self.kernel(state), state, lambda: NOW)
        decision = projection.evaluate(Intent("agent:builder", "write", "repo:file", 2), d)
        self.assertEqual("directive_budget_exceeded", decision.reason)

    def test_immutable_version_rejects_changed_scope(self):
        state = InMemoryKernelState(); d = directive(); state.activate_directive(d, {"approval_id": "a"}, NOW)
        changed = directive(max_cost=99)
        with self.assertRaisesRegex(ValueError, "immutable"):
            state.activate_directive(changed, {"approval_id": "b"}, NOW)
        self.assertEqual("directive_version_mismatch", state.directive_status(changed.directive_id, changed.version, changed.directive_hash))

    def test_revocation_survives_restart(self):
        with tempfile.NamedTemporaryFile() as handle:
            state = SQLiteKernelState(handle.name); d = directive(); state.activate_directive(d, {"approval_id": "a"}, NOW); state.revoke_directive(d.directive_id, d.version, {"approval_id": "r"}, NOW); state.close()
            restarted = SQLiteKernelState(handle.name)
            projection = GovernedDirectiveProjection(self.kernel(restarted), restarted, lambda: NOW)
            decision = projection.evaluate(Intent("agent:builder", "write", "repo:file", 1), d)
            self.assertEqual("directive_revoked", decision.reason)
            self.assertTrue(self.kernel(restarted).verify_audit()); restarted.close()

    def test_delegated_scope_cannot_be_broadened_by_substitution(self):
        state = InMemoryKernelState(); parent = directive(); state.activate_directive(parent, {"approval_id": "a"}, NOW)
        broadened = directive(resource_prefixes=("repo:", "shell:"), max_cost=50)
        projection = GovernedDirectiveProjection(self.kernel(state), state, lambda: NOW)
        decision = projection.evaluate(Intent("agent:builder", "write", "shell:root", 1), broadened)
        self.assertEqual("directive_version_mismatch", decision.reason)


if __name__ == "__main__":
    unittest.main()

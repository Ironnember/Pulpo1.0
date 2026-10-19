import unittest

from pulpo import GovernanceKernel, Policy
from pulpo.directives import Directive, DirectiveAuthorityController
from pulpo.state import InMemoryKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 2_000_000
OPERATOR = "operator:owner"


class ParentRevokesAtMutationState(InMemoryKernelState):
    """Simulate a parent revocation after precheck but at activation mutation."""

    def __init__(self):
        super().__init__()
        self.watched_parent_hash = None
        self.parent_checks = 0

    def directive_hash_status(self, directive_hash: str) -> str:
        if directive_hash == self.watched_parent_hash:
            self.parent_checks += 1
            if self.parent_checks == 2:
                for (directive_id, version), (digest, revoked) in list(self._directives.items()):
                    if digest == directive_hash and not revoked:
                        self.revoke_directive(
                            directive_id,
                            version,
                            {"test_race": True, "authority_effect": "none"},
                            NOW,
                        )
                        break
        return super().directive_hash_status(directive_hash)


class DirectiveParentActivationRaceTests(unittest.TestCase):
    def governed(self, state):
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"write", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(verifier),
        )
        kernel = GovernanceKernel(
            policy,
            secret=b"directive-parent-race",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        return kernel, verifier, DirectiveAuthorityController(kernel)

    def approve(self, kernel, verifier, controller, directive, approval_id):
        intent = controller.authority_intent(
            controller.ACTIVATE,
            directive,
            operator_principal=OPERATOR,
        )
        return signed_envelope(
            kernel,
            intent,
            verifier,
            now_ns=NOW - 10,
            approval_id=approval_id,
            nonce=f"{approval_id}-nonce",
        )

    def test_parent_revoked_between_precheck_and_mutation_denies_child(self):
        state = ParentRevokesAtMutationState()
        kernel, verifier, controller = self.governed(state)
        parent = Directive(
            directive_id="parent",
            version=1,
            issuer_authority_id="authority:test-owner",
            principal="agent:builder",
            allowed_actions=frozenset({"write"}),
            resource_prefixes=("repo:",),
            max_cost=5,
            issued_at_ns=1_000_000,
            expires_at_ns=3_000_000,
        )
        parent_approval = self.approve(kernel, verifier, controller, parent, "activate-parent")
        self.assertEqual(
            "allow",
            controller.activate(parent, parent_approval, operator_principal=OPERATOR).outcome,
        )

        child = Directive(
            directive_id="child",
            version=1,
            issuer_authority_id=parent.issuer_authority_id,
            principal=parent.principal,
            allowed_actions=frozenset({"write"}),
            resource_prefixes=("repo:service:",),
            max_cost=3,
            issued_at_ns=1_200_000,
            expires_at_ns=2_800_000,
            parent_directive_hash=parent.directive_hash,
        )
        state.watched_parent_hash = parent.directive_hash
        child_approval = self.approve(kernel, verifier, controller, child, "activate-child")
        decision = controller.activate(
            child,
            child_approval,
            operator_principal=OPERATOR,
            parent_directive=parent,
        )

        self.assertEqual(
            ("deny", "directive_parent_inactive_at_activation"),
            (decision.outcome, decision.reason),
        )
        self.assertEqual(
            "directive_not_authorized",
            state.directive_status(child.directive_id, child.version, child.directive_hash),
        )
        self.assertEqual("directive_parent_revoked", state.directive_hash_status(parent.directive_hash))
        activated = [
            record
            for record in state.audit
            if record["event"] == "directive_activated"
            and record["payload"]["directive_id"] == child.directive_id
        ]
        self.assertEqual([], activated)
        self.assertTrue(kernel.verify_audit())


if __name__ == "__main__":
    unittest.main()

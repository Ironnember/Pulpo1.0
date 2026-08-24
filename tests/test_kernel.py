import unittest

from pulpo import AgentGrant, GovernanceKernel, Intent, Policy
from pulpo.profiles import ESSENTIAL_AGENT_GRANTS, ESSENTIAL_PLUGIN_PROFILES


class GovernanceKernelTests(unittest.TestCase):
    def setUp(self):
        self.kernel = GovernanceKernel(
            Policy(frozenset({"read", "write", "push"}), 100, frozenset({"push"})),
            secret=b"test-secret",
        )

    def test_allowed_intent_gets_bound_one_use_permit(self):
        intent = Intent("agent", "write", "repo:file", 10)
        decision = self.kernel.evaluate(intent)
        self.assertEqual("allow", decision.outcome)
        self.assertTrue(self.kernel.consume(decision.permit, intent))
        self.assertFalse(self.kernel.consume(decision.permit, intent))

    def test_permit_cannot_be_used_for_different_intent(self):
        first = Intent("agent", "read", "repo:a")
        second = Intent("agent", "read", "repo:b")
        decision = self.kernel.evaluate(first)
        self.assertFalse(self.kernel.consume(decision.permit, second))

    def test_fail_closed_policy_boundaries(self):
        self.assertEqual("deny", self.kernel.evaluate(Intent("agent", "delete", "repo", 0)).outcome)
        self.assertEqual("deny", self.kernel.evaluate(Intent("agent", "write", "repo", 101)).outcome)
        self.assertEqual("deny", self.kernel.evaluate(Intent("", "read", "repo", 0)).outcome)
        self.assertEqual("deny", self.kernel.evaluate(Intent("agent", "read", "repo", 0, "")).outcome)

    def test_approval_is_explicit(self):
        intent = Intent("agent", "push", "origin/main", 0)
        self.assertEqual("require_approval", self.kernel.evaluate(intent).outcome)

    def test_audit_chain_detects_tampering(self):
        self.kernel.evaluate(Intent("agent", "read", "repo"))
        self.assertTrue(self.kernel.verify_audit())
        self.kernel.audit[0]["payload"]["reason"] = "changed"
        self.assertFalse(self.kernel.verify_audit())

    def test_agent_grants_fail_closed_for_unknown_principal(self):
        actions = frozenset().union(*(grant.allowed_actions for grant in ESSENTIAL_AGENT_GRANTS))
        kernel = GovernanceKernel(
            Policy(actions, 100, agent_grants=ESSENTIAL_AGENT_GRANTS),
            secret=b"test-secret",
        )
        decision = kernel.evaluate(Intent("agent:unknown", "read", "repo:README.md"))
        self.assertEqual(("deny", "unknown_principal"), (decision.outcome, decision.reason))

    def test_agent_role_cannot_expand_its_action_or_resource(self):
        actions = frozenset().union(*(grant.allowed_actions for grant in ESSENTIAL_AGENT_GRANTS))
        kernel = GovernanceKernel(
            Policy(actions, 3_000, agent_grants=ESSENTIAL_AGENT_GRANTS),
            secret=b"test-secret",
        )
        action = kernel.evaluate(Intent("agent:planner", "write", "repo:README.md"))
        resource = kernel.evaluate(Intent("agent:builder", "read", "evidence:audit"))
        self.assertEqual("agent_action_not_allowed", action.reason)
        self.assertEqual("agent_resource_not_allowed", resource.reason)

    def test_github_access_is_read_only_and_role_scoped(self):
        actions = frozenset().union(*(grant.allowed_actions for grant in ESSENTIAL_AGENT_GRANTS))
        kernel = GovernanceKernel(Policy(actions, 100, agent_grants=ESSENTIAL_AGENT_GRANTS), secret=b"test-secret")
        planner_read = kernel.evaluate(Intent("agent:planner", "read", "plugin:github:Ironnember/Pulpo1.0"))
        builder_read = kernel.evaluate(Intent("agent:builder", "read", "plugin:github:Ironnember/Pulpo1.0"))
        planner_write = kernel.evaluate(Intent("agent:planner", "write", "plugin:github:Ironnember/Pulpo1.0"))
        self.assertEqual("allow", planner_read.outcome)
        self.assertEqual("agent_resource_not_allowed", builder_read.reason)
        self.assertEqual("agent_action_not_allowed", planner_write.reason)

    def test_agent_budget_is_stricter_than_global_budget(self):
        grant = AgentGrant("agent:small", frozenset({"read"}), ("repo:",), 5)
        kernel = GovernanceKernel(Policy(frozenset({"read"}), 100, agent_grants=(grant,)), secret=b"test-secret")
        decision = kernel.evaluate(Intent("agent:small", "read", "repo:file", 6))
        self.assertEqual(("deny", "agent_budget_exceeded"), (decision.outcome, decision.reason))

    def test_malformed_or_duplicate_agent_grants_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "resource prefixes"):
            AgentGrant("agent:bad", frozenset({"read"}), ("",), 1)
        grant = AgentGrant("agent:same", frozenset({"read"}), ("repo:",), 1)
        with self.assertRaisesRegex(ValueError, "unique"):
            Policy(frozenset({"read"}), 10, agent_grants=(grant, grant))
        with self.assertRaisesRegex(ValueError, "subset"):
            Policy(
                frozenset({"read"}),
                10,
                agent_grants=(AgentGrant("agent:writer", frozenset({"write"}), ("repo:",), 1),),
            )

    def test_default_profiles_do_not_create_an_approver_agent(self):
        principals = {grant.principal for grant in ESSENTIAL_AGENT_GRANTS}
        actions = set().union(*(grant.allowed_actions for grant in ESSENTIAL_AGENT_GRANTS))
        self.assertNotIn("agent:approver", principals)
        self.assertNotIn("push", actions)
        self.assertNotIn("deploy", actions)
        commerce = next(grant for grant in ESSENTIAL_AGENT_GRANTS if grant.principal == "agent:commerce")
        self.assertEqual((frozenset({"purchase_domain"}), 3_000), (commerce.allowed_actions, commerce.max_cost))

    def test_plugin_profiles_are_declarations_not_connection_claims(self):
        ids = {profile.plugin_id for profile in ESSENTIAL_PLUGIN_PROFILES}
        self.assertEqual({"github", "sentry", "cloudflare"}, ids)
        self.assertTrue(all(profile.write_requires_approval for profile in ESSENTIAL_PLUGIN_PROFILES))


if __name__ == "__main__":
    unittest.main()

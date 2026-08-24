import unittest

from pulpo import GovernanceKernel, Intent, Policy


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

    def test_approval_is_explicit(self):
        intent = Intent("agent", "push", "origin/main", 0)
        self.assertEqual("require_approval", self.kernel.evaluate(intent).outcome)
        self.assertEqual("allow", self.kernel.evaluate(intent, approved=True).outcome)

    def test_audit_chain_detects_tampering(self):
        self.kernel.evaluate(Intent("agent", "read", "repo"))
        self.assertTrue(self.kernel.verify_audit())
        self.kernel.audit[0]["payload"]["reason"] = "changed"
        self.assertFalse(self.kernel.verify_audit())


if __name__ == "__main__":
    unittest.main()

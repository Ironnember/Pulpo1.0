import ast
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pulpo import GovernanceKernel, Intent, Policy
from pulpo.directive_memory_surface import (
    DirectiveMemorySkillProjection,
    freeze_directive_memory_snapshot,
)
from pulpo.directive_memory_transport import build_directive_memory_request
from pulpo.directives import Directive, DirectiveAuthorityController, GovernedDirectiveProjection
from pulpo.state import InMemoryKernelState, SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


NOW = 2_000_000
OPERATOR = "operator:owner"
ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "skill-host" / "directive_memory_host.py"


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


class DirectiveMemorySkillHostTests(unittest.TestCase):
    def governed(self, state=None):
        verifier = HmacTestVerifier()
        policy = Policy(
            frozenset({"write", "activate_directive", "revoke_directive"}),
            100,
            frozenset({"activate_directive", "revoke_directive"}),
            authority_trust=trust_for(verifier),
        )
        kernel = GovernanceKernel(
            policy,
            secret=b"directive-memory-host-proof",
            approval_verifier=verifier,
            clock=lambda: NOW,
            state=state,
        )
        return kernel, verifier

    def approve(self, kernel, verifier, operation, d, approval_id, nonce):
        intent = DirectiveAuthorityController.authority_intent(
            operation,
            d,
            operator_principal=OPERATOR,
        )
        return signed_envelope(
            kernel,
            intent,
            verifier,
            now_ns=NOW - 10,
            approval_id=approval_id,
            nonce=nonce,
        )

    def activate(self, state, d):
        kernel, verifier = self.governed(state)
        controller = DirectiveAuthorityController(kernel)
        envelope = self.approve(
            kernel,
            verifier,
            controller.ACTIVATE,
            d,
            "activate-host-1",
            "activate-host-nonce-1",
        )
        decision = controller.activate(d, envelope, operator_principal=OPERATOR)
        self.assertEqual("allow", decision.outcome)
        return kernel, verifier, controller

    def run_host(self, payload: bytes):
        completed = subprocess.run(
            [sys.executable, "-I", str(HOST)],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=ROOT,
            env={},
            check=False,
        )
        return completed, json.loads(completed.stdout)

    def test_host_source_imports_only_stdlib_and_has_no_pulpo_import(self):
        source = HOST.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
        self.assertEqual({"__future__", "hashlib", "json", "sys", "typing"}, imported_roots)
        self.assertNotIn("from pulpo", source)
        self.assertNotIn("import pulpo", source)

    def test_isolated_host_matches_trusted_frozen_projection_without_mutation(self):
        state = InMemoryKernelState()
        d = directive()
        kernel, _, _ = self.activate(state, d)
        audit_before = list(state.audit)
        snapshot = freeze_directive_memory_snapshot(kernel, d)
        trusted = DirectiveMemorySkillProjection(snapshot).propose_intent(
            action="write",
            resource="repo:file",
            cost=3,
            session_id="skill-test",
        )
        payload = build_directive_memory_request(
            snapshot,
            operation="propose",
            action="write",
            resource="repo:file",
            cost=3,
            session_id="skill-test",
        )

        completed, response = self.run_host(payload)

        self.assertEqual(0, completed.returncode, completed.stderr.decode())
        self.assertEqual(trusted["intent_hash"], response["intent_hash"])
        self.assertEqual(trusted["directive_hash"], response["directive_hash"])
        self.assertEqual(trusted["frozen_scope_match"], response["frozen_scope_match"])
        self.assertEqual("not_asserted", response["authority"])
        self.assertEqual("none", response["authority_effect"])
        self.assertEqual("none", response["governed_effect"])
        self.assertFalse(response["canonical_state_mutation"])
        self.assertTrue(response["requires_canonical_revalidation"])
        self.assertEqual(audit_before, state.audit)

    def test_inspection_crosses_json_only_and_exposes_no_runtime_capability_fields(self):
        state = InMemoryKernelState()
        d = directive()
        kernel, _, _ = self.activate(state, d)
        snapshot = freeze_directive_memory_snapshot(kernel, d)
        payload = build_directive_memory_request(snapshot, operation="inspect")

        request = json.loads(payload)
        encoded = payload.decode("utf-8")
        for forbidden in (
            "kernel",
            "authority_client",
            "approval_verifier",
            "executor",
            "ledger",
            "permit",
            "secret",
            "credential",
        ):
            self.assertNotIn(forbidden, request)
            self.assertNotIn(f'"{forbidden}"', encoded)

        completed, response = self.run_host(payload)
        self.assertEqual(0, completed.returncode, completed.stderr.decode())
        self.assertEqual("pulpo.directive-memory-skill-inspection.v0", response["schema"])
        self.assertEqual("frozen", response["freshness"])
        self.assertEqual("not_asserted", response["authority"])
        self.assertFalse(response["canonical_state_mutation"])

    def test_injected_capability_fields_fail_closed(self):
        kernel, _, _ = self.activate(InMemoryKernelState(), directive())
        snapshot = freeze_directive_memory_snapshot(kernel, directive())
        request = json.loads(build_directive_memory_request(snapshot, operation="inspect"))

        for field in ("kernel", "authority_client", "executor", "ledger"):
            with self.subTest(field=field):
                hostile = dict(request)
                hostile[field] = {"pretend": True}
                completed, response = self.run_host(
                    json.dumps(hostile, sort_keys=True, separators=(",", ":")).encode()
                )
                self.assertEqual(2, completed.returncode)
                self.assertEqual("pulpo.directive-memory-skill-error.v0", response["schema"])
                self.assertEqual("directive_memory_request_fields_invalid", response["reason"])
                self.assertEqual("not_asserted", response["authority"])
                self.assertEqual("none", response["authority_effect"])
                self.assertEqual("none", response["governed_effect"])
                self.assertFalse(response["canonical_state_mutation"])

    def test_broadening_through_host_is_non_authoritative_failure(self):
        state = InMemoryKernelState()
        d = directive(max_cost=5)
        kernel, _, _ = self.activate(state, d)
        audit_before = list(state.audit)
        snapshot = freeze_directive_memory_snapshot(kernel, d)
        payload = build_directive_memory_request(
            snapshot,
            operation="propose",
            action="write",
            resource="repo:file",
            cost=50,
        )

        completed, response = self.run_host(payload)

        self.assertEqual(0, completed.returncode, completed.stderr.decode())
        self.assertFalse(response["frozen_scope_match"])
        self.assertEqual("directive_budget_exceeded", response["frozen_scope_reason"])
        self.assertEqual("not_asserted", response["authority"])
        self.assertTrue(response["requires_canonical_revalidation"])
        self.assertEqual(audit_before, state.audit)

    def test_stale_host_snapshot_cannot_override_live_revocation_after_restart(self):
        with tempfile.NamedTemporaryFile() as handle:
            state = SQLiteKernelState(handle.name)
            d = directive()
            kernel, verifier, controller = self.activate(state, d)
            snapshot = freeze_directive_memory_snapshot(kernel, d)
            payload = build_directive_memory_request(
                snapshot,
                operation="propose",
                action="write",
                resource="repo:file",
                cost=1,
            )

            revoke_envelope = self.approve(
                kernel,
                verifier,
                controller.REVOKE,
                d,
                "revoke-host-1",
                "revoke-host-nonce-1",
            )
            revoke = controller.revoke(d, revoke_envelope, operator_principal=OPERATOR)
            self.assertEqual("allow", revoke.outcome)
            state.close()

            restarted = SQLiteKernelState(handle.name)
            restarted_kernel, _ = self.governed(restarted)
            live = GovernedDirectiveProjection(restarted_kernel).evaluate(
                Intent("agent:builder", "write", "repo:file", 1),
                d,
            )
            completed, stale = self.run_host(payload)

            self.assertEqual(0, completed.returncode, completed.stderr.decode())
            self.assertEqual(("deny", "directive_revoked"), (live.outcome, live.reason))
            self.assertTrue(stale["frozen_scope_match"])
            self.assertEqual("frozen", stale["freshness"])
            self.assertEqual("not_asserted", stale["authority"])
            self.assertTrue(stale["requires_canonical_revalidation"])
            self.assertTrue(restarted_kernel.verify_audit())
            restarted.close()


if __name__ == "__main__":
    unittest.main()

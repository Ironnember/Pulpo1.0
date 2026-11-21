"""Bounded hostile task-injection proof; real provider and human proof excluded."""
from __future__ import annotations

from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "proofs/agent-task-injection/synthetic_task_injection_proof.py"

REQUIRED_OS_CASES = {
    "worker_reaches_custody_unix_socket",
    "unrestricted_positive_control_reaches_alternate_unix",
    "sandbox_worker_cannot_reach_other_unix_socket",
    "worker_environment_has_no_provider_or_authority_credentials",
    "unrestricted_positive_control_reaches_fake_provider",
    "sandbox_worker_direct_provider_raw_ip_denied",
    "sandbox_worker_direct_provider_localhost_denied",
    "unrestricted_positive_control_reads_dummy",
    "sandbox_worker_cannot_read_protected_dummy",
    "unrestricted_positive_control_can_write_test_file",
    "sandbox_worker_cannot_write_filesystem",
    "sandbox_worker_shell_cannot_bypass_file_write_denial",
    "no_approval_cannot_create_synthetic_effect",
    "worker_claimed_authority_without_valid_permit_denied",
    "malicious_task_cannot_change_policy_or_inject_authority",
    "worker_cannot_mint_approvals_via_public_socket",
    "valid_permit_cannot_be_retargeted",
    "untrusted_prompt_field_cannot_expand_exact_permit",
    "valid_exact_fixture_approval_allows_one_effect",
    "consumed_permit_replay_denied",
    "worker_fabricated_success_cannot_ratify_consequence",
    "protected_state_audit_valid_before_restart",
    "canonical_state_reloads_after_process_restart",
    "permit_replay_after_full_custody_process_restart_denied",
    "canonical_audit_and_effect_still_exact",
}


def load_proof():
    spec = importlib.util.spec_from_file_location("pulpo_task_injection_proof", PROOF)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class BoundedHostileTaskInjectionTests(unittest.TestCase):
    def test_underlying_kernel_denies_fake_authority_mismatch_replay_and_restart(self):
        proof = load_proof()
        with tempfile.TemporaryDirectory(prefix="pulpo-injection-kernel-") as tmp:
            from pulpo import SQLiteKernelState
            from pulpo.targets import evaluate_locked_target_with_approval
            from tests.authority_support import HmacTestVerifier, signed_envelope

            secret = b"synthetic-test-only-secret-not-production"
            clock = proof.incident.ManualClock()
            verifier = HmacTestVerifier()
            db_path = Path(tmp) / "kernel.sqlite3"
            kernel, state = proof.incident.make_kernel(db_path, clock, verifier, secret)
            try:
                target = kernel.lock_target("fixture-injected-target", proof.INTENT)
                preapproval = kernel.evaluate(proof.INTENT)
                self.assertEqual("require_approval", preapproval.outcome)
                self.assertIsNone(preapproval.permit)
                envelope = signed_envelope(
                    kernel, proof.INTENT, verifier,
                    now_ns=proof.incident.START_NS - 10,
                    approval_id="fixture-injection", nonce="nonce-injection",
                )
                forged = replace(envelope, signature="00" * 32)
                _, denied = evaluate_locked_target_with_approval(
                    kernel, target.target_id, target.target_hash, forged
                )
                self.assertEqual(("deny", "approval_signature_invalid"),
                                 (denied.outcome, denied.reason))
                _, approved = evaluate_locked_target_with_approval(
                    kernel, target.target_id, target.target_hash, envelope
                )
                self.assertEqual("allow", approved.outcome)
                self.assertIsNotNone(approved.permit)
                bad = replace(proof.INTENT, action="install_ssh_key",
                              resource="privileged:host")
                self.assertFalse(kernel.consume(approved.permit, bad))
                self.assertTrue(kernel.consume(approved.permit, proof.INTENT))
                self.assertFalse(kernel.consume(approved.permit, proof.INTENT))
                self.assertTrue(kernel.verify_audit())
            finally:
                state.close()
            kernel2, state2 = proof.incident.make_kernel(db_path, clock, verifier, secret)
            try:
                self.assertFalse(kernel2.consume(approved.permit, proof.INTENT))
                self.assertTrue(kernel2.verify_audit())
            finally:
                state2.close()

    @unittest.skipUnless(
        sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file(),
        "macOS Seatbelt-specific worker-network and protected-file negative tests",
    )
    def test_sandboxed_worker_cannot_bypass_kernel_and_provider_boundary(self):
        with tempfile.TemporaryDirectory(prefix="pulpo-injection-evidence-") as tmp:
            output = Path(tmp) / "proof"
            proc = subprocess.run(
                [sys.executable, "-B", str(PROOF), "--output", str(output)],
                cwd=ROOT, capture_output=True, text=True, timeout=90,
                check=False,
            )
            self.assertEqual(0, proc.returncode, (proc.stdout, proc.stderr))
            report = json.loads((output / "result.json").read_text())
            self.assertEqual("PASS", report["result"])
            self.assertEqual(25, report["checks_passed"])
            self.assertEqual(25, report["checks_total"])
            self.assertEqual(
                REQUIRED_OS_CASES,
                {case["name"] for case in report["checks"]},
            )
            self.assertEqual(
                1, report["synthetic_provider_observation"]["effect_count"]
            )
            self.assertFalse(report["real_authenticator"])
            self.assertEqual(0, report["real_provider_connections"])
            self.assertTrue(all(
                case["status"] == "PASS" for case in report["checks"]
            ))


if __name__ == "__main__":
    unittest.main()

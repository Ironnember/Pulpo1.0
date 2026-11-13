"""End-to-end tests for the pulpo-ops operator CLI (pulpo/ops.py).

Every test drives ``pulpo.ops.main(argv)`` in-process against a deployment
directory in a TemporaryDirectory. The approval envelope is minted with the
test-only authority double in ``tests/authority_support.py`` — the same
step the operator quickstart describes as "your authority produces this
file" — using a throwaway kernel that carries the exact policy/trust the
CLI persisted at init time, so policy_hash / intent_hash line up.
"""

from __future__ import annotations

import contextlib
from dataclasses import asdict, replace
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from pulpo import (
    AuthorityTrust,
    GovernanceKernel,
    InMemoryKernelState,
    Intent,
    Policy,
)
from pulpo.ops import TEST_SECRET_ENV, main
from tests.authority_support import HmacTestVerifier, signed_envelope


SECRET_TEXT = "ops-cli-test-secret"
SECRET_BYTES = SECRET_TEXT.encode("utf-8")
ACTION = "deploy.release"
RESOURCE = "service:api"
PRINCIPAL = "alice"
DEPLOYMENT_ID = "deployment:test-ops"
SESSION_ID = "default"
ENVELOPE_TTL_NS = 60_000_000_000


class OpsCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pulpo-ops-")
        self.root = Path(self.temporary.name)
        self.deployment = self.root / "deployment"
        self.envelope_path = self.root / "envelope.json"
        self.env = mock.patch.dict(os.environ, {TEST_SECRET_ENV: SECRET_TEXT})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temporary.cleanup()

    # -- helpers ---------------------------------------------------------

    def run_cli(self, argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main([str(item) for item in argv])
        text = output.getvalue().strip()
        return exit_code, (json.loads(text) if text else {})

    def init_trusted(self):
        exit_code, report = self.run_cli(
            [
                "init",
                self.deployment,
                "--action",
                ACTION,
                "--max-cost",
                "1000",
                "--session-id",
                SESSION_ID,
                "--deployment-id",
                DEPLOYMENT_ID,
                "--authority-id",
                HmacTestVerifier.authority_id,
                "--verifier-id",
                HmacTestVerifier.verifier_id,
                "--key-id",
                HmacTestVerifier.key_id,
                "--algorithm",
                HmacTestVerifier.algorithm,
                "--key-fingerprint",
                HmacTestVerifier.key_fingerprint,
                "--verifier-kind",
                "hmac-test",
            ]
        )
        self.assertEqual(0, exit_code, report)
        self.assertTrue(report["authority_configured"])
        return report

    def init_trustless(self):
        exit_code, report = self.run_cli(
            [
                "init",
                self.deployment,
                "--action",
                ACTION,
                "--max-cost",
                "1000",
            ]
        )
        self.assertEqual(0, exit_code, report)
        self.assertFalse(report["authority_configured"])
        return report

    def deployment_policy(self):
        config = json.loads(
            (self.deployment / "policy.json").read_text(encoding="utf-8")
        )
        trust = AuthorityTrust(**config["authority_trust"])
        policy = Policy(
            allowed_actions=frozenset(config["allowed_actions"]),
            max_cost=config["max_cost"],
            approval_actions=frozenset(config["approval_actions"]),
            authority_trust=trust,
        )
        return config, policy

    def mint_envelope(self, intent, *, tamper_signature=False, **changes):
        _, policy = self.deployment_policy()
        verifier = HmacTestVerifier(secret=SECRET_BYTES)
        throwaway = GovernanceKernel(
            policy,
            approval_verifier=verifier,
            state=InMemoryKernelState(),
        )
        envelope = signed_envelope(
            throwaway,
            intent,
            verifier,
            now_ns=time.time_ns(),
            ttl_ns=ENVELOPE_TTL_NS,
            **changes,
        )
        if tamper_signature:
            envelope = replace(envelope, signature="0" * 64)
        self.envelope_path.write_text(
            json.dumps(asdict(envelope)), encoding="utf-8"
        )
        return envelope

    def intent(self, cost=100):
        return Intent(
            principal=PRINCIPAL,
            action=ACTION,
            resource=RESOURCE,
            cost=cost,
            session_id=SESSION_ID,
        )

    def authorize(self, cost=100):
        return self.run_cli(
            [
                "authorize",
                self.deployment,
                "--envelope",
                self.envelope_path,
                "--principal",
                PRINCIPAL,
                "--action",
                ACTION,
                "--resource",
                RESOURCE,
                "--cost",
                str(cost),
                "--session-id",
                SESSION_ID,
            ]
        )

    def consume(self, permit_path, cost=100):
        return self.run_cli(
            [
                "consume",
                self.deployment,
                "--permit-file",
                permit_path,
                "--principal",
                PRINCIPAL,
                "--action",
                ACTION,
                "--resource",
                RESOURCE,
                "--cost",
                str(cost),
                "--session-id",
                SESSION_ID,
            ]
        )

    def authorize_ok(self, cost=100):
        self.mint_envelope(self.intent(cost=cost))
        exit_code, report = self.authorize(cost=cost)
        self.assertEqual(0, exit_code, report)
        self.assertEqual("allow", report["outcome"])
        permit_path = Path(report["permit_path"])
        self.assertTrue(permit_path.is_file())
        return report, permit_path

    # -- tests -----------------------------------------------------------

    def test_end_to_end_hmac_flow(self):
        self.init_trusted()

        config, _ = self.deployment_policy()
        self.assertEqual("pulpo.ops-policy.v1", config["schema"])
        # The hmac-test secret never enters the deployment files: the file
        # records only the environment variable name.
        self.assertEqual(
            {"kind": "hmac-test", "secret_env": TEST_SECRET_ENV}, config["verifier"]
        )
        self.assertNotIn(SECRET_TEXT, (self.deployment / "policy.json").read_text())

        report, permit_path = self.authorize_ok()
        self.assertEqual(
            self.deployment
            / "permits"
            / f"{report['intent_hash']}--approval-1.permit",
            permit_path,
        )

        exit_code, consumed = self.consume(permit_path)
        self.assertEqual(0, exit_code, consumed)
        self.assertTrue(consumed["consumed"])

        exit_code, verification = self.run_cli(["verify", self.deployment])
        self.assertEqual(0, exit_code, verification)
        self.assertTrue(verification["chain_valid"])
        self.assertTrue(verification["ok"])

        exit_code, status = self.run_cli(["status", self.deployment])
        self.assertEqual(0, exit_code, status)
        self.assertTrue(status["chain_valid"])
        self.assertEqual(report["policy_hash"], status["policy_hash"])
        self.assertEqual(1, status["event_counts"]["permit_consumed"])
        self.assertEqual(1, status["event_counts"]["approval_verified"])
        self.assertEqual(0, status["event_counts"]["permit_rejected"])

    def test_tampered_envelope_signature_denies_without_permit(self):
        self.init_trusted()
        self.mint_envelope(self.intent(), tamper_signature=True)
        exit_code, report = self.authorize()
        self.assertNotEqual(0, exit_code)
        self.assertEqual("deny", report["outcome"])
        self.assertEqual("approval_signature_invalid", report["reason"])
        permits_dir = self.deployment / "permits"
        self.assertEqual([], list(permits_dir.glob("*.permit")))

    def test_permit_replay_second_consume_fails(self):
        self.init_trusted()
        _, permit_path = self.authorize_ok()
        exit_code, first = self.consume(permit_path)
        self.assertEqual(0, exit_code, first)
        self.assertTrue(first["consumed"])
        exit_code, second = self.consume(permit_path)
        self.assertNotEqual(0, exit_code)
        self.assertFalse(second["consumed"])
        exit_code, status = self.run_cli(["status", self.deployment])
        self.assertEqual(0, exit_code, status)
        self.assertEqual(1, status["event_counts"]["permit_consumed"])
        self.assertEqual(1, status["event_counts"]["permit_rejected"])

    def test_amount_substitution_consume_fails(self):
        self.init_trusted()
        _, permit_path = self.authorize_ok(cost=100)
        exit_code, report = self.consume(permit_path, cost=999)
        self.assertNotEqual(0, exit_code)
        self.assertFalse(report["consumed"])

    def test_trustless_authorize_fails_closed_without_state_mutation(self):
        self.init_trustless()
        self.envelope_path.write_text(
            json.dumps({"note": "no authority ever signed this"}), encoding="utf-8"
        )
        exit_code, report = self.authorize()
        self.assertNotEqual(0, exit_code)
        self.assertIn("authority trust not configured", report["error"])
        permits_dir = self.deployment / "permits"
        self.assertEqual([], list(permits_dir.glob("*.permit")))
        # The refusal happened before the kernel was opened: no audit
        # records were appended by the failed authorize.
        exit_code, status = self.run_cli(["status", self.deployment])
        self.assertEqual(0, exit_code, status)
        self.assertEqual(0, status["audit_records"])
        exit_code, verification = self.run_cli(["verify", self.deployment])
        self.assertEqual(0, exit_code, verification)
        self.assertTrue(verification["chain_valid"])

    def test_anchor_seam_reports_unavailable_in_this_build(self):
        # Arrange the pulpo.anchor (WS1) module's absence so the seam
        # branch that runs is the ImportError branch, whatever tree this
        # test executes in: both surfaces must say so plainly instead of
        # implying an anchored check happened.
        self.init_trusted()
        with mock.patch.dict(sys.modules, {"pulpo.anchor": None}):
            exit_code, status = self.run_cli(["status", self.deployment])
            self.assertEqual(0, exit_code, status)
            self.assertFalse(status["anchor"]["available"])
            self.assertIn("not available in this build", status["anchor"]["note"])

            exit_code, verification = self.run_cli(["verify", self.deployment])
            self.assertEqual(0, exit_code, verification)
            self.assertFalse(verification["anchored"]["available"])
            self.assertFalse(verification["anchored"]["checked"])
            self.assertIn(
                "not available in this build", verification["anchored"]["note"]
            )
            # An unavailable optional witness does not fail the chain check.
            self.assertTrue(verification["ok"])

    def test_anchor_seam_reports_available_without_anchor_file(self):
        # The companion posture once pulpo.anchor is present in the tree
        # (PR #352): the seam is live, no deployment anchor file exists
        # yet, and both surfaces say exactly that — available, unchecked,
        # and the chain verdict is unaffected.
        self.init_trusted()
        exit_code, status = self.run_cli(["status", self.deployment])
        self.assertEqual(0, exit_code, status)
        self.assertTrue(status["anchor"]["available"])
        self.assertFalse(status["anchor"]["present"])
        self.assertIsNone(status["anchor"]["last_anchor"])

        exit_code, verification = self.run_cli(["verify", self.deployment])
        self.assertEqual(0, exit_code, verification)
        self.assertTrue(verification["anchored"]["available"])
        self.assertFalse(verification["anchored"]["checked"])
        self.assertFalse(verification["anchored"]["present"])
        self.assertIn(
            "no anchor file present", verification["anchored"]["note"]
        )
        self.assertTrue(verification["ok"])

    def test_authorize_fails_closed_when_test_secret_env_missing(self):
        self.init_trusted()
        self.mint_envelope(self.intent())
        with mock.patch.dict(os.environ, {}, clear=True):
            exit_code, report = self.authorize()
        self.assertNotEqual(0, exit_code)
        self.assertIn(TEST_SECRET_ENV, report["error"])
        self.assertEqual(
            [], list((self.deployment / "permits").glob("*.permit"))
        )

    # -- Codex P1 regressions (PR #353 fix round) -------------------------

    def test_permit_artifacts_are_owner_only(self):
        # A permit file is a bearer artifact: under a typical umask 022
        # the permits directory must be 0700 and the file 0600, and
        # authorize must repair a directory loosened by an earlier init.
        previous_umask = os.umask(0o022)
        try:
            self.init_trusted()
            permits_dir = self.deployment / "permits"
            self.assertEqual(0o700, stat.S_IMODE(permits_dir.stat().st_mode))
            os.chmod(permits_dir, 0o755)  # simulate a pre-fix deployment
            _, permit_path = self.authorize_ok()
        finally:
            os.umask(previous_umask)
        self.assertEqual(0o700, stat.S_IMODE(permits_dir.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(permit_path.stat().st_mode))

    def test_distinct_approvals_same_intent_get_distinct_permit_files(self):
        self.init_trusted()
        _, first_path = self.authorize_ok()
        first_content = first_path.read_text(encoding="utf-8")
        self.mint_envelope(
            self.intent(), approval_id="approval-2", nonce="approval-nonce-2"
        )
        exit_code, report = self.authorize()
        self.assertEqual(0, exit_code, report)
        second_path = Path(report["permit_path"])
        self.assertNotEqual(first_path, second_path)
        self.assertIn("approval-2", second_path.name)
        files = list((self.deployment / "permits").glob("*.permit"))
        self.assertEqual({first_path, second_path}, set(files))
        # The first artifact was not overwritten, and its permit is still
        # live and consumable: inventory and kernel state agree that two
        # permits were issued for the intent.
        self.assertEqual(first_content, first_path.read_text(encoding="utf-8"))
        exit_code, consumed = self.consume(first_path)
        self.assertEqual(0, exit_code, consumed)
        self.assertTrue(consumed["consumed"])
        exit_code, status = self.run_cli(["status", self.deployment])
        self.assertEqual(0, exit_code, status)
        self.assertEqual(2, status["event_counts"]["approval_verified"])

    def test_authorize_preflights_permits_path_before_issuance(self):
        self.init_trusted()
        permits = self.deployment / "permits"
        permits.rmdir()
        permits.write_text("squatting file\n", encoding="utf-8")
        self.mint_envelope(self.intent())
        exit_code, report = self.authorize()
        self.assertNotEqual(0, exit_code)
        self.assertIn("permits", report["error"])
        # Nothing was issued: the refusal happened before the kernel
        # opened, so the audit chain is untouched and the same envelope
        # authorizes cleanly once the destination is repaired (no
        # approval_id_replayed dead end).
        exit_code, status = self.run_cli(["status", self.deployment])
        self.assertEqual(0, exit_code, status)
        self.assertEqual(0, status["audit_records"])
        permits.unlink()
        exit_code, report = self.authorize()
        self.assertEqual(0, exit_code, report)
        self.assertEqual("allow", report["outcome"])

    def test_persistence_failure_after_issuance_reports_recoverable_permit(self):
        self.init_trusted()
        envelope = self.mint_envelope(self.intent())
        # Squat on exactly the path authorize will write, with a
        # directory: the preflight probe (a different name) succeeds and
        # issuance commits, then the atomic create fails.
        target = (
            self.deployment
            / "permits"
            / f"{envelope.intent_hash}--{envelope.approval_id}.permit"
        )
        target.mkdir()
        exit_code, report = self.authorize()
        self.assertNotEqual(0, exit_code)
        self.assertFalse(report["permit_persisted"])
        permit = report["permit"]
        self.assertTrue(permit)
        # The issuance really happened (canonical state changed), and the
        # reported permit string is the genuine recoverable artifact:
        # stored by the operator, it consumes exactly once.
        exit_code, status = self.run_cli(["status", self.deployment])
        self.assertEqual(0, exit_code, status)
        self.assertEqual(1, status["event_counts"]["approval_verified"])
        recovered = self.root / "recovered.permit"
        recovered.write_text(permit + "\n", encoding="utf-8")
        exit_code, consumed = self.consume(recovered)
        self.assertEqual(0, exit_code, consumed)
        self.assertTrue(consumed["consumed"])

    # -- read-only projections never provision the kernel secret ----------

    def make_legacy(self):
        """A pre-kernel-secret deployment: governed history, no secret file.

        Deployments written before the secret file existed hold exactly
        policy.json, state.db, and permits/. Removing the file that init
        created reproduces that shape over real governed state.
        """
        self.init_trusted()
        _, permit_path = self.authorize_ok()
        exit_code, consumed = self.consume(permit_path)
        self.assertEqual(0, exit_code, consumed)
        self.assertTrue(consumed["consumed"])
        secret_path = self.deployment / "kernel-secret"
        secret_path.unlink()
        self.assertFalse(secret_path.exists())
        return secret_path

    def test_verify_status_on_legacy_deployment_create_no_secret(self):
        secret_path = self.make_legacy()
        before = sorted(path.name for path in self.deployment.rglob("*"))

        exit_code, verification = self.run_cli(["verify", self.deployment])
        self.assertEqual(0, exit_code, verification)
        self.assertTrue(verification["chain_valid"])
        self.assertTrue(verification["ok"])

        exit_code, status = self.run_cli(["status", self.deployment])
        self.assertEqual(0, exit_code, status)
        self.assertTrue(status["chain_valid"])
        self.assertEqual(1, status["event_counts"]["permit_consumed"])

        # Neither projection created the secret -- or anything else.
        self.assertFalse(secret_path.exists())
        self.assertEqual(
            before, sorted(path.name for path in self.deployment.rglob("*"))
        )

    def test_verify_status_succeed_on_readonly_legacy_deployment(self):
        # The read-only-mount case from Codex's P1 on PR #355: verify
        # used to fail here and report the (valid) chain as invalid,
        # because opening the kernel tried to create the secret file.
        secret_path = self.make_legacy()
        os.chmod(self.deployment, 0o500)
        try:
            exit_code, verification = self.run_cli(["verify", self.deployment])
            self.assertEqual(0, exit_code, verification)
            self.assertTrue(verification["chain_valid"])
            self.assertTrue(verification["ok"])
            exit_code, status = self.run_cli(["status", self.deployment])
            self.assertEqual(0, exit_code, status)
            self.assertTrue(status["chain_valid"])
        finally:
            os.chmod(self.deployment, 0o700)
        self.assertFalse(secret_path.exists())

    def test_verify_status_do_not_repair_loose_secret_permissions(self):
        self.init_trusted()
        secret_path = self.deployment / "kernel-secret"
        original = secret_path.read_bytes()
        os.chmod(secret_path, 0o644)

        exit_code, verification = self.run_cli(["verify", self.deployment])
        self.assertEqual(0, exit_code, verification)
        self.assertTrue(verification["ok"])
        exit_code, status = self.run_cli(["status", self.deployment])
        self.assertEqual(0, exit_code, status)
        self.assertTrue(status["chain_valid"])

        # Unrepaired and untouched: the projections are read-only.
        self.assertEqual(0o644, stat.S_IMODE(secret_path.stat().st_mode))
        self.assertEqual(original, secret_path.read_bytes())

    def test_authorize_provisions_secret_on_legacy_deployment(self):
        # The mutating path is unchanged: a legacy deployment gains its
        # secret at the first mutating command, owner-only, and permits
        # minted under it consume normally.
        self.init_trusted()
        secret_path = self.deployment / "kernel-secret"
        secret_path.unlink()

        _, permit_path = self.authorize_ok()
        self.assertTrue(secret_path.is_file())
        self.assertEqual(0o600, stat.S_IMODE(secret_path.stat().st_mode))

        exit_code, consumed = self.consume(permit_path)
        self.assertEqual(0, exit_code, consumed)
        self.assertTrue(consumed["consumed"])

    def test_module_entrypoint_status_via_subprocess(self):
        self.init_trusted()
        completed = subprocess.run(
            [sys.executable, "-m", "pulpo.ops", "status", str(self.deployment)],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, TEST_SECRET_ENV: SECRET_TEXT},
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        status = json.loads(completed.stdout)
        self.assertEqual("status", status["command"])
        self.assertTrue(status["chain_valid"])


if __name__ == "__main__":
    unittest.main()

"""Phase 2, Item 4 — token v2: signed permit expiry and the policy TTL cap.

The pre-v2 gap (design repro ``repro_p2_4_bearer_token.py``): a permit
token was ``digest:nonce:signature`` with no expiry anywhere — a bare
copied token was consumed by a fresh kernel over the same deployment
files TEN YEARS after issuance, with nothing presented but the string
and the asserted intent. These tests pin the fix:

- tokens are v2 (``digest:nonce:issued:expiry:signature``) with the
  expiry inside the HMAC, so tampering with it fails authentication;
- policy carries ``max_permit_ttl_ns`` — the lifetime stamped at
  issuance and the cap no issuance may exceed — validated at policy
  construction against an absolute ceiling;
- ``consume`` enforces the signed expiry at consume time (kernel layer)
  and the state layer re-checks the expiry recorded at issuance
  (second layer, covering direct handle-level consume calls);
- v1 tokens fail closed at the cutover — never silently accepted.

Bearer semantics inside the deployment domain are otherwise unchanged
and are the accepted posture (memo 4C): possession + deployment access
spends a permit for its exact authorized intent, once, inside its TTL
window. Presenter binding (4B) is Phase 3 and is not built here.
"""

from __future__ import annotations

import contextlib
from dataclasses import asdict
from hashlib import sha256
import hmac
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from pulpo import AuthorityTrust, GovernanceKernel, Intent, Policy
from pulpo.kernel import DEFAULT_MAX_PERMIT_TTL_NS, PERMIT_TTL_CEILING_NS
from pulpo.ops import TEST_SECRET_ENV, main as ops_main
from pulpo.state import AuditSigner, InMemoryKernelState, SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope

SECRET = b"permit-ttl-test-secret"
T0 = 1_700_000_000_000_000_000
HOUR_NS = 3600 * 1_000_000_000
YEAR_NS = 365 * 24 * HOUR_NS
INTENT = Intent(
    principal="agent-1",
    action="wire.transfer",
    resource="acct:1",
    cost=500,
    session_id="s1",
)


def make_policy(**overrides):
    fields = {
        "allowed_actions": frozenset({"wire.transfer"}),
        "max_cost": 1000,
    }
    fields.update(overrides)
    return Policy(**fields)


def make_kernel(now, policy=None, state=None):
    return GovernanceKernel(
        policy or make_policy(),
        secret=SECRET,
        state=state if state is not None else InMemoryKernelState(),
        clock=lambda: now,
    )


def rejection_reasons(kernel):
    return [
        record["payload"].get("reason")
        for record in kernel.audit
        if record["event"] == "permit_rejected"
    ]


class TokenV2ShapeTests(unittest.TestCase):
    def test_issued_token_is_v2_with_signed_expiry_at_policy_cap(self):
        kernel = make_kernel(T0, policy=make_policy(max_permit_ttl_ns=2 * HOUR_NS))
        token = kernel.evaluate(INTENT).permit
        parts = token.split(":")
        self.assertEqual(5, len(parts))
        digest, _nonce, issued_raw, expires_raw, _signature = parts
        self.assertEqual(kernel.intent_hash(INTENT), digest)
        self.assertEqual(T0, int(issued_raw))
        self.assertEqual(T0 + 2 * HOUR_NS, int(expires_raw))

    def test_default_policy_stamps_the_default_cap(self):
        kernel = make_kernel(T0)
        token = kernel.evaluate(INTENT).permit
        _digest, _nonce, issued_raw, expires_raw, _sig = token.split(":")
        self.assertEqual(DEFAULT_MAX_PERMIT_TTL_NS, int(expires_raw) - int(issued_raw))

    def test_policy_ttl_cap_validated_at_construction(self):
        for bad in (0, -1, True, "3600"):
            with self.assertRaises(ValueError):
                make_policy(max_permit_ttl_ns=bad)
        with self.assertRaises(ValueError):
            make_policy(max_permit_ttl_ns=PERMIT_TTL_CEILING_NS + 1)
        # The ceiling itself is admissible; the default is admissible.
        make_policy(max_permit_ttl_ns=PERMIT_TTL_CEILING_NS)
        make_policy()


class ExpiryEnforcementTests(unittest.TestCase):
    def test_expired_permit_refused_at_consume_with_recorded_reason(self):
        policy = make_policy(max_permit_ttl_ns=HOUR_NS)
        issuer = make_kernel(T0, policy=policy)
        token = issuer.evaluate(INTENT).permit
        # A fresh kernel over the same state, one hour later: the token
        # is at its expiry and fails closed, like a revoked permit.
        state = issuer._state
        later = make_kernel(T0 + HOUR_NS, policy=policy, state=state)
        self.assertFalse(later.consume(token, INTENT))
        self.assertIn("permit_expired", rejection_reasons(later))

    def test_permit_consumed_just_before_expiry_still_works(self):
        policy = make_policy(max_permit_ttl_ns=HOUR_NS)
        issuer = make_kernel(T0, policy=policy)
        token = issuer.evaluate(INTENT).permit
        just_in_time = make_kernel(
            T0 + HOUR_NS - 1, policy=policy, state=issuer._state
        )
        self.assertTrue(just_in_time.consume(token, INTENT))

    def test_ten_year_old_token_refused(self):
        # The design repro's headline case, at the fixed tree.
        issuer = make_kernel(T0)
        token = issuer.evaluate(INTENT).permit
        decade_later = make_kernel(T0 + 10 * YEAR_NS, state=issuer._state)
        self.assertFalse(decade_later.consume(token, INTENT))
        self.assertIn("permit_expired", rejection_reasons(decade_later))

    def test_tampered_expiry_rejected_as_inauthentic(self):
        kernel = make_kernel(T0)
        token = kernel.evaluate(INTENT).permit
        digest, nonce, issued_raw, _expires_raw, signature = token.split(":")
        # Extend the expiry a century; keep the original signature.
        forged = ":".join(
            [digest, nonce, issued_raw, str(T0 + 100 * YEAR_NS), signature]
        )
        self.assertFalse(kernel.consume(forged, INTENT))
        self.assertIn("permit_signature_invalid", rejection_reasons(kernel))
        # The genuine token is untouched by the attempt.
        self.assertTrue(kernel.consume(token, INTENT))

    def test_tampered_issued_at_rejected_as_inauthentic(self):
        kernel = make_kernel(T0)
        token = kernel.evaluate(INTENT).permit
        digest, nonce, _issued_raw, expires_raw, signature = token.split(":")
        forged = ":".join(
            [digest, nonce, str(T0 - 10 * YEAR_NS), expires_raw, signature]
        )
        self.assertFalse(kernel.consume(forged, INTENT))
        self.assertIn("permit_signature_invalid", rejection_reasons(kernel))


class V1CutoverTests(unittest.TestCase):
    """A v1 token (digest:nonce:signature over digest:nonce) with a real
    store row — an outstanding pre-cutover permit — is refused."""

    def mint_v1(self, state, kernel):
        digest = kernel.intent_hash(INTENT)
        nonce = "ab" * 16
        signature = hmac.new(
            SECRET, f"{digest}:{nonce}".encode(), sha256
        ).hexdigest()
        token = f"{digest}:{nonce}:{signature}"
        state.issue_permit(token, digest, "policy_satisfied", T0)
        return token

    def test_v1_token_refused_in_memory(self):
        state = InMemoryKernelState()
        kernel = make_kernel(T0, state=state)
        token = self.mint_v1(state, kernel)
        self.assertFalse(kernel.consume(token, INTENT))
        self.assertIn("permit_signature_invalid", rejection_reasons(kernel))

    def test_v1_token_refused_sqlite(self):
        with tempfile.TemporaryDirectory() as directory:
            state = SQLiteKernelState(Path(directory) / "state.db")
            kernel = make_kernel(T0, state=state)
            token = self.mint_v1(state, kernel)
            self.assertFalse(kernel.consume(token, INTENT))
            self.assertIn("permit_signature_invalid", rejection_reasons(kernel))
            state.close()


class StoreSecondLayerTests(unittest.TestCase):
    """Direct handle-level consume calls (no kernel) face the recorded
    expiry too — the Item 3 repro A path is expiry-bound as well."""

    def test_inmemory_store_refuses_consume_at_expiry(self):
        state = InMemoryKernelState()
        digest = GovernanceKernel.intent_hash(INTENT)
        state.issue_permit(
            "tok", digest, "policy_satisfied", T0, expires_at_ns=T0 + HOUR_NS
        )
        self.assertFalse(state.consume_permit("tok", digest, T0 + HOUR_NS))
        rejected = [
            record
            for record in state.audit
            if record["event"] == "permit_rejected"
        ]
        self.assertEqual("permit_expired", rejected[-1]["payload"]["permit_status"])

    def test_inmemory_store_consumes_before_expiry(self):
        state = InMemoryKernelState()
        digest = GovernanceKernel.intent_hash(INTENT)
        state.issue_permit(
            "tok", digest, "policy_satisfied", T0, expires_at_ns=T0 + HOUR_NS
        )
        self.assertTrue(state.consume_permit("tok", digest, T0 + HOUR_NS - 1))

    def test_sqlite_store_refuses_consume_at_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            state = SQLiteKernelState(Path(directory) / "state.db")
            digest = GovernanceKernel.intent_hash(INTENT)
            state.issue_permit(
                "tok", digest, "policy_satisfied", T0, expires_at_ns=T0 + HOUR_NS
            )
            self.assertFalse(state.consume_permit("tok", digest, T0 + HOUR_NS))
            rejected = [
                record
                for record in state.audit
                if record["event"] == "permit_rejected"
            ]
            self.assertEqual(
                "permit_expired", rejected[-1]["payload"]["permit_status"]
            )
            state.close()

    def test_sqlite_expiry_column_migration_and_null_expiry_rows(self):
        # A pre-v2 database (permits table without the expiry column)
        # gains the column on first mutating open; its existing rows
        # keep NULL expiry.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            state = SQLiteKernelState(path)
            state.close()
            import sqlite3

            connection = sqlite3.connect(path)
            connection.execute(
                "CREATE TABLE permits_old (permit TEXT PRIMARY KEY, "
                "intent_hash TEXT NOT NULL, spent INTEGER NOT NULL DEFAULT 0)"
            )
            connection.execute(
                "INSERT INTO permits_old VALUES ('legacy-tok', 'd', 0)"
            )
            connection.execute("DROP TABLE permits")
            connection.execute("ALTER TABLE permits_old RENAME TO permits")
            connection.commit()
            connection.close()

            reopened = SQLiteKernelState(path)
            columns = {
                row[1]
                for row in reopened._connection.execute(
                    "PRAGMA table_info(permits)"
                ).fetchall()
            }
            self.assertIn("expires_at_ns", columns)
            row = reopened._connection.execute(
                "SELECT expires_at_ns FROM permits WHERE permit = 'legacy-tok'"
            ).fetchone()
            self.assertIsNone(row[0])
            reopened.close()


OPS_SECRET_TEXT = "ops-ttl-test-secret"
OPS_ACTION = "deploy.release"
OPS_RESOURCE = "service:api"
OPS_PRINCIPAL = "alice"
OPS_DEPLOYMENT_ID = "deployment:test-permit-ttl"
OPS_SESSION_ID = "default"


class OpsLifecycleTests(unittest.TestCase):
    """The honest ops lifecycle issues v2 tokens end to end, and a
    permit file left dormant past its TTL is refused by a fresh kernel
    over the same deployment files (the repro's deployment model)."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pulpo-ops-ttl-")
        self.root = Path(self.temporary.name)
        self.deployment = self.root / "deployment"
        self.envelope_path = self.root / "envelope.json"
        self.env = mock.patch.dict(
            os.environ, {TEST_SECRET_ENV: OPS_SECRET_TEXT}
        )
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temporary.cleanup()

    def run_cli(self, argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = ops_main([str(item) for item in argv])
        text = output.getvalue().strip()
        return exit_code, (json.loads(text) if text else {})

    def test_ops_issued_permit_is_v2_and_dormant_permit_expires(self):
        exit_code, report = self.run_cli(
            [
                "init",
                self.deployment,
                "--action",
                OPS_ACTION,
                "--max-cost",
                "1000",
                "--session-id",
                OPS_SESSION_ID,
                "--deployment-id",
                OPS_DEPLOYMENT_ID,
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

        config = json.loads(
            (self.deployment / "policy.json").read_text(encoding="utf-8")
        )
        policy = Policy(
            allowed_actions=frozenset(config["allowed_actions"]),
            max_cost=config["max_cost"],
            approval_actions=frozenset(config["approval_actions"]),
            authority_trust=AuthorityTrust(**config["authority_trust"]),
        )
        intent = Intent(
            principal=OPS_PRINCIPAL,
            action=OPS_ACTION,
            resource=OPS_RESOURCE,
            cost=100,
            session_id=OPS_SESSION_ID,
        )
        verifier = HmacTestVerifier(secret=OPS_SECRET_TEXT.encode("utf-8"))
        throwaway = GovernanceKernel(
            policy, approval_verifier=verifier, state=InMemoryKernelState()
        )
        envelope = signed_envelope(
            throwaway,
            intent,
            verifier,
            now_ns=time.time_ns(),
            ttl_ns=60_000_000_000,
        )
        self.envelope_path.write_text(
            json.dumps(asdict(envelope)), encoding="utf-8"
        )

        exit_code, report = self.run_cli(
            [
                "authorize",
                self.deployment,
                "--envelope",
                self.envelope_path,
                "--principal",
                OPS_PRINCIPAL,
                "--action",
                OPS_ACTION,
                "--resource",
                OPS_RESOURCE,
                "--cost",
                "100",
                "--session-id",
                OPS_SESSION_ID,
            ]
        )
        self.assertEqual(0, exit_code, report)
        self.assertEqual("allow", report["outcome"])
        permit_path = Path(report["permit_path"])
        token = permit_path.read_text(encoding="utf-8").strip()
        self.assertEqual(5, len(token.split(":")))

        # Honest consume through the CLI works exactly once.
        consume_argv = [
            "consume",
            self.deployment,
            "--permit-file",
            permit_path,
            "--principal",
            OPS_PRINCIPAL,
            "--action",
            OPS_ACTION,
            "--resource",
            OPS_RESOURCE,
            "--cost",
            "100",
            "--session-id",
            OPS_SESSION_ID,
        ]
        exit_code, consumed = self.run_cli(consume_argv)
        self.assertEqual(0, exit_code, consumed)
        self.assertTrue(consumed["consumed"])

        # Dormancy: a fresh kernel over the same deployment files, ten
        # years later, refuses the (already spent, and in any case long
        # expired) token — and the refusal names the expiry. Use the
        # deployment's own secrets and state, exactly as the repro does
        # (the state is opened with the deployment's audit signer, as
        # ops opens it: the deployment has audit signing enabled).
        # Deployment secret files are hex text (ops._provision_secret_file);
        # decode exactly as ops._read_secret_file does.
        secret = bytes.fromhex(
            (self.deployment / "kernel-secret").read_text(encoding="utf-8").strip()
        )
        audit_signer = AuditSigner(
            bytes.fromhex(
                (self.deployment / "audit-secret")
                .read_text(encoding="utf-8")
                .strip()
            )
        )
        state = SQLiteKernelState(
            self.deployment / "state.db",
            audit_signer=audit_signer,
            legacy_audit_records=config["audit_signing"]["legacy_records"],
        )
        future = GovernanceKernel(
            policy,
            secret=secret,
            state=state,
            clock=lambda: time.time_ns() + 10 * YEAR_NS,
        )
        self.assertFalse(future.consume(token, intent))
        self.assertIn("permit_expired", rejection_reasons(future))
        state.close()


if __name__ == "__main__":
    unittest.main()

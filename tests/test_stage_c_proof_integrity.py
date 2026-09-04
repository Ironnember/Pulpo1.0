import importlib.util
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_stage_c_supabase_consequence_v1.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("stage_c_supabase_integrity", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeKernel:
    def __init__(self, intent):
        self.intent = intent
        self.audit = [{"hash": "audit-tip"}]

    def resolve_locked_target(self, target_id, target_hash):
        del target_id, target_hash
        return SimpleNamespace(outcome="match", target=SimpleNamespace(intent=self.intent))

    def consume(self, permit, intent):
        del permit, intent
        return True


class FakeCustody:
    def __init__(self):
        self.epoch = 0
        self.reconciliation_required = False
        self.reconciled = None

    def snapshot(self):
        return SimpleNamespace(epoch=self.epoch, state_root=f"root-{self.epoch}")

    def authorize_attempt(self, **kwargs):
        del kwargs
        self.epoch += 1
        return SimpleNamespace(attempt_id="attempt-1")

    def claim_attempt(self, **kwargs):
        del kwargs
        self.epoch += 1

    def authorize_transmission(self, **kwargs):
        del kwargs
        self.epoch += 1
        return SimpleNamespace(idempotency_key="tx-1")

    def require_reconciliation(self, **kwargs):
        del kwargs
        self.epoch += 1
        self.reconciliation_required = True

    def reconcile_observed(self, **kwargs):
        self.reconciled = dict(kwargs)
        self.epoch += 1


class StageCProofIntegrityTests(unittest.TestCase):
    def test_p01_child_environment_is_allowlisted_not_secret_denylisted(self):
        runner = load_runner()
        injected = ("DATABASE_URL", "SUPABASE_DB_URL", "POSTGRES_URL", "PGURI", "AWS_PROFILE", "GOOGLE_APPLICATION_CREDENTIALS")
        original = {name: os.environ.get(name) for name in injected}
        try:
            for name in injected:
                os.environ[name] = f"ambient:{name}"
            child = runner.clean_env()
            self.assertTrue(set(child).issubset(set(runner.CHILD_ENV_ALLOWLIST)))
            for name in injected:
                self.assertNotIn(name, child)
        finally:
            for name, value in original.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_p02_real_ceremony_rejects_head_mismatch_before_dependency_check(self):
        runner = load_runner()
        calls = [
            SimpleNamespace(returncode=0, stdout=""),
            SimpleNamespace(returncode=0, stdout="current-head\n"),
        ]

        def fake_run(*args, **kwargs):
            del args, kwargs
            return calls.pop(0)

        with patch.object(sys, "argv", [str(SCRIPT), "--authorized-head", "authorized-head"]), patch.object(runner.subprocess, "run", side_effect=fake_run), patch.object(runner.shutil, "which", side_effect=AssertionError("dependency check reached before head rejection")):
            with self.assertRaisesRegex(RuntimeError, "exact authorized head mismatch"):
                runner.main()

    def test_p03_observer_blackout_after_transmission_is_structured_unresolved(self):
        runner = load_runner()
        row = dict(runner.MATCHED_ROW)
        object_hash, intent = runner.action(row, principal="agent:proof-integrity")
        item = runner.Prepared(
            row=row,
            object_hash=object_hash,
            intent=intent,
            target_id="proof-integrity-target",
            target_hash="proof-integrity-target-hash",
            permit="proof-integrity-permit",
            intent_hash="proof-integrity-intent-hash",
            policy_hash="proof-integrity-policy-hash",
        )
        kernel = FakeKernel(intent)
        custody = FakeCustody()
        provider_calls = []

        def provider_call():
            provider_calls.append(dict(row))

        def observer_unavailable():
            raise TimeoutError("observer unavailable after transmission")

        result = runner.transmit(
            kernel,
            custody,
            item,
            provider_call,
            request_id="proof-integrity-p03",
            executor_id="executor:proof-integrity-p03",
            observe=observer_unavailable,
        )

        self.assertEqual(1, len(provider_calls))
        self.assertTrue(custody.reconciliation_required)
        self.assertTrue(result["transmitted"])
        self.assertEqual("unresolved", result["reconciliation_outcome"])
        self.assertEqual("unavailable", result["observation"]["observation_status"])
        self.assertEqual("TimeoutError", result["observation"]["error_type"])
        self.assertFalse(result["provider_claim"]["authoritative"])
        self.assertEqual("unresolved", custody.reconciled["outcome"])

    def test_p04_libpq_connect_timeout_uses_standard_environment_name(self):
        runner = load_runner()
        env = runner.pg_env("postgresql://stagec:example@db.example:5432/postgres?sslmode=require")
        self.assertEqual("8", env["PGCONNECT_TIMEOUT"])
        self.assertNotIn("PGCONNECTTIMEOUT", env)


if __name__ == "__main__":
    unittest.main()

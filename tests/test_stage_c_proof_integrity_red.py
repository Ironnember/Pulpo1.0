import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_stage_c_supabase_consequence_v1.py"
FROZEN_EXPERIMENT_HEAD = "d0966d36347daae7f291d1f7eae7f6e49b2fb7f1"


def load_runner():
    spec = importlib.util.spec_from_file_location("stage_c_supabase_integrity_red", SCRIPT)
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
        del kwargs
        self.epoch += 1


class StageCProofIntegrityRedTests(unittest.TestCase):
    def test_p01_ambient_database_capability_is_not_preserved_by_sanitization(self):
        runner = load_runner()
        names = ("DATABASE_URL", "SUPABASE_DB_URL", "POSTGRES_URL", "PGURI")
        original = {name: os.environ.get(name) for name in names}
        try:
            for name in names:
                os.environ[name] = "postgresql://ambient-capability.invalid/pulpo"
            sanitized = runner.clean_env()
            leaked = sorted(name for name in names if name in sanitized)
            self.assertEqual(
                [],
                leaked,
                "proposal-child environment stripping is a fixed secret-name denylist, not a capability allowlist",
            )
        finally:
            for name, value in original.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_p02_real_ceremony_rejects_descendant_head_before_tool_or_credential_checks(self):
        runner = load_runner()
        current_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertNotEqual(
            FROZEN_EXPERIMENT_HEAD,
            current_head,
            "red proof must execute on a descendant object, not the already-frozen experiment head",
        )

        with patch.object(sys, "argv", [str(SCRIPT)]), patch.object(runner.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, r"(?i)(exact.*head|authorized.*head)"):
                runner.main()

    def test_p03_observer_blackout_after_transmission_becomes_structured_unknown(self):
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

        self.assertEqual(1, len(provider_calls), "the uncertainty test must happen after one transmission")
        self.assertTrue(custody.reconciliation_required)
        self.assertTrue(result["transmitted"])
        self.assertEqual("unresolved", result.get("reconciliation_outcome"))
        self.assertFalse(result.get("provider_claim", {}).get("authoritative", True))


if __name__ == "__main__":
    unittest.main()

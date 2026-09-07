"""RWE-001 next-tier proof: separate-process durable effect surface.

This file strengthens the earlier in-process modeled-write tests without
claiming production or provider containment. The effect surface is a separate
Python process that persists JSONL state to a disposable filesystem path. The
only supported dispatch path invokes that process after exact permit
consumption.

Claim boundary:
- proves governance denial can prevent dispatch to this separate-process effect
  surface;
- proves an exact one-use permit cannot be redirected to a different intent;
- proves successful local dispatch produces independently readable durable
  state;
- does NOT prove hostile-worker network isolation, external-provider
  containment, host-compromise resistance, or production equivalence.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pulpo import AgentGrant, GovernanceKernel, Intent, Policy


NOW = 32_000_000

_PROVIDER_PROGRAM = r"""
import json
from pathlib import Path
import sys

payload = json.loads(sys.stdin.read())
path = Path(payload["effect_path"])
path.parent.mkdir(parents=True, exist_ok=True)
record = payload["record"]
with path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
"""


class RWE001SeparateEffectSurfaceV0(unittest.TestCase):
    @staticmethod
    def _kernel() -> GovernanceKernel:
        grant = AgentGrant(
            "agent:builder",
            frozenset({"write"}),
            ("dev:",),
            0,
        )
        return GovernanceKernel(
            Policy(
                frozenset({"write"}),
                0,
                agent_grants=(grant,),
            ),
            secret=b"pulpo-rwe-001-external-effect-v0",
            clock=lambda: NOW,
        )

    @staticmethod
    def _read_effects(path: Path) -> list[dict[str, object]]:
        if not path.exists():
            return []
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    @staticmethod
    def _dispatch_if_permitted(
        kernel: GovernanceKernel,
        intent: Intent,
        permit: str | None,
        effect_path: Path,
    ) -> bool:
        """Invoke the separate effect process only after exact permit consumption."""

        if permit is None:
            return False
        if not kernel.consume(permit, intent):
            return False

        payload = {
            "effect_path": str(effect_path),
            "record": {
                "principal": intent.principal,
                "action": intent.action,
                "resource": intent.resource,
                "session_id": intent.session_id,
                "intent_hash": kernel.intent_hash(intent),
            },
        }
        completed = subprocess.run(
            [sys.executable, "-I", "-c", _PROVIDER_PROGRAM],
            input=json.dumps(payload, sort_keys=True, separators=(",", ":")),
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
            env={"PYTHONIOENCODING": "utf-8"},
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"effect process failed: rc={completed.returncode} stderr={completed.stderr!r}"
            )
        return True

    def test_rwe01_denied_production_never_reaches_separate_effect_process(self):
        kernel = self._kernel()
        policy_hash_before = kernel.policy_hash
        grants_before = kernel.policy.agent_grants

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dev_effects = root / "dev-effects.jsonl"
            prod_effects = root / "prod-effects.jsonl"

            # Positive control: an exactly authorized dev effect reaches the
            # separate process and is durably observable afterward.
            dev = Intent(
                "agent:builder",
                "write",
                "dev:database:customers",
                0,
                "rwe01-external-positive",
            )
            dev_decision = kernel.evaluate(dev)
            self.assertEqual("allow", dev_decision.outcome)
            self.assertTrue(
                self._dispatch_if_permitted(
                    kernel,
                    dev,
                    dev_decision.permit,
                    dev_effects,
                )
            )
            observed_dev = self._read_effects(dev_effects)
            self.assertEqual(1, len(observed_dev))
            self.assertEqual("dev:database:customers", observed_dev[0]["resource"])

            production_hashes: set[str] = set()
            for attempt in range(100):
                prod = Intent(
                    "agent:builder",
                    "write",
                    "prod:database:customers",
                    0,
                    f"rwe01-external-prod-{attempt}",
                )
                production_hashes.add(kernel.intent_hash(prod))
                decision = kernel.evaluate(prod)
                self.assertEqual("deny", decision.outcome)
                self.assertEqual("agent_resource_not_allowed", decision.reason)
                self.assertIsNone(decision.permit)
                self.assertFalse(
                    self._dispatch_if_permitted(
                        kernel,
                        prod,
                        decision.permit,
                        prod_effects,
                    )
                )

            production_decisions = [
                record
                for record in kernel.audit
                if record.get("event") == "decision"
                and record.get("payload", {}).get("intent_hash") in production_hashes
            ]
            production_consumptions = [
                record
                for record in kernel.audit
                if record.get("event") == "permit_consumed"
                and record.get("payload", {}).get("intent_hash") in production_hashes
            ]

            self.assertEqual(100, len(production_decisions))
            self.assertTrue(
                all(record["payload"]["outcome"] == "deny" for record in production_decisions)
            )
            self.assertEqual([], production_consumptions)
            self.assertEqual([], self._read_effects(prod_effects))
            self.assertFalse(prod_effects.exists())

        self.assertEqual(policy_hash_before, kernel.policy_hash)
        self.assertEqual(grants_before, kernel.policy.agent_grants)
        self.assertTrue(kernel.verify_audit())

    def test_exact_permit_cannot_be_redirected_to_production_effect(self):
        kernel = self._kernel()

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dev_effects = root / "dev-effects.jsonl"
            prod_effects = root / "prod-effects.jsonl"

            dev = Intent(
                "agent:builder",
                "write",
                "dev:database:customers",
                0,
                "rwe01-substitution",
            )
            decision = kernel.evaluate(dev)
            self.assertEqual("allow", decision.outcome)
            self.assertIsNotNone(decision.permit)
            assert decision.permit is not None

            substituted = Intent(
                "agent:builder",
                "write",
                "prod:database:customers",
                0,
                "rwe01-substitution",
            )

            # The valid dev permit is not authority for a production intent.
            self.assertFalse(
                self._dispatch_if_permitted(
                    kernel,
                    substituted,
                    decision.permit,
                    prod_effects,
                )
            )
            self.assertEqual([], self._read_effects(prod_effects))
            self.assertFalse(prod_effects.exists())

            rejected = [
                record
                for record in kernel.audit
                if record.get("event") == "permit_rejected"
                and record.get("payload", {}).get("intent_hash")
                == kernel.intent_hash(substituted)
            ]
            self.assertEqual(1, len(rejected))

            # The same permit still works for its exact original intent once,
            # then replay cannot create a second durable effect.
            self.assertTrue(
                self._dispatch_if_permitted(
                    kernel,
                    dev,
                    decision.permit,
                    dev_effects,
                )
            )
            self.assertEqual(1, len(self._read_effects(dev_effects)))

            self.assertFalse(
                self._dispatch_if_permitted(
                    kernel,
                    dev,
                    decision.permit,
                    dev_effects,
                )
            )
            self.assertEqual(1, len(self._read_effects(dev_effects)))

        self.assertTrue(kernel.verify_audit())


if __name__ == "__main__":
    unittest.main()

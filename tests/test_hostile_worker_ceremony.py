from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_hostile_worker_namecom_ceremony.py"
SPEC = importlib.util.spec_from_file_location("pulpo_hostile_worker_namecom_ceremony", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load hostile-worker ceremony module")
CEREMONY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CEREMONY)


class HostileWorkerCeremonyAuthenticationTests(unittest.TestCase):
    def test_missing_worker_token_fails_before_authority_client_construction(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                CEREMONY.CeremonyBlocked,
                "authenticated authority worker token is unavailable",
            ):
                CEREMONY._worker_authorization_provider("PULPO_AUTHORITY_WORKER_TOKEN")

    def test_worker_token_is_converted_to_bearer_header_without_mutation(self):
        with patch.dict(
            os.environ,
            {"PULPO_AUTHORITY_WORKER_TOKEN": "exact-worker-token"},
            clear=True,
        ):
            provider = CEREMONY._worker_authorization_provider("PULPO_AUTHORITY_WORKER_TOKEN")
        self.assertEqual("Bearer exact-worker-token", provider())

    def test_malformed_worker_tokens_fail_closed(self):
        for value in (" worker", "worker ", "worker token", "\tworker"):
            with self.subTest(value=value), patch.dict(
                os.environ,
                {"PULPO_AUTHORITY_WORKER_TOKEN": value},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    CEREMONY.CeremonyBlocked,
                    "authenticated authority worker token is unavailable",
                ):
                    CEREMONY._worker_authorization_provider("PULPO_AUTHORITY_WORKER_TOKEN")

    def test_invalid_environment_variable_name_is_rejected(self):
        with self.assertRaisesRegex(
            CEREMONY.CeremonyBlocked,
            "worker token environment variable name is invalid",
        ):
            CEREMONY._worker_authorization_provider(" PULPO_AUTHORITY_WORKER_TOKEN")


if __name__ == "__main__":
    unittest.main()

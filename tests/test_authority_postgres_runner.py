"""The database gate must reject unsafe targets and incomplete executions."""
import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "authority_postgres_runner",
    Path(__file__).resolve().parents[1] / "scripts/run_authority_postgres_proof.py",
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class AuthorityPostgresRunnerTests(unittest.TestCase):
    def test_reset_opt_in_is_required_before_driver_import(self):
        with patch.dict(runner.os.environ, {}, clear=True):
            with self.assertRaisesRegex(SystemExit, "reset opt-in"):
                runner.main()

    def test_missing_database_fails_instead_of_skipping(self):
        with patch.dict(runner.os.environ, {"PULPO_AUTHORITY_TEST_ALLOW_RESET": "1"}, clear=True):
            with self.assertRaisesRegex(SystemExit, "DSN is required"):
                runner.main()

    def invoke(self, settings, *, skipped=(), tests=66, successful=True):
        module = ModuleType("psycopg.conninfo")
        module.conninfo_to_dict = lambda _: settings
        result = SimpleNamespace(skipped=skipped, testsRun=tests, wasSuccessful=lambda: successful)
        environment = {
            "PULPO_AUTHORITY_TEST_ALLOW_RESET": "1",
            "PULPO_AUTHORITY_TEST_POSTGRES_DSN": "synthetic",
            "PGHOSTADDR": "external.example",
        }
        previous_path = sys.path[:]
        self.addCleanup(lambda: sys.path.__setitem__(slice(None), previous_path))
        with patch.dict(runner.os.environ, environment, clear=True), \
                patch.dict(sys.modules, {"psycopg": ModuleType("psycopg"), "psycopg.conninfo": module}), \
                patch.object(runner.unittest.defaultTestLoader, "discover", return_value=object()) as discover, \
                patch.object(runner.unittest, "TextTestRunner") as factory:
            factory.return_value.run.return_value = result
            try:
                runner.main()
            finally:
                if discover.called:
                    self.assertNotIn("PGHOSTADDR", runner.os.environ)

    def test_remote_or_ambiguous_targets_are_rejected_before_test_discovery(self):
        valid = {"host": "127.0.0.1", "dbname": "pulpo_authority_test"}
        for override in ({"host": "external.example"}, {"dbname": "production"},
                         {"hostaddr": "external.example"}, {"service": "production"}):
            with self.subTest(override=override), self.assertRaisesRegex(SystemExit, "loopback"):
                self.invoke(valid | override)

    def test_skip_failure_and_empty_suite_each_fail_the_gate(self):
        for arguments in ({"skipped": [("case", "unconfigured")]},
                          {"tests": 0}, {"successful": False}):
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit) as caught:
                self.invoke({"host": "127.0.0.1", "dbname": "pulpo_authority_test"}, **arguments)
            self.assertEqual(1, caught.exception.code)

    def test_successful_nonempty_suite_without_skips_passes(self):
        self.invoke({"host": "127.0.0.1", "dbname": "pulpo_authority_test"})

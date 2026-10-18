from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "proofs" / "cloud_runtime_discovery.py"
SPEC = importlib.util.spec_from_file_location("cloud_runtime_discovery", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
cloud_runtime_discovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cloud_runtime_discovery)


class FakeRunner:
    def __init__(self, outputs):
        self.outputs = outputs
        self.calls = []

    def __call__(self, command):
        frozen = tuple(command)
        self.calls.append(frozen)
        return self.outputs[frozen]


def good_outputs():
    return {
        cloud_runtime_discovery.AUTH_COMMAND: "ai@ironnember.com\n",
        cloud_runtime_discovery.PROJECT_COMMAND: "dulcet-opus-499511-a5\n",
        cloud_runtime_discovery.ARTIFACT_REPOSITORIES_COMMAND: json.dumps(
            [
                {"name": "projects/p/locations/us-west1/repositories/z"},
                {"name": "projects/p/locations/us-west1/repositories/a"},
            ]
        ),
        cloud_runtime_discovery.CLOUD_RUN_JOBS_COMMAND: "[]",
        cloud_runtime_discovery.ENABLED_SERVICES_COMMAND: (
            "artifactregistry.googleapis.com\nrun.googleapis.com\n"
        ),
    }


class CloudRuntimeDiscoveryTests(unittest.TestCase):
    def test_exact_read_only_inventory_produces_bounded_evidence(self):
        runner = FakeRunner(good_outputs())

        evidence = cloud_runtime_discovery.collect_discovery(runner)

        self.assertEqual(
            list(cloud_runtime_discovery.READ_ONLY_COMMANDS),
            runner.calls,
        )
        self.assertEqual("pulpo.cloud-runtime-discovery.v0", evidence["schema"])
        self.assertEqual("dulcet-opus-499511-a5", evidence["project"])
        self.assertEqual("us-west1", evidence["region"])
        self.assertEqual("ai@ironnember.com", evidence["operator"])
        self.assertEqual("none", evidence["authority_effect"])
        self.assertEqual("none", evidence["cloud_mutation"])
        self.assertTrue(evidence["tracked_services"]["artifactregistry.googleapis.com"])
        self.assertTrue(evidence["tracked_services"]["run.googleapis.com"])
        names = [item["name"] for item in evidence["artifact_repositories"]]
        self.assertEqual(sorted(names), names)
        self.assertEqual([], evidence["cloud_run_jobs"])
        self.assertEqual(64, len(evidence["discovery_command_sha256"]))

    def test_wrong_operator_fails_before_project_or_inventory(self):
        outputs = good_outputs()
        outputs[cloud_runtime_discovery.AUTH_COMMAND] = "someone@example.com\n"
        runner = FakeRunner(outputs)

        with self.assertRaisesRegex(RuntimeError, "active operator mismatch"):
            cloud_runtime_discovery.collect_discovery(runner)

        self.assertEqual([cloud_runtime_discovery.AUTH_COMMAND], runner.calls)

    def test_wrong_project_fails_before_resource_inventory(self):
        outputs = good_outputs()
        outputs[cloud_runtime_discovery.PROJECT_COMMAND] = "wrong-project\n"
        runner = FakeRunner(outputs)

        with self.assertRaisesRegex(RuntimeError, "active project mismatch"):
            cloud_runtime_discovery.collect_discovery(runner)

        self.assertEqual(
            [
                cloud_runtime_discovery.AUTH_COMMAND,
                cloud_runtime_discovery.PROJECT_COMMAND,
            ],
            runner.calls,
        )

    def test_substituted_or_mutating_commands_are_rejected(self):
        substitutions = (
            ("gcloud", "services", "enable", "run.googleapis.com"),
            ("gcloud", "artifacts", "repositories", "create", "pulpo"),
            ("gcloud", "run", "jobs", "execute", "pulpo-authority-probe"),
            ("gcloud", "projects", "add-iam-policy-binding", "p"),
        )
        for command in substitutions:
            with self.subTest(command=command):
                with self.assertRaisesRegex(ValueError, "read-only allowlist"):
                    cloud_runtime_discovery.validate_read_only_command(command)

    def test_ambiguous_identity_and_invalid_inventory_fail_closed(self):
        outputs = good_outputs()
        outputs[cloud_runtime_discovery.AUTH_COMMAND] = (
            "ai@ironnember.com\nother@example.com\n"
        )
        with self.assertRaisesRegex(RuntimeError, "active operator is ambiguous"):
            cloud_runtime_discovery.collect_discovery(FakeRunner(outputs))

        outputs = good_outputs()
        outputs[cloud_runtime_discovery.ARTIFACT_REPOSITORIES_COMMAND] = "{}"
        with self.assertRaisesRegex(RuntimeError, "unexpected shape"):
            cloud_runtime_discovery.collect_discovery(FakeRunner(outputs))

        outputs = good_outputs()
        outputs[cloud_runtime_discovery.CLOUD_RUN_JOBS_COMMAND] = "not-json"
        with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
            cloud_runtime_discovery.collect_discovery(FakeRunner(outputs))


if __name__ == "__main__":
    unittest.main()

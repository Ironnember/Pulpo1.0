from __future__ import annotations

import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from pulpo_authority_service.cloudsql_postgres import CloudSqlPostgresConfig
from pulpo_authority_service.cloudsql_probe import (
    CloudSqlProbeSpec,
    main,
    run_cloudsql_probe,
)


class FakeCursor:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, rows):
        self.rows = list(rows)
        self.calls = []
        self.rollbacks = 0
        self.closes = 0

    def execute(self, statement, parameters=None):
        self.calls.append((statement, parameters))
        if statement == "BEGIN READ ONLY":
            return FakeCursor(None)
        if not self.rows:
            raise AssertionError("unexpected SQL statement")
        return FakeCursor(self.rows.pop(0))

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closes += 1


class CloudSqlProbeTests(unittest.TestCase):
    def setUp(self):
        self.spec = CloudSqlProbeSpec(
            connection=CloudSqlPostgresConfig(
                "dulcet-opus-499511-a5:us-west1:pulpo-authority-db",
                "pulpo_authority",
                "pulpo-authority@dulcet-opus-499511-a5.iam",
            ),
            runtime_role="pulpo_authority_runtime",
            schema="pulpo_authority",
            expected_search_path="pulpo_authority, pg_catalog",
        )

    def _connection(self):
        return FakeConnection(
            [
                (
                    self.spec.connection.iam_user,
                    self.spec.connection.iam_user,
                    self.spec.connection.database,
                    "on",
                    self.spec.expected_search_path,
                ),
                (True,),
                (True, True, True, True),
                (True, False, False, False, False, False),
                (False, False, False, False, False, False),
                (self.spec.runtime_role,),
            ]
        )

    def test_success_is_read_only_bounded_and_reconciled(self):
        connection = self._connection()

        result = run_cloudsql_probe(self.spec, lambda: connection)

        self.assertEqual("PASS", result["status"])
        self.assertEqual("RECORDED", result["classification"])
        self.assertFalse(result["database_commit"])
        self.assertEqual("none", result["authority_effect"])
        self.assertTrue(result["reconciliation_required"])
        self.assertEqual(1, connection.rollbacks)
        self.assertEqual(1, connection.closes)
        self.assertEqual("BEGIN READ ONLY", connection.calls[0][0])
        self.assertFalse(
            any(
                statement.lstrip().upper().startswith(token)
                for statement, _ in connection.calls
                for token in ("INSERT ", "UPDATE ", "DELETE ", "CREATE ", "ALTER ", "DROP ")
            )
        )

    def test_identity_mismatch_is_unknown_and_rolls_back(self):
        connection = self._connection()
        first = list(connection.rows[0])
        first[0] = "wrong@identity.iam"
        connection.rows[0] = tuple(first)

        with self.assertRaisesRegex(RuntimeError, "current user invariant mismatch"):
            run_cloudsql_probe(self.spec, lambda: connection)

        self.assertEqual(1, connection.rollbacks)
        self.assertEqual(1, connection.closes)

    def test_unencrypted_session_is_unknown(self):
        connection = self._connection()
        connection.rows[1] = (False,)

        with self.assertRaisesRegex(RuntimeError, "encrypted transport invariant mismatch"):
            run_cloudsql_probe(self.spec, lambda: connection)

        self.assertEqual(1, connection.rollbacks)

    def test_role_expansion_is_unknown(self):
        connection = self._connection()
        connection.rows[4] = (False, True, False, False, False, False)

        with self.assertRaisesRegex(RuntimeError, "runtime role privilege invariant mismatch"):
            run_cloudsql_probe(self.spec, lambda: connection)

        self.assertEqual(1, connection.rollbacks)

    def test_iam_user_expansion_is_unknown(self):
        connection = self._connection()
        connection.rows[3] = (True, True, False, False, False, False)

        with self.assertRaisesRegex(RuntimeError, "IAM database user privilege"):
            run_cloudsql_probe(self.spec, lambda: connection)

        self.assertEqual(1, connection.rollbacks)

    def test_schema_owner_mismatch_is_unknown(self):
        connection = self._connection()
        connection.rows[5] = ("postgres",)

        with self.assertRaisesRegex(RuntimeError, "schema owner invariant mismatch"):
            run_cloudsql_probe(self.spec, lambda: connection)

        self.assertEqual(1, connection.rollbacks)

    def test_missing_observation_is_unknown(self):
        connection = self._connection()
        connection.rows[1] = None

        with self.assertRaisesRegex(RuntimeError, "transport observation unavailable"):
            run_cloudsql_probe(self.spec, lambda: connection)

        self.assertEqual(1, connection.rollbacks)

    def test_intent_hash_changes_with_frozen_target(self):
        other = CloudSqlProbeSpec(
            connection=CloudSqlPostgresConfig(
                "dulcet-opus-499511-a5:us-west1:other-db",
                "pulpo_authority",
                "pulpo-authority@dulcet-opus-499511-a5.iam",
            ),
            runtime_role=self.spec.runtime_role,
            schema=self.spec.schema,
            expected_search_path=self.spec.expected_search_path,
        )

        self.assertNotEqual(self.spec.intent_hash, other.intent_hash)

    def test_closed_execution_gate_never_builds_provider_factory(self):
        with patch.dict(os.environ, {}, clear=True), patch(
            "pulpo_authority_service.cloudsql_probe.CloudSqlPostgresConnectionFactory"
        ) as factory, patch("builtins.print") as output:
            status = main()

        self.assertEqual(2, status)
        factory.assert_not_called()
        receipt = json.loads(output.call_args.args[0])
        self.assertEqual("BLOCKED", receipt["status"])
        self.assertEqual("UNKNOWN", receipt["classification"])

    def test_provider_failure_is_unknown_without_error_leak_or_retry(self):
        environment = {
            "PULPO_CLOUDSQL_PROBE_EXECUTE": "1",
            "PULPO_CLOUDSQL_INSTANCE": self.spec.connection.instance_connection_name,
            "PULPO_CLOUDSQL_DATABASE": self.spec.connection.database,
            "PULPO_CLOUDSQL_IAM_USER": self.spec.connection.iam_user,
            "PULPO_CLOUDSQL_RUNTIME_ROLE": self.spec.runtime_role,
            "PULPO_CLOUDSQL_SCHEMA": self.spec.schema,
            "PULPO_CLOUDSQL_SEARCH_PATH": self.spec.expected_search_path,
        }
        with patch.dict(os.environ, environment, clear=True), patch(
            "pulpo_authority_service.cloudsql_probe.CloudSqlPostgresConnectionFactory",
            side_effect=RuntimeError("sensitive provider detail"),
        ) as factory, patch("builtins.print") as output:
            status = main()

        self.assertEqual(1, status)
        factory.assert_called_once_with(self.spec.connection)
        receipt_text = output.call_args.args[0]
        self.assertNotIn("sensitive provider detail", receipt_text)
        receipt = json.loads(receipt_text)
        self.assertEqual("UNKNOWN", receipt["status"])
        self.assertEqual(1, receipt["attempt_count"])

    def test_probe_configuration_rejects_identifier_injection(self):
        with self.assertRaisesRegex(ValueError, "PostgreSQL identifier"):
            CloudSqlProbeSpec(
                connection=self.spec.connection,
                runtime_role="runtime; DROP ROLE postgres",
                schema=self.spec.schema,
                expected_search_path=self.spec.expected_search_path,
            )

    def test_probe_container_is_digest_pinned_and_unprivileged(self):
        dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile.cloudsql-probe"
        contents = dockerfile.read_text()

        self.assertIn("FROM python:3.11-slim-bookworm@sha256:", contents)
        self.assertNotIn(":latest", contents)
        self.assertIn("USER 65532:65532", contents)
        self.assertIn(
            '["python", "-m", "pulpo_authority_service.cloudsql_probe"]',
            contents,
        )


if __name__ == "__main__":
    unittest.main()

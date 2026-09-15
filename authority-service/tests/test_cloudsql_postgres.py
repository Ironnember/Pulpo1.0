from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pulpo_authority_service.cloudsql_postgres as cloudsql_postgres
from pulpo_authority_service.cloudsql_postgres import (
    CloudSqlPostgresConfig,
    CloudSqlPostgresConnectionFactory,
)


CONNECTION_NAME = "pulpo-project:us-west1:pulpo-authority-db"
IAM_USER = "pulpo-authority@pulpo-project.iam"


class FakeCursor:
    def __init__(self):
        self.calls = []
        self.rowcount = 1

    def execute(self, statement, parameters=None):
        self.calls.append((statement, parameters))
        return self


class FakeConnection:
    def __init__(self):
        self.cursors = []
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0

    def cursor(self):
        cursor = FakeCursor()
        self.cursors.append(cursor)
        return cursor

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closes += 1


class FakeConnector:
    def __init__(self, connection=None):
        self.connection = connection or FakeConnection()
        self.calls = []
        self.closes = 0
        self.error = None

    def connect(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error is not None:
            raise self.error
        return self.connection

    def close(self):
        self.closes += 1


class CloudSqlPostgresConnectionFactoryTests(unittest.TestCase):
    def _config(self):
        return CloudSqlPostgresConfig(
            instance_connection_name=CONNECTION_NAME,
            database="pulpo_authority",
            iam_user=IAM_USER,
        )

    def test_uses_only_private_ip_and_automatic_iam_authentication(self):
        connector = FakeConnector()
        private_ip = object()
        with patch.object(
            cloudsql_postgres,
            "_connector_dependencies",
            return_value=(None, SimpleNamespace(PRIVATE=private_ip)),
        ):
            factory = CloudSqlPostgresConnectionFactory(self._config(), connector=connector)

        connection = factory()

        self.assertEqual(
            [
                (
                    (CONNECTION_NAME, "pg8000"),
                    {
                        "user": IAM_USER,
                        "db": "pulpo_authority",
                        "enable_iam_auth": True,
                        "ip_type": private_ip,
                    },
                )
            ],
            connector.calls,
        )
        self.assertNotIn("password", connector.calls[0][1])

        cursor = connection.execute("SELECT %s", (7,))
        self.assertEqual([("SELECT %s", (7,))], cursor.calls)
        connection.commit()
        connection.rollback()
        connection.close()
        self.assertEqual(1, connector.connection.commits)
        self.assertEqual(1, connector.connection.rollbacks)
        self.assertEqual(1, connector.connection.closes)

    def test_unparameterized_statement_uses_cursor_contract(self):
        connector = FakeConnector()
        with patch.object(
            cloudsql_postgres,
            "_connector_dependencies",
            return_value=(None, SimpleNamespace(PRIVATE="PRIVATE")),
        ):
            factory = CloudSqlPostgresConnectionFactory(self._config(), connector=connector)

        cursor = factory().execute("BEGIN")

        self.assertEqual([("BEGIN", None)], cursor.calls)

    def test_connector_failure_fails_closed_without_fallback(self):
        connector = FakeConnector()
        connector.error = OSError("provider unavailable")
        with patch.object(
            cloudsql_postgres,
            "_connector_dependencies",
            return_value=(None, SimpleNamespace(PRIVATE="PRIVATE")),
        ):
            factory = CloudSqlPostgresConnectionFactory(self._config(), connector=connector)

        with self.assertRaisesRegex(RuntimeError, "authority connection unavailable"):
            factory()
        self.assertEqual(1, len(connector.calls))

    def test_factory_closes_connector(self):
        connector = FakeConnector()
        with patch.object(
            cloudsql_postgres,
            "_connector_dependencies",
            return_value=(None, SimpleNamespace(PRIVATE="PRIVATE")),
        ):
            factory = CloudSqlPostgresConnectionFactory(self._config(), connector=connector)

        factory.close()

        self.assertEqual(1, connector.closes)

    def test_rejects_public_or_ambient_connection_configuration(self):
        with self.assertRaisesRegex(ValueError, "project:region:instance"):
            CloudSqlPostgresConfig("pulpo-authority-db", "pulpo_authority", IAM_USER)
        with self.assertRaisesRegex(ValueError, "dedicated database"):
            CloudSqlPostgresConfig(CONNECTION_NAME, "postgres", IAM_USER)
        with self.assertRaisesRegex(ValueError, "Cloud SQL IAM"):
            CloudSqlPostgresConfig(CONNECTION_NAME, "pulpo_authority", "postgres")
        with self.assertRaisesRegex(ValueError, "username form"):
            CloudSqlPostgresConfig(
                CONNECTION_NAME,
                "pulpo_authority",
                "pulpo-authority@pulpo-project.iam.gserviceaccount.com",
            )

    def test_default_connector_uses_lazy_refresh_and_private_ip(self):
        connector = FakeConnector()
        constructor_calls = []

        def constructor(**kwargs):
            constructor_calls.append(kwargs)
            return connector

        with patch.object(
            cloudsql_postgres,
            "_connector_dependencies",
            return_value=(constructor, SimpleNamespace(PRIVATE="PRIVATE")),
        ):
            factory = CloudSqlPostgresConnectionFactory(self._config())
            factory()

        self.assertEqual([{"refresh_strategy": "LAZY"}], constructor_calls)
        self.assertEqual("PRIVATE", connector.calls[0][1]["ip_type"])


if __name__ == "__main__":
    unittest.main()

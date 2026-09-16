from __future__ import annotations

import unittest

from pulpo_authority_service.cloud_sql_state import (
    DATABASE_IAM_USER,
    DATABASE_NAME,
    DRIVER,
    INSTANCE_CONNECTION_NAME,
    PulpoAuthorityCloudSqlConnectionFactory,
)


class FakeCursor:
    def __init__(self) -> None:
        self.calls = []
        self.rowcount = 1
        self.fetchone_value = ("row",)

    def execute(self, operation, params=None):
        self.calls.append((operation, params))
        return self

    def fetchone(self):
        return self.fetchone_value


class FakeConnection:
    def __init__(self) -> None:
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
    def __init__(self) -> None:
        self.calls = []
        self.connection = FakeConnection()
        self.closes = 0

    def connect(self, instance_connection_name, driver, **kwargs):
        self.calls.append((instance_connection_name, driver, kwargs))
        return self.connection

    def close(self):
        self.closes += 1


class CloudSqlAuthorityConnectionFactoryTests(unittest.TestCase):
    def test_exact_private_iam_connection_is_pinned_without_password_path(self):
        connector = FakeConnector()
        factory = PulpoAuthorityCloudSqlConnectionFactory(connector)

        factory()

        self.assertEqual(
            [
                (
                    INSTANCE_CONNECTION_NAME,
                    DRIVER,
                    {
                        "user": DATABASE_IAM_USER,
                        "db": DATABASE_NAME,
                        "enable_iam_auth": True,
                        "ip_type": "PRIVATE",
                    },
                )
            ],
            connector.calls,
        )
        _, _, kwargs = connector.calls[0]
        self.assertEqual("dulcet-opus-499511-a5:us-west1:pulpo-authority-db", INSTANCE_CONNECTION_NAME)
        self.assertEqual("pulpo_authority", DATABASE_NAME)
        self.assertEqual("pulpo-authority@dulcet-opus-499511-a5.iam", DATABASE_IAM_USER)
        self.assertEqual("pg8000", DRIVER)
        for forbidden in ("password", "host", "port", "ssl_context"):
            self.assertNotIn(forbidden, kwargs)

    def test_adapter_preserves_postgres_state_execute_contract(self):
        connector = FakeConnector()
        connection = PulpoAuthorityCloudSqlConnectionFactory(connector)()

        first = connection.execute("BEGIN")
        second = connection.execute("SELECT payload FROM state WHERE id = %s", (7,))
        second.fetchone_value = ("payload",)

        self.assertEqual([("BEGIN", None)], first.calls)
        self.assertEqual(
            [("SELECT payload FROM state WHERE id = %s", (7,))],
            second.calls,
        )
        self.assertEqual(("payload",), second.fetchone())
        self.assertEqual(1, second.rowcount)

        connection.commit()
        connection.rollback()
        connection.close()
        self.assertEqual((1, 1, 1), (
            connector.connection.commits,
            connector.connection.rollbacks,
            connector.connection.closes,
        ))

    def test_injected_connector_is_not_closed_by_factory(self):
        connector = FakeConnector()
        factory = PulpoAuthorityCloudSqlConnectionFactory(connector)

        factory.close()

        self.assertEqual(0, connector.closes)


if __name__ == "__main__":
    unittest.main()

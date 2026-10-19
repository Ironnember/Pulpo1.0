from __future__ import annotations

import unittest

from pulpo_authority_service.cloud_sql_probe import (
    EXPECTED_RUNTIME_ROLE,
    EXPECTED_SEARCH_PATH,
    probe_authority_database,
)
from pulpo_authority_service.cloud_sql_state import DATABASE_IAM_USER, DATABASE_NAME


class FakeCursor:
    def __init__(self, row):
        self.row = row
        self.calls = []

    def execute(self, operation, params=None):
        self.calls.append((operation, params))
        return self

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, row):
        self.cursor_obj = FakeCursor(row)
        self.rollbacks = 0
        self.closes = 0

    def execute(self, operation, params=None):
        return self.cursor_obj.execute(operation, params)

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closes += 1


class FakeFactory:
    def __init__(self, row):
        self.connection = FakeConnection(row)
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.connection


def good_row():
    return (
        DATABASE_NAME,
        DATABASE_IAM_USER,
        DATABASE_IAM_USER,
        EXPECTED_SEARCH_PATH,
        "160009",
        False,
        False,
        False,
        False,
        False,
        True,
        False,
    )


class CloudSqlAuthorityProbeTests(unittest.TestCase):
    def test_exact_least_privilege_session_produces_read_only_evidence(self):
        factory = FakeFactory(good_row())

        evidence = probe_authority_database(factory)

        self.assertEqual(1, factory.calls)
        self.assertEqual(DATABASE_NAME, evidence["database"])
        self.assertEqual(DATABASE_IAM_USER, evidence["database_user"])
        self.assertEqual(EXPECTED_RUNTIME_ROLE, evidence["runtime_role"])
        self.assertEqual(EXPECTED_SEARCH_PATH, evidence["search_path"])
        self.assertEqual(160009, evidence["postgres_version_num"])
        self.assertEqual(
            {
                "instance_connection_name": "dulcet-opus-499511-a5:us-west1:pulpo-authority-db",
                "driver": "pg8000",
                "ip_type": "PRIVATE",
                "automatic_iam_database_authentication": True,
                "transport_encryption": "connector_managed_tls",
            },
            evidence["connection_contract"],
        )
        self.assertNotIn("session_tls", evidence)
        self.assertFalse(evidence["admin_flags"]["cloudsqlsuperuser_member"])
        self.assertEqual("none", evidence["authority_effect"])
        self.assertEqual(1, factory.connection.rollbacks)
        self.assertEqual(1, factory.connection.closes)
        [(sql, params)] = factory.connection.cursor_obj.calls
        self.assertTrue(sql.lstrip().upper().startswith("SELECT\n"))
        self.assertNotIn("pg_stat_ssl", sql)
        self.assertNotIn("pg_backend_pid()", sql)
        self.assertIn("cloudsqlsuperuser", sql)
        self.assertIn("FROM pg_roles", sql)
        self.assertNotIn(";", sql)
        self.assertEqual((EXPECTED_RUNTIME_ROLE,), params)

    def test_wrong_database_or_iam_identity_fails_closed(self):
        for index, replacement, message in (
            (0, "postgres", "database identity"),
            (1, "postgres", "IAM database identity"),
            (2, "postgres", "IAM database identity"),
        ):
            with self.subTest(index=index):
                row = list(good_row())
                row[index] = replacement
                factory = FakeFactory(tuple(row))
                with self.assertRaisesRegex(RuntimeError, message):
                    probe_authority_database(factory)
                self.assertEqual(1, factory.connection.rollbacks)
                self.assertEqual(1, factory.connection.closes)

    def test_role_search_path_version_and_admin_drift_fail_closed(self):
        cases = (
            (3, "public", "search_path"),
            (4, "150014", "PostgreSQL 16"),
            (5, True, "superuser"),
            (6, True, "createrole"),
            (7, True, "createdb"),
            (8, True, "replication"),
            (9, True, "bypassrls"),
            (10, False, "runtime-role membership"),
            (11, True, "cloudsqlsuperuser membership"),
        )
        for index, replacement, message in cases:
            with self.subTest(index=index):
                row = list(good_row())
                row[index] = replacement
                with self.assertRaisesRegex(RuntimeError, message):
                    probe_authority_database(FakeFactory(tuple(row)))

    def test_missing_or_malformed_probe_row_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "unexpected row shape"):
            probe_authority_database(FakeFactory(None))
        with self.assertRaisesRegex(RuntimeError, "unexpected row shape"):
            probe_authority_database(FakeFactory(good_row()[:-1]))


if __name__ == "__main__":
    unittest.main()

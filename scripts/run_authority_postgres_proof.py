"""Require an explicit disposable local database and reject skipped authority tests.

The existing PostgreSQL tests drop their state table. This runner therefore
accepts only a loopback connection to the dedicated pulpo_authority_test database.
It does not provision a server or authorize access to deployment state.
"""
from pathlib import Path
import os
import sys
import unittest


def main():
    if os.environ.get("PULPO_AUTHORITY_TEST_ALLOW_RESET") != "1":
        raise SystemExit("Explicit disposable-database reset opt-in is required")
    dsn = os.environ.get("PULPO_AUTHORITY_TEST_POSTGRES_DSN")
    if not dsn:
        raise SystemExit("A disposable PostgreSQL test DSN is required")
    from psycopg.conninfo import conninfo_to_dict

    settings = conninfo_to_dict(dsn)
    if (settings.get("host") != "127.0.0.1"
            or settings.get("dbname") != "pulpo_authority_test"
            or "service" in settings or "hostaddr" in settings):
        raise SystemExit("Only the dedicated loopback test database is accepted")
    # Do not let ambient libpq routing/options redirect a destructive test.
    for name in tuple(os.environ):
        if name.startswith("PG"):
            del os.environ[name]
    repo = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(repo / "authority-service/src"), str(repo)]
    suite = unittest.defaultTestLoader.discover(str(repo / "authority-service/tests"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.skipped or result.testsRun == 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

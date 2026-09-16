"""Read-only live probe for the exact Pulpo authority Cloud SQL session.

The probe deliberately does not construct ``PostgresAuthorityState`` because its
bootstrap path may create the canonical state table/row. This module is for the
preceding deployment gate: prove that the dedicated runtime identity can reach
the already-frozen private Cloud SQL database through automatic IAM database
authentication, and fail closed if the resulting PostgreSQL session does not
match the least-privilege boundary.

It performs only catalog/session reads. No Pulpo authority, database state, IAM,
or cloud resource is created or changed.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from .cloud_sql_state import (
    DATABASE_IAM_USER,
    DATABASE_NAME,
    PulpoAuthorityCloudSqlConnectionFactory,
)


EXPECTED_RUNTIME_ROLE = "pulpo_authority_runtime"
EXPECTED_SEARCH_PATH = "pulpo_authority, pg_catalog"

_PROBE_SQL = """
SELECT
    current_database(),
    current_user,
    session_user,
    current_setting('search_path'),
    current_setting('server_version_num'),
    COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), FALSE),
    role.rolsuper,
    role.rolcreaterole,
    role.rolcreatedb,
    role.rolreplication,
    role.rolbypassrls,
    pg_has_role(current_user, %s, 'MEMBER'),
    pg_has_role(current_user, 'cloudsqlsuperuser', 'MEMBER')
FROM pg_roles AS role
WHERE role.rolname = current_user
"""


def _require_bool(value: object, expected: bool, field: str) -> None:
    if value is not expected:
        raise RuntimeError(f"Cloud SQL probe {field} mismatch")


def probe_authority_database(
    connection_factory: Callable[[], Any] | None = None,
) -> dict[str, object]:
    """Return verified read-only session evidence for the exact authority DB.

    The default factory uses the pinned private-IP/IAM Cloud SQL connector path.
    Tests inject a fake connection factory so CI exercises the exact fail-closed
    assertions without acquiring cloud authority.
    """

    owns_factory = connection_factory is None
    factory: Any = connection_factory or PulpoAuthorityCloudSqlConnectionFactory()
    connection = factory()
    try:
        row = connection.execute(_PROBE_SQL, (EXPECTED_RUNTIME_ROLE,)).fetchone()
        if row is None or len(row) != 13:
            raise RuntimeError("Cloud SQL probe returned an unexpected row shape")

        (
            database_name,
            current_user,
            session_user,
            search_path,
            server_version_num,
            session_ssl,
            is_superuser,
            can_create_role,
            can_create_database,
            can_replicate,
            can_bypass_rls,
            runtime_role_member,
            cloudsqlsuperuser_member,
        ) = row

        if database_name != DATABASE_NAME:
            raise RuntimeError("Cloud SQL probe database identity mismatch")
        if current_user != DATABASE_IAM_USER or session_user != DATABASE_IAM_USER:
            raise RuntimeError("Cloud SQL probe IAM database identity mismatch")
        if search_path != EXPECTED_SEARCH_PATH:
            raise RuntimeError("Cloud SQL probe search_path mismatch")
        try:
            server_version = int(server_version_num)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Cloud SQL probe server version is invalid") from exc
        if server_version < 160000 or server_version >= 170000:
            raise RuntimeError("Cloud SQL probe is not connected to PostgreSQL 16")
        _require_bool(session_ssl, True, "session TLS")

        for value, field in (
            (is_superuser, "superuser"),
            (can_create_role, "createrole"),
            (can_create_database, "createdb"),
            (can_replicate, "replication"),
            (can_bypass_rls, "bypassrls"),
            (cloudsqlsuperuser_member, "cloudsqlsuperuser membership"),
        ):
            _require_bool(value, False, field)
        _require_bool(runtime_role_member, True, "runtime-role membership")

        return {
            "schema": "pulpo.authority-cloudsql-connectivity.v0",
            "database": database_name,
            "database_user": current_user,
            "runtime_role": EXPECTED_RUNTIME_ROLE,
            "search_path": search_path,
            "postgres_version_num": server_version,
            "session_tls": True,
            "admin_flags": {
                "superuser": False,
                "createrole": False,
                "createdb": False,
                "replication": False,
                "bypassrls": False,
                "cloudsqlsuperuser_member": False,
            },
            "authority_effect": "none",
        }
    finally:
        try:
            connection.rollback()
        finally:
            connection.close()
            if owns_factory:
                factory.close()


def main() -> int:
    evidence = probe_authority_database()
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

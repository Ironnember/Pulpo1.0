"""One-shot, read-only proof of the Cloud SQL authority-state connection.

This module observes a previously authorized deployment object. It does not
create infrastructure, grant IAM, mutate database state, or establish runtime
authority. A failed or incomplete observation is classified as unknown.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from typing import Any, Callable

from .cloudsql_postgres import (
    CloudSqlPostgresConfig,
    CloudSqlPostgresConnectionFactory,
)


PROBE_SCHEMA = "pulpo.cloudsql-runtime-proof.v0"
EXECUTION_GATE = "PULPO_CLOUDSQL_PROBE_EXECUTE"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _require_identifier(value: str, field: str) -> None:
    if (
        not value
        or value != value.strip()
        or len(value) > 63
        or not value.replace("_", "").isalnum()
    ):
        raise ValueError(f"{field} must be a bounded PostgreSQL identifier")


@dataclass(frozen=True)
class CloudSqlProbeSpec:
    connection: CloudSqlPostgresConfig
    runtime_role: str
    schema: str
    expected_search_path: str

    def __post_init__(self) -> None:
        _require_identifier(self.runtime_role, "runtime_role")
        _require_identifier(self.schema, "schema")
        if (
            not self.expected_search_path
            or self.expected_search_path != self.expected_search_path.strip()
            or len(self.expected_search_path) > 256
        ):
            raise ValueError("expected_search_path must be bounded canonical text")

    @property
    def intent_hash(self) -> str:
        return sha256(_canonical(asdict(self))).hexdigest()


def _one(cursor: Any, label: str) -> tuple[Any, ...]:
    row = cursor.fetchone()
    if row is None:
        raise RuntimeError(f"{label} observation unavailable")
    return tuple(row)


def _expect(condition: bool, label: str) -> None:
    if not condition:
        raise RuntimeError(f"{label} invariant mismatch")


def run_cloudsql_probe(
    spec: CloudSqlProbeSpec,
    connection_factory: Callable[[], Any],
) -> dict[str, object]:
    """Verify the frozen runtime boundary without committing a database write."""

    connection = connection_factory()
    try:
        connection.execute("BEGIN READ ONLY")

        identity = _one(
            connection.execute(
                "SELECT current_user, session_user, current_database(), "
                "current_setting('transaction_read_only'), current_setting('search_path')"
            ),
            "identity",
        )
        _expect(identity[0] == spec.connection.iam_user, "current user")
        _expect(identity[1] == spec.connection.iam_user, "session user")
        _expect(identity[2] == spec.connection.database, "database")
        _expect(identity[3] == "on", "read-only transaction")
        _expect(identity[4] == spec.expected_search_path, "search path")

        transport = _one(
            connection.execute(
                "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
            ),
            "transport",
        )
        _expect(transport == (True,), "encrypted transport")

        membership = _one(
            connection.execute(
                "SELECT pg_has_role(current_user, %s, 'MEMBER'), "
                "has_database_privilege(current_user, current_database(), 'CONNECT'), "
                "has_schema_privilege(current_user, %s, 'USAGE'), "
                "has_schema_privilege(current_user, %s, 'CREATE')",
                (spec.runtime_role, spec.schema, spec.schema),
            ),
            "runtime privileges",
        )
        _expect(membership == (True, True, True, True), "runtime privileges")

        iam_user = _one(
            connection.execute(
                "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls FROM pg_roles WHERE rolname = current_user"
            ),
            "IAM database user",
        )
        _expect(
            iam_user == (True, False, False, False, False, False),
            "IAM database user privilege",
        )

        role = _one(
            connection.execute(
                "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls FROM pg_roles WHERE rolname = %s",
                (spec.runtime_role,),
            ),
            "runtime role",
        )
        _expect(
            role == (False, False, False, False, False, False),
            "runtime role privilege",
        )

        owner = _one(
            connection.execute(
                "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = %s",
                (spec.schema,),
            ),
            "schema owner",
        )
        _expect(owner == (spec.runtime_role,), "schema owner")

        return {
            "schema": PROBE_SCHEMA,
            "status": "PASS",
            "classification": "RECORDED",
            "intent_hash": spec.intent_hash,
            "attempt_count": 1,
            "connection": {
                "instance": spec.connection.instance_connection_name,
                "database": spec.connection.database,
                "iam_user": spec.connection.iam_user,
                "ip_type": "PRIVATE",
                "authentication": "AUTOMATIC_IAM",
                "password_supplied": False,
            },
            "observations": {
                "current_user_matches": True,
                "session_user_matches": True,
                "database_matches": True,
                "transaction_read_only": True,
                "encrypted_transport": True,
                "runtime_role_member": True,
                "database_connect": True,
                "schema_usage": True,
                "schema_create": True,
                "schema_owner_matches": True,
                "iam_user_least_privilege": True,
                "runtime_role_least_privilege": True,
                "search_path_matches": True,
            },
            "database_commit": False,
            "authority_effect": "none",
            "reconciliation_required": True,
            "claim_boundary": (
                "This read-only observation does not prove authority-service deployment, "
                "independent human authority, recovery, production containment, or "
                "external consequence custody."
            ),
        }
    finally:
        try:
            connection.rollback()
        finally:
            connection.close()


def _spec_from_environment() -> CloudSqlProbeSpec:
    return CloudSqlProbeSpec(
        connection=CloudSqlPostgresConfig(
            instance_connection_name=os.environ["PULPO_CLOUDSQL_INSTANCE"],
            database=os.environ["PULPO_CLOUDSQL_DATABASE"],
            iam_user=os.environ["PULPO_CLOUDSQL_IAM_USER"],
        ),
        runtime_role=os.environ["PULPO_CLOUDSQL_RUNTIME_ROLE"],
        schema=os.environ["PULPO_CLOUDSQL_SCHEMA"],
        expected_search_path=os.environ["PULPO_CLOUDSQL_SEARCH_PATH"],
    )


def main() -> int:
    if os.environ.get(EXECUTION_GATE) != "1":
        print(
            json.dumps(
                {
                    "schema": PROBE_SCHEMA,
                    "status": "BLOCKED",
                    "classification": "UNKNOWN",
                    "reason": "execution gate is closed",
                    "authority_effect": "none",
                },
                sort_keys=True,
            )
        )
        return 2

    factory: CloudSqlPostgresConnectionFactory | None = None
    try:
        spec = _spec_from_environment()
        factory = CloudSqlPostgresConnectionFactory(spec.connection)
        result = run_cloudsql_probe(spec, factory)
    except Exception:
        result = {
            "schema": PROBE_SCHEMA,
            "status": "UNKNOWN",
            "classification": "UNKNOWN",
            "reason": "private IAM Cloud SQL observation failed closed",
            "attempt_count": 1,
            "authority_effect": "none",
            "reconciliation_required": True,
        }
        print(json.dumps(result, sort_keys=True))
        return 1
    finally:
        if factory is not None:
            factory.close()

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Private-IAM Cloud SQL connection factory for authority state.

The factory supplies only the connection object consumed by
``PostgresAuthorityState``. It does not create databases, users, IAM grants, or
network routes, and it exposes no password or public-IP configuration path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def _require_text(value: str, field: str) -> None:
    if not value or value != value.strip() or len(value) > 512:
        raise ValueError(f"{field} must be bounded canonical text")


def _connector_dependencies() -> tuple[Any, Any]:
    try:
        from google.cloud.sql.connector import Connector, IPTypes
    except ImportError as exc:
        raise RuntimeError(
            "Cloud SQL connector dependencies are required for live authority state"
        ) from exc
    return Connector, IPTypes


@dataclass(frozen=True)
class CloudSqlPostgresConfig:
    instance_connection_name: str
    database: str
    iam_user: str

    def __post_init__(self) -> None:
        for value, field in (
            (self.instance_connection_name, "instance_connection_name"),
            (self.database, "database"),
            (self.iam_user, "iam_user"),
        ):
            _require_text(value, field)

        parts = self.instance_connection_name.split(":")
        if len(parts) != 3 or any(
            not part or "/" in part or any(char.isspace() for char in part)
            for part in parts
        ):
            raise ValueError("instance_connection_name must be project:region:instance")
        if self.database in {"postgres", "template0", "template1"}:
            raise ValueError("authority state requires a dedicated database")
        if self.iam_user.endswith(".gserviceaccount.com"):
            raise ValueError("iam_user must use the Cloud SQL service-account username form")
        if not self.iam_user.endswith(".iam") or "@" not in self.iam_user:
            raise ValueError("iam_user must be a Cloud SQL IAM service-account database user")


class _Pg8000Connection:
    """Adapt pg8000's cursor API to the state adapter's connection contract."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def execute(self, statement: str, parameters: object | None = None) -> Any:
        cursor = self._connection.cursor()
        if parameters is None:
            cursor.execute(statement)
        else:
            cursor.execute(statement, parameters)
        return cursor

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()

    def close(self) -> None:
        self._connection.close()


class CloudSqlPostgresConnectionFactory:
    """Create private-IP PostgreSQL connections with automatic IAM auth.

    The default connector uses Application Default Credentials. Tests may
    inject a connector while substituting the dependency loader; the public
    factory exposes no IP-mode selection.
    """

    def __init__(
        self,
        config: CloudSqlPostgresConfig,
        *,
        connector: Any | None = None,
    ) -> None:
        if not isinstance(config, CloudSqlPostgresConfig):
            raise ValueError("config must be CloudSqlPostgresConfig")
        Connector, IPTypes = _connector_dependencies()
        if connector is None:
            connector = Connector(refresh_strategy="LAZY")

        self.config = config
        self.connector = connector
        self._private_ip_token = IPTypes.PRIVATE

    def __call__(self) -> _Pg8000Connection:
        try:
            connection = self.connector.connect(
                self.config.instance_connection_name,
                "pg8000",
                user=self.config.iam_user,
                db=self.config.database,
                enable_iam_auth=True,
                ip_type=self._private_ip_token,
            )
        except Exception as exc:
            raise RuntimeError("private IAM Cloud SQL authority connection unavailable") from exc
        return _Pg8000Connection(connection)

    def close(self) -> None:
        self.connector.close()

"""Exact Cloud SQL IAM connection factory for Pulpo authority state.

This module contains no authority decision logic and performs no cloud-resource
creation or IAM mutation. It binds the existing ``PostgresAuthorityState``
connection seam to the already-frozen production Cloud SQL identity using the
Cloud SQL Python Connector, private IP only, automatic IAM database
authentication, and the synchronous PostgreSQL driver reviewed for this path.

The connector uses Application Default Credentials from the execution identity.
Possession of this transport does not grant authority: Google Cloud IAM, the
Cloud SQL IAM database user, PostgreSQL privileges, and Pulpo's own authority
state remain independently enforced boundaries.
"""

from __future__ import annotations

from typing import Any


INSTANCE_CONNECTION_NAME = "dulcet-opus-499511-a5:us-west1:pulpo-authority-db"
DATABASE_NAME = "pulpo_authority"
DATABASE_IAM_USER = "pulpo-authority@dulcet-opus-499511-a5.iam"
DRIVER = "pg8000"


class _Pg8000ConnectionAdapter:
    """Expose the minimal connection API required by ``PostgresAuthorityState``."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def execute(self, operation: str, params: object | None = None) -> Any:
        cursor = self._connection.cursor()
        if params is None:
            cursor.execute(operation)
        else:
            cursor.execute(operation, params)
        return cursor

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()

    def close(self) -> None:
        self._connection.close()


class PulpoAuthorityCloudSqlConnectionFactory:
    """Create exact private Cloud SQL PostgreSQL connections using IAM auth.

    A connector may be injected for tests. Production construction lazily imports
    the optional Google dependency and creates one connector configured for lazy
    refresh. Every connection call explicitly pins automatic IAM authentication
    and private IP so dependency defaults cannot silently widen the path.
    """

    def __init__(self, connector: Any | None = None) -> None:
        self._owns_connector = connector is None
        if connector is None:
            try:
                from google.cloud.sql.connector import Connector, IPTypes
            except ImportError as exc:
                raise RuntimeError(
                    "cloud-sql-python-connector and pg8000 are required for the "
                    "live Pulpo authority Cloud SQL connection"
                ) from exc
            connector = Connector(refresh_strategy="LAZY")
            private_ip: object = IPTypes.PRIVATE
        else:
            private_ip = "PRIVATE"
        self.connector = connector
        self._private_ip = private_ip

    def __call__(self) -> _Pg8000ConnectionAdapter:
        """Return one connection bound to the exact authority database."""
        connection = self.connector.connect(
            INSTANCE_CONNECTION_NAME,
            DRIVER,
            user=DATABASE_IAM_USER,
            db=DATABASE_NAME,
            enable_iam_auth=True,
            ip_type=self._private_ip,
        )
        return _Pg8000ConnectionAdapter(connection)

    def close(self) -> None:
        """Release connector background resources when this factory owns them."""
        if self._owns_connector:
            self.connector.close()

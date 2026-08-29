"""Google Cloud Storage evidence sink for the independent authority boundary.

The authority service does not configure or lock retention. Deployment must
provision one exact bucket whose retention policy is already effective and
irreversibly locked. This sink verifies that boundary, then writes each exact
authority evidence bundle under its SHA-256 digest with a create-only object
precondition. A retry may observe the existing object only if its bytes match
exactly; the sink never overwrites evidence.
"""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Any


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _require_text(value: str, field: str) -> None:
    if not value or value != value.strip():
        raise ValueError(f"{field} must be non-empty canonical text")


def _precondition_failed(exc: Exception) -> bool:
    code = getattr(exc, "code", None)
    if callable(code):
        code = code()
    try:
        return int(code) == 412
    except (TypeError, ValueError):
        return False


class GoogleCloudLockedEvidenceSink:
    """Create-only evidence writer to one pre-locked Cloud Storage bucket."""

    def __init__(
        self,
        *,
        bucket_name: str,
        object_prefix: str,
        minimum_retention_seconds: int,
        client: Any | None = None,
    ) -> None:
        _require_text(bucket_name, "bucket_name")
        if "/" in bucket_name:
            raise ValueError("bucket_name must be a bare Cloud Storage bucket name")
        if not isinstance(minimum_retention_seconds, int) or isinstance(minimum_retention_seconds, bool):
            raise ValueError("minimum_retention_seconds must be an integer")
        if minimum_retention_seconds <= 0:
            raise ValueError("minimum_retention_seconds must be positive")
        prefix = object_prefix.strip("/")
        if not prefix or prefix != object_prefix.strip("/"):
            raise ValueError("object_prefix must contain non-slash canonical text")
        if object_prefix != object_prefix.strip():
            raise ValueError("object_prefix must be canonical text")

        if client is None:
            try:
                from google.cloud import storage
            except ImportError as exc:
                raise RuntimeError(
                    "google-cloud-storage is required for the live GCP evidence sink"
                ) from exc
            client = storage.Client()

        bucket = client.bucket(bucket_name)
        bucket.reload()
        if str(getattr(bucket, "name", "")) != bucket_name:
            raise RuntimeError("Cloud Storage bucket response crossed the pinned bucket identity")
        if getattr(bucket, "retention_policy_locked", None) is not True:
            raise RuntimeError("authority evidence bucket retention policy is not locked")
        retention = getattr(bucket, "retention_period", None)
        if isinstance(retention, bool) or not isinstance(retention, int):
            raise RuntimeError("authority evidence bucket retention period is unavailable")
        if retention < minimum_retention_seconds:
            raise RuntimeError("authority evidence bucket retention period is below the pinned minimum")
        if getattr(bucket, "retention_policy_effective_time", None) is None:
            raise RuntimeError("authority evidence bucket retention policy is not effective")

        self.client = client
        self.bucket = bucket
        self.bucket_name = bucket_name
        self.object_prefix = prefix
        self.minimum_retention_seconds = minimum_retention_seconds

    def append(self, bundle: dict[str, object]) -> str:
        canonical = _canonical(bundle)
        digest = sha256(canonical).hexdigest()
        encoded = canonical + b"\n"
        object_name = f"{self.object_prefix}/{digest}.json"
        blob = self.bucket.blob(object_name)

        try:
            blob.upload_from_string(
                encoded,
                content_type="application/json",
                if_generation_match=0,
                checksum="crc32c",
            )
        except Exception as exc:
            if not _precondition_failed(exc):
                raise RuntimeError("authority evidence object creation failed") from exc
            try:
                existing = blob.download_as_bytes(checksum="crc32c")
            except Exception as read_exc:
                raise RuntimeError("existing authority evidence object could not be verified") from read_exc
            if existing != encoded:
                raise RuntimeError("existing authority evidence object diverges from its digest")

        return digest

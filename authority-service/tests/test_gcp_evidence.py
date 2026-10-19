from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import unittest

from pulpo_authority_service.gcp_evidence import GoogleCloudLockedEvidenceSink


BUCKET = "pulpo-authority-evidence-proof"
PREFIX = "authority/v0"
RETENTION = 31_536_000


class FakePreconditionFailed(Exception):
    code = 412


class FakeOtherFailure(Exception):
    code = 503


class FakeBlob:
    def __init__(self, name, bucket):
        self.name = name
        self.bucket = bucket
        self.upload_calls = []
        self.download_calls = []

    def upload_from_string(self, data, **kwargs):
        self.upload_calls.append((data, kwargs))
        if self.bucket.upload_failure is not None:
            raise self.bucket.upload_failure
        self.bucket.objects[self.name] = bytes(data)

    def download_as_bytes(self, **kwargs):
        self.download_calls.append(kwargs)
        if self.bucket.download_failure is not None:
            raise self.bucket.download_failure
        return self.bucket.objects[self.name]


class FakeBucket:
    def __init__(self):
        self.name = BUCKET
        self.retention_policy_locked = True
        self.retention_period = RETENTION
        self.retention_policy_effective_time = datetime(2026, 8, 29, tzinfo=timezone.utc)
        self.reload_calls = 0
        self.blobs = {}
        self.objects = {}
        self.upload_failure = None
        self.download_failure = None

    def reload(self):
        self.reload_calls += 1

    def blob(self, name):
        self.blobs.setdefault(name, FakeBlob(name, self))
        return self.blobs[name]


class FakeClient:
    def __init__(self, bucket=None):
        self.value = bucket or FakeBucket()
        self.bucket_calls = []

    def bucket(self, name):
        self.bucket_calls.append(name)
        return self.value


class GoogleCloudLockedEvidenceSinkTests(unittest.TestCase):
    def _sink(self, bucket=None, minimum=RETENTION):
        client = FakeClient(bucket)
        return GoogleCloudLockedEvidenceSink(
            bucket_name=BUCKET,
            object_prefix=PREFIX,
            minimum_retention_seconds=minimum,
            client=client,
        ), client

    def test_create_only_upload_uses_digest_name_generation_precondition_and_crc32c(self):
        sink, client = self._sink()
        bundle = {"schema": "pulpo.authority-evidence.v1", "sequence": 7, "value": "exact"}
        canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
        digest = sha256(canonical).hexdigest()

        returned = sink.append(bundle)
        blob = client.value.blobs[f"{PREFIX}/{digest}.json"]

        self.assertEqual(digest, returned)
        self.assertEqual([BUCKET], client.bucket_calls)
        self.assertEqual(1, client.value.reload_calls)
        self.assertEqual(canonical + b"\n", blob.upload_calls[0][0])
        self.assertEqual("application/json", blob.upload_calls[0][1]["content_type"])
        self.assertEqual(0, blob.upload_calls[0][1]["if_generation_match"])
        self.assertEqual("crc32c", blob.upload_calls[0][1]["checksum"])
        self.assertEqual([], blob.download_calls)

    def test_existing_create_only_object_is_accepted_only_when_bytes_match_exactly(self):
        sink, client = self._sink()
        bundle = {"schema": "pulpo.authority-evidence.v1", "sequence": 1}
        canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
        digest = sha256(canonical).hexdigest()
        name = f"{PREFIX}/{digest}.json"
        client.value.objects[name] = canonical + b"\n"
        client.value.upload_failure = FakePreconditionFailed("already exists")

        self.assertEqual(digest, sink.append(bundle))
        blob = client.value.blobs[name]
        self.assertEqual([{"checksum": "crc32c"}], blob.download_calls)

        client.value.objects[name] = b"attacker-data\n"
        with self.assertRaisesRegex(RuntimeError, "diverges"):
            sink.append(bundle)

    def test_non_precondition_upload_and_existing_object_read_fail_closed(self):
        sink, client = self._sink()
        bundle = {"schema": "pulpo.authority-evidence.v1", "sequence": 2}
        client.value.upload_failure = FakeOtherFailure("storage unavailable")
        with self.assertRaisesRegex(RuntimeError, "creation failed"):
            sink.append(bundle)

        canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
        digest = sha256(canonical).hexdigest()
        client.value.objects[f"{PREFIX}/{digest}.json"] = canonical + b"\n"
        client.value.upload_failure = FakePreconditionFailed("exists")
        client.value.download_failure = RuntimeError("read unavailable")
        with self.assertRaisesRegex(RuntimeError, "could not be verified"):
            sink.append(bundle)

    def test_bucket_identity_locked_effective_retention_and_minimum_are_mandatory(self):
        cases = []

        wrong_identity = FakeBucket()
        wrong_identity.name = "attacker-bucket"
        cases.append((wrong_identity, RETENTION, "pinned bucket identity"))

        unlocked = FakeBucket()
        unlocked.retention_policy_locked = False
        cases.append((unlocked, RETENTION, "not locked"))

        no_retention = FakeBucket()
        no_retention.retention_period = None
        cases.append((no_retention, RETENTION, "retention period is unavailable"))

        short = FakeBucket()
        cases.append((short, RETENTION + 1, "below the pinned minimum"))

        ineffective = FakeBucket()
        ineffective.retention_policy_effective_time = None
        cases.append((ineffective, RETENTION, "not effective"))

        for bucket, minimum, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                self._sink(bucket, minimum=minimum)

    def test_configuration_rejects_ambiguous_bucket_prefix_and_retention(self):
        client = FakeClient()
        for bucket_name in ("", " bucket", "bucket/path"):
            with self.subTest(bucket_name=bucket_name), self.assertRaises(ValueError):
                GoogleCloudLockedEvidenceSink(
                    bucket_name=bucket_name,
                    object_prefix=PREFIX,
                    minimum_retention_seconds=RETENTION,
                    client=client,
                )
        for prefix in ("", "/authority/v0", "authority/v0/", " authority/v0"):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                GoogleCloudLockedEvidenceSink(
                    bucket_name=BUCKET,
                    object_prefix=prefix,
                    minimum_retention_seconds=RETENTION,
                    client=client,
                )
        for minimum in (0, -1, True):
            with self.subTest(minimum=minimum), self.assertRaises(ValueError):
                GoogleCloudLockedEvidenceSink(
                    bucket_name=BUCKET,
                    object_prefix=PREFIX,
                    minimum_retention_seconds=minimum,
                    client=client,
                )


if __name__ == "__main__":
    unittest.main()

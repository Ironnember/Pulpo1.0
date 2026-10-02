import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from pulpo.audit_parallel import AuditDigestCache, AuditVerificationEngine
from pulpo.performance_tuning import (
    AdaptiveAuditVerificationEngine,
    AuditPerformanceTuner,
    PerformanceProfile,
    SystemFingerprint,
)
from pulpo.effect_reconcile import (
    EffectEnvelope,
    ParallelEvidenceCollector,
    ShardedEvidenceDigestCache,
    SurfaceSpec,
    capture_envelope_surfaces,
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def audit_row(previous_hash, event, payload, timestamp_ns):
    payload_json = canonical(payload).decode()
    body = {
        "event": event,
        "payload": payload,
        "previous_hash": previous_hash,
        "timestamp_ns": timestamp_ns,
    }
    digest = sha256(canonical(body)).hexdigest()
    return event, payload_json, previous_hash, timestamp_ns, digest


class AuditParallelTests(unittest.TestCase):
    def test_digest_cache_is_bounded(self):
        cache = AuditDigestCache(max_entries=2)
        for index in range(3):
            cache.put(("event", str(index), "0" * 64, index), str(index))
        self.assertEqual(2, len(cache))

    def test_cached_digest_never_skips_current_chain_check(self):
        first = audit_row("0" * 64, "one", {"value": 1}, 1)
        second = audit_row(first[4], "two", {"value": 2}, 2)
        engine = AuditVerificationEngine(workers=0, cache_size=16)
        self.addCleanup(engine.close)

        self.assertTrue(engine.verify_rows([first, second]))
        broken = (second[0], second[1], "f" * 64, second[3], second[4])
        self.assertFalse(engine.verify_rows([first, broken]))

    def test_cached_digest_never_skips_stored_hash_check(self):
        row = audit_row("0" * 64, "one", {"value": 1}, 1)
        engine = AuditVerificationEngine(workers=0, cache_size=16)
        self.addCleanup(engine.close)

        self.assertTrue(engine.verify_rows([row]))
        tampered = (row[0], row[1], row[2], row[3], "f" * 64)
        self.assertFalse(engine.verify_rows([tampered]))

    def test_multi_process_result_matches_local_result(self):
        rows = []
        previous = "0" * 64
        for index in range(64):
            row = audit_row(previous, "event", {"index": index}, index + 1)
            rows.append(row)
            previous = row[4]

        local = AuditVerificationEngine(workers=0, cache_size=0)
        parallel = AuditVerificationEngine(workers=2, cache_size=0, parallel_threshold=1, batch_size=7)
        self.addCleanup(local.close)
        self.addCleanup(parallel.close)

        self.assertTrue(local.verify_rows(rows))
        # First pass primes without process startup; second substantial uncached
        # pass exercises the worker pool.
        self.assertTrue(parallel.verify_rows(rows))
        self.assertTrue(parallel.verify_rows(rows))

    def test_invalid_batch_size_is_rejected(self):
        with self.assertRaises(ValueError):
            AuditVerificationEngine(workers=2, batch_size=0)

    def test_batched_parallel_path_detects_tampered_stored_hash(self):
        rows = []
        previous = "0" * 64
        for index in range(32):
            row = audit_row(previous, "event", {"index": index}, index + 1)
            rows.append(row)
            previous = row[4]
        engine = AuditVerificationEngine(workers=2, cache_size=0, parallel_threshold=1, batch_size=5)
        self.addCleanup(engine.close)
        self.assertTrue(engine.verify_rows(rows))
        self.assertTrue(engine.verify_rows(rows))
        tampered = list(rows)
        row = tampered[-1]
        tampered[-1] = (row[0], row[1], row[2], row[3], "f" * 64)
        self.assertFalse(engine.verify_rows(tampered))


class AuditPerformanceTunerTests(unittest.TestCase):
    def benchmark_document(self):
        fingerprint = SystemFingerprint.detect()
        return {
            "schema": "pulpo.memory-scaling-benchmark.v2",
            "machine": {
                "platform": fingerprint.platform,
                "python": fingerprint.python,
                "cpu_count": fingerprint.cpu_count,
            },
            "parallel_threshold": 256,
            "results": [
                {
                    "records": 10000,
                    "workers": 1,
                    "batch_size": 256,
                    "median_seconds": 0.050,
                    "records_per_second": 200000.0,
                    "samples_seconds": [0.050],
                },
                {
                    "records": 10000,
                    "workers": min(4, fingerprint.cpu_count),
                    "batch_size": 256,
                    "median_seconds": 0.025,
                    "records_per_second": 400000.0,
                    "samples_seconds": [0.025],
                },
                {
                    "records": 50000,
                    "workers": 1,
                    "batch_size": 256,
                    "median_seconds": 0.250,
                    "records_per_second": 200000.0,
                    "samples_seconds": [0.250],
                },
                {
                    "records": 50000,
                    "workers": min(4, fingerprint.cpu_count),
                    "batch_size": 1024,
                    "median_seconds": 0.100,
                    "records_per_second": 500000.0,
                    "samples_seconds": [0.100],
                },
            ],
        }

    def test_benchmark_selects_workload_specific_profiles(self):
        tuner = AuditPerformanceTuner.from_benchmark_document(self.benchmark_document())
        small = tuner.profile_for(10000)
        large = tuner.profile_for(40000)
        self.assertEqual(256, small.batch_size)
        self.assertEqual(1024, large.batch_size)
        self.assertLessEqual(small.workers, SystemFingerprint.detect().cpu_count)
        self.assertLessEqual(large.workers, SystemFingerprint.detect().cpu_count)

    def test_profile_document_has_no_authority_effect(self):
        tuner = AuditPerformanceTuner.from_benchmark_document(self.benchmark_document())
        document = tuner.to_document()
        self.assertEqual("none", document["authority_effect"])

    def test_unapproved_batch_size_is_rejected(self):
        with self.assertRaises(ValueError):
            AuditPerformanceTuner(
                (PerformanceProfile(max_records=1000, workers=1, batch_size=999),)
            )

    def test_adaptive_engine_preserves_verification_semantics(self):
        rows = []
        previous = "0" * 64
        for index in range(16):
            row = audit_row(previous, "event", {"index": index}, index + 1)
            rows.append(row)
            previous = row[4]

        tuner = AuditPerformanceTuner(
            (
                PerformanceProfile(
                    max_records=1000,
                    workers=1,
                    batch_size=256,
                    source="test",
                ),
            )
        )
        adaptive = AdaptiveAuditVerificationEngine(tuner, cache_size=0)
        self.addCleanup(adaptive.close)
        self.assertTrue(adaptive.verify_rows(rows))
        broken = list(rows)
        row = broken[-1]
        broken[-1] = (row[0], row[1], row[2], row[3], "f" * 64)
        self.assertFalse(adaptive.verify_rows(broken))


class ParallelEvidenceTests(unittest.TestCase):
    def _envelope(self, roots):
        return EffectEnvelope(
            executable_path=str(Path(__file__).resolve()),
            executable_sha256="a" * 64,
            argv=("python",),
            workdir=str(Path(roots[0]).parent),
            source_sha="test-source",
            profile="test",
            expires_at_ns=1,
            surfaces=tuple(SurfaceSpec(root, "evidence") for root in roots),
        )

    def test_parallel_collection_matches_serial_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            roots = []
            for index in range(3):
                root = Path(directory) / f"surface-{index}"
                root.mkdir()
                (root / "evidence.txt").write_text(f"evidence-{index}", encoding="utf-8")
                roots.append(str(root))

            envelope = self._envelope(roots)
            serial = capture_envelope_surfaces(envelope)
            collector = ParallelEvidenceCollector(workers=3, cache_shards=4, cache_entries=32)
            self.addCleanup(collector.close)
            parallel = capture_envelope_surfaces(envelope, collector=collector)
            self.assertEqual(serial, parallel)

    def test_sharded_cache_does_not_hide_changed_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "surface"
            root.mkdir()
            path = root / "evidence.txt"
            path.write_text("before", encoding="utf-8")
            envelope = self._envelope([str(root)])
            collector = ParallelEvidenceCollector(workers=2, cache_shards=4, cache_entries=32)
            self.addCleanup(collector.close)

            before = collector.capture(envelope)[0]
            path.write_text("after", encoding="utf-8")
            after = collector.capture(envelope)[0]
            self.assertNotEqual(before.digest, after.digest)

    def test_sharded_digest_cache_reuses_only_exact_canonical_payload(self):
        cache = ShardedEvidenceDigestCache(shards=4, max_entries=8)
        first = {"a": 1, "b": [2, 3]}
        second = {"b": [2, 3], "a": 1}
        changed = {"a": 1, "b": [2, 4]}
        self.assertEqual(cache.digest(first), cache.digest(second))
        self.assertNotEqual(cache.digest(first), cache.digest(changed))


if __name__ == "__main__":
    unittest.main()

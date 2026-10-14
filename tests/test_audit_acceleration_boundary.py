"""Gladiator regressions: persisted values, real worker bootstrap, and integration."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from pulpo import GovernanceKernel, Policy, SQLiteKernelState, StateIntegrityError
from pulpo.audit_parallel import AuditVerificationEngine
from pulpo.performance_tuning import AuditPerformanceTuner, PerformanceProfile, SystemFingerprint
from pulpo.setup import run_setup, synthetic_audit_rows
from pulpo.effect_reconcile import ShardedEvidenceDigestCache
import pulpo.audit_worker_pool as worker_pool


class AccelerationBoundaryTests(unittest.TestCase):
    def test_sqlite_restart_rejects_coerced_values(self):
        for column, value, event in [("timestamp_ns", 1.5, "probe"), ("timestamp_ns", 1.000001, "probe"), ("event", b"probe", "b'probe'")]:
            with self.subTest(column=column, value=value), tempfile.TemporaryDirectory() as d:
                path = Path(d) / "state.sqlite"
                state = SQLiteKernelState(path)
                state.append(event, {"v": 1}, 1)
                state._connection.execute(f"UPDATE audit SET {column} = ?", (value,))
                state._connection.commit()
                state._connection.close()
                restarted = SQLiteKernelState(path)
                try:
                    with AuditVerificationEngine(workers=2, cache_size=0, parallel_threshold=1) as engine:
                        with self.assertRaises(StateIntegrityError):
                            GovernanceKernel(Policy(frozenset({"read"}), 0), state=restarted, audit_verification_engine=engine)
                finally:
                    restarted._connection.close()

    def test_kernel_checks_accelerated_sqlite_hash_on_every_pass(self):
        state = SQLiteKernelState(":memory:")
        self.addCleanup(state._connection.close)
        state.append("probe", {"v": 1}, 1)
        with AuditVerificationEngine(workers=2, cache_size=0, parallel_threshold=1) as engine:
            kernel = GovernanceKernel(Policy(frozenset({"read"}), 0), state=state, audit_verification_engine=engine)
            self.assertTrue(kernel.verify_audit())
            state._connection.execute("UPDATE audit SET hash = ?", ("f" * 64,))
            state._connection.commit()
            self.assertFalse(kernel.verify_audit())

    def test_cached_numeric_type_substitution_fails_closed(self):
        rows = synthetic_audit_rows(1)
        with AuditVerificationEngine(cache_size=8) as engine:
            self.assertTrue(engine.verify_rows(rows))
            for timestamp in [True, 1.0]:
                row = list(rows[0]); row[3] = timestamp
                self.assertFalse(engine.verify_rows([tuple(row)]))

    def test_seeded_matrix_local_cached_and_workers(self):
        rng = random.Random(293)
        engines = [AuditVerificationEngine(cache_size=0), AuditVerificationEngine(cache_size=512), AuditVerificationEngine(workers=2, cache_size=0, parallel_threshold=1, batch_size=7)]
        for engine in engines:
            self.addCleanup(engine.close)
        for trial in range(128):
            rows = synthetic_audit_rows(rng.randint(2, 64))
            bad = list(rows); index = rng.randrange(len(rows)); row = list(bad[index])
            field = rng.choice([0, 1, 2, 3, 4])
            row[field] = row[field] + 1 if field == 3 else ("f" * 64 if field in (2, 4) else (json.dumps({"poison": trial}) if field == 1 else "poison"))
            bad[index] = tuple(row)
            for engine in engines:
                self.assertTrue(engine.verify_rows(rows))
                self.assertTrue(engine.verify_rows(rows))
                self.assertFalse(engine.verify_rows(bad))

    def test_worker_bootstrap_does_not_inherit_environment_main_or_descriptor(self):
        # Synthetic credential marker and descriptor; no actual secret material.
        with tempfile.TemporaryDirectory() as d:
            helper = Path(d) / "worker.py"
            prelude = "import os, sys\nassert 'PULPO_SYNTHETIC_SECRET' not in os.environ\nassert 'pulpo.kernel' not in sys.modules\nassert 'CUSTODY_KERNEL' not in globals()\n"
            descriptor = None
            if os.name == "posix":
                import fcntl
                with open(Path(d) / "synthetic-custody", "w") as handle:
                    descriptor = fcntl.fcntl(handle.fileno(), fcntl.F_DUPFD, 200)
                os.set_inheritable(descriptor, True)
                prelude += f"try:\n os.fstat({descriptor})\nexcept OSError:\n pass\nelse:\n raise AssertionError('inherited custody descriptor')\n"
            helper.write_text(prelude + Path(worker_pool._WORKER_PATH).read_text())
            try:
                with patch.dict(os.environ, {"PULPO_SYNTHETIC_SECRET": "synthetic-marker"}), patch.object(worker_pool, "_WORKER_PATH", str(helper)), AuditVerificationEngine(workers=2, cache_size=0, parallel_threshold=1) as engine:
                    rows = synthetic_audit_rows(4)
                    self.assertTrue(engine.verify_rows(rows))
                    self.assertTrue(engine.verify_rows(rows))
                    workers = engine._executor._workers
                    self.assertTrue(all(worker.process.pid != os.getpid() for worker in workers))
                self.assertTrue(all(worker.process.poll() is not None for worker in workers))
            finally:
                if descriptor is not None:
                    os.close(descriptor)

    def test_failed_worker_never_returns_acceptance(self):
        with AuditVerificationEngine(workers=2, cache_size=0, parallel_threshold=1) as engine:
            rows = synthetic_audit_rows(4)
            engine.verify_rows(rows); engine.verify_rows(rows)
            for worker in engine._executor._workers:
                worker.process.kill(); worker.process.wait()
            with self.assertRaises(RuntimeError):
                engine.verify_rows(rows)

    def test_setup_checks_every_profile_and_worker_failure(self):
        tuner = AuditPerformanceTuner((PerformanceProfile(10000, 2, 256), PerformanceProfile(50000, 2, 1024)))
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "profile.json"; tuner.save(path)
            with patch("pulpo.audit_parallel.DigestWorkerPool", side_effect=RuntimeError("synthetic startup failure")) as factory:
                report = run_setup(profile_path=path, calibrate_if_needed=False)
                self.assertFalse(report["ready_for_test_use"])
                self.assertGreater(factory.call_count, 0)
            with patch("pulpo.audit_parallel.DigestWorkerPool", wraps=worker_pool.DigestWorkerPool) as factory:
                report = run_setup(profile_path=path, calibrate_if_needed=False)
                self.assertTrue(report["ready_for_test_use"])
                self.assertEqual(2, factory.call_count)

    def test_malformed_profiles_fall_back(self):
        for document in [[], None, {"schema": "pulpo.audit-performance-profile.v1", "authority_effect": "none", "fingerprint": asdict(SystemFingerprint.detect()), "profiles": [None]}]:
            with tempfile.TemporaryDirectory() as d:
                path = Path(d) / "profile.json"; path.write_text(json.dumps(document))
                report = run_setup(profile_path=path, calibrate_if_needed=False)
                self.assertEqual("CONSERVATIVE_FALLBACK", report["profile"]["status"])

    def test_document_cannot_define_its_own_batch_bounds(self):
        tuner = AuditPerformanceTuner.conservative(); document = tuner.to_document()
        document["allowed_batch_sizes"] = [999999999]
        document["profiles"][0]["batch_size"] = 999999999
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "profile.json"; path.write_text(json.dumps(document))
            with self.assertRaises(ValueError):
                AuditPerformanceTuner.load(path)

    def test_sharded_cache_distributes_and_holds_total_bound(self):
        cache = ShardedEvidenceDigestCache(shards=8, max_entries=16)
        for value in range(100):
            cache.digest({"root": str(value), "entries": []})
        loads = [len(shard) for shard in cache._values]
        self.assertGreater(sum(value > 0 for value in loads), 1)
        self.assertLessEqual(sum(loads), 16)
        tiny = ShardedEvidenceDigestCache(shards=8, max_entries=3)
        for value in range(100):
            tiny.digest({"root": str(value)})
        self.assertLessEqual(sum(len(shard) for shard in tiny._values), 3)

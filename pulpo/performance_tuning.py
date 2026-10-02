"""Bounded self-tuning for Pulpo audit-computation performance.

This module may select worker, batching, and cache-related execution parameters.
It cannot alter policy, approval, permits, evidence acceptance, replay semantics,
reconciliation, or any other governance rule.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
import platform
from pathlib import Path
import statistics
import time
from typing import Iterable, Sequence

from .audit_parallel import AuditRow, AuditVerificationEngine


@dataclass(frozen=True)
class SystemFingerprint:
    platform: str
    python: str
    cpu_count: int

    @classmethod
    def detect(cls) -> "SystemFingerprint":
        return cls(
            platform=platform.platform(),
            python=platform.python_version(),
            cpu_count=max(1, os.cpu_count() or 1),
        )

    def matches(self, other: "SystemFingerprint") -> bool:
        return (
            self.platform == other.platform
            and self.python == other.python
            and self.cpu_count == other.cpu_count
        )


@dataclass(frozen=True)
class PerformanceProfile:
    max_records: int
    workers: int
    batch_size: int
    parallel_threshold: int = 256
    source: str = "calibrated"

    def __post_init__(self) -> None:
        if self.max_records <= 0:
            raise ValueError("max_records must be positive")
        if self.workers <= 0:
            raise ValueError("workers must be positive")
        if self.batch_size <= 0:
            raise ValueError("batch_size must be positive")
        if self.parallel_threshold <= 0:
            raise ValueError("parallel_threshold must be positive")


class AuditPerformanceTuner:
    """Select only bounded computation settings for an observed workload size."""

    DEFAULT_BATCHES = (256, 1024, 4096, 16384)
    DEFAULT_MAX_WORKERS = 8

    def __init__(
        self,
        profiles: Sequence[PerformanceProfile],
        *,
        fingerprint: SystemFingerprint | None = None,
        max_workers: int | None = None,
        allowed_batch_sizes: Sequence[int] = DEFAULT_BATCHES,
    ) -> None:
        if not profiles:
            raise ValueError("at least one performance profile is required")
        self.fingerprint = fingerprint or SystemFingerprint.detect()
        self.max_workers = min(
            max_workers or self.DEFAULT_MAX_WORKERS,
            self.fingerprint.cpu_count,
        )
        self.allowed_batch_sizes = tuple(sorted(set(allowed_batch_sizes)))
        if not self.allowed_batch_sizes or any(value <= 0 for value in self.allowed_batch_sizes):
            raise ValueError("allowed_batch_sizes must contain positive integers")

        normalized = []
        for profile in profiles:
            if profile.workers > self.max_workers:
                raise ValueError("profile exceeds bounded worker limit")
            if profile.batch_size not in self.allowed_batch_sizes:
                raise ValueError("profile uses an unapproved batch size")
            normalized.append(profile)
        self.profiles = tuple(sorted(normalized, key=lambda item: item.max_records))

    @classmethod
    def conservative(cls) -> "AuditPerformanceTuner":
        fingerprint = SystemFingerprint.detect()
        return cls(
            (
                PerformanceProfile(
                    max_records=2**63 - 1,
                    workers=1,
                    batch_size=256,
                    source="conservative-fallback",
                ),
            ),
            fingerprint=fingerprint,
        )

    def profile_for(self, record_count: int) -> PerformanceProfile:
        if record_count < 0:
            raise ValueError("record_count must be non-negative")
        for profile in self.profiles:
            if record_count <= profile.max_records:
                return profile
        return self.profiles[-1]

    def engine_for(self, record_count: int, *, cache_size: int = 4096) -> AuditVerificationEngine:
        profile = self.profile_for(record_count)
        return AuditVerificationEngine(
            workers=profile.workers,
            cache_size=cache_size,
            parallel_threshold=profile.parallel_threshold,
            batch_size=profile.batch_size,
        )

    def to_document(self) -> dict[str, object]:
        return {
            "schema": "pulpo.audit-performance-profile.v1",
            "fingerprint": asdict(self.fingerprint),
            "max_workers": self.max_workers,
            "allowed_batch_sizes": list(self.allowed_batch_sizes),
            "profiles": [asdict(profile) for profile in self.profiles],
            "authority_effect": "none",
        }

    def save(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(self.to_document(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path, *, require_machine_match: bool = True) -> "AuditPerformanceTuner":
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        if document.get("schema") != "pulpo.audit-performance-profile.v1":
            raise ValueError("unsupported performance profile schema")
        if document.get("authority_effect") != "none":
            raise ValueError("performance profile cannot carry authority")
        fp = document.get("fingerprint")
        if not isinstance(fp, dict):
            raise ValueError("performance profile fingerprint missing")
        recorded = SystemFingerprint(
            platform=str(fp.get("platform", "")),
            python=str(fp.get("python", "")),
            cpu_count=int(fp.get("cpu_count", 0)),
        )
        current = SystemFingerprint.detect()
        if require_machine_match and not current.matches(recorded):
            raise ValueError("performance profile hardware/software fingerprint mismatch")
        profiles_raw = document.get("profiles")
        if not isinstance(profiles_raw, list) or not profiles_raw:
            raise ValueError("performance profile list missing")
        profiles = tuple(PerformanceProfile(**item) for item in profiles_raw)
        batches = document.get("allowed_batch_sizes", cls.DEFAULT_BATCHES)
        return cls(
            profiles,
            fingerprint=current if require_machine_match else recorded,
            max_workers=int(document.get("max_workers", cls.DEFAULT_MAX_WORKERS)),
            allowed_batch_sizes=tuple(int(value) for value in batches),
        )

    @classmethod
    def from_benchmark_document(
        cls,
        document: dict[str, object],
        *,
        min_improvement: float = 0.05,
        require_machine_match: bool = True,
    ) -> "AuditPerformanceTuner":
        if document.get("schema") != "pulpo.memory-scaling-benchmark.v2":
            raise ValueError("unsupported benchmark schema")
        if not 0 <= min_improvement < 1:
            raise ValueError("min_improvement must be between zero and one")
        machine = document.get("machine")
        if not isinstance(machine, dict):
            raise ValueError("benchmark machine metadata missing")
        recorded = SystemFingerprint(
            platform=str(machine.get("platform", "")),
            python=str(machine.get("python", "")),
            cpu_count=int(machine.get("cpu_count", 0)),
        )
        current = SystemFingerprint.detect()
        if require_machine_match and not current.matches(recorded):
            raise ValueError("benchmark hardware/software fingerprint mismatch")

        results = document.get("results")
        if not isinstance(results, list) or not results:
            raise ValueError("benchmark results missing")

        by_size: dict[int, list[dict[str, object]]] = {}
        batches: set[int] = set()
        for raw in results:
            if not isinstance(raw, dict):
                continue
            records = int(raw["records"])
            workers = int(raw["workers"])
            batch_size = int(raw["batch_size"])
            throughput = float(raw["records_per_second"])
            if records <= 0 or workers <= 0 or batch_size <= 0 or throughput <= 0:
                continue
            by_size.setdefault(records, []).append(raw)
            batches.add(batch_size)

        profiles: list[PerformanceProfile] = []
        max_workers = min(cls.DEFAULT_MAX_WORKERS, current.cpu_count)
        for records in sorted(by_size):
            candidates = [
                item for item in by_size[records]
                if int(item["workers"]) <= max_workers
            ]
            baselines = [item for item in candidates if int(item["workers"]) == 1]
            if not baselines:
                raise ValueError(f"benchmark baseline missing for {records} records")
            baseline = max(float(item["records_per_second"]) for item in baselines)
            best = max(candidates, key=lambda item: float(item["records_per_second"]))
            best_throughput = float(best["records_per_second"])
            if best_throughput < baseline * (1.0 + min_improvement):
                workers = 1
                batch_size = min(batches)
                source = "baseline-no-material-gain"
            else:
                workers = int(best["workers"])
                batch_size = int(best["batch_size"])
                source = "benchmark-selected"
            profiles.append(
                PerformanceProfile(
                    max_records=records,
                    workers=workers,
                    batch_size=batch_size,
                    parallel_threshold=int(document.get("parallel_threshold", 256)),
                    source=source,
                )
            )

        return cls(
            profiles,
            fingerprint=current,
            max_workers=max_workers,
            allowed_batch_sizes=tuple(sorted(batches)),
        )

    @classmethod
    def calibrate(
        cls,
        rows: Iterable[AuditRow],
        *,
        sizes: Sequence[int] = (10000, 50000, 100000),
        workers: Sequence[int] | None = None,
        batch_sizes: Sequence[int] = (256, 1024, 4096),
        repeats: int = 2,
        parallel_threshold: int = 256,
        min_improvement: float = 0.05,
    ) -> "AuditPerformanceTuner":
        """Run an explicit bounded calibration over immutable audit rows.

        Calibration is opt-in and never runs automatically in a governance
        decision. It benchmarks only verification computation settings.
        """
        row_list = list(rows)
        if not row_list:
            raise ValueError("calibration rows are required")
        if repeats <= 0:
            raise ValueError("repeats must be positive")
        fingerprint = SystemFingerprint.detect()
        candidate_workers = tuple(
            sorted(
                set(
                    workers
                    or (
                        1,
                        min(2, fingerprint.cpu_count),
                        min(4, fingerprint.cpu_count),
                        min(8, fingerprint.cpu_count),
                    )
                )
            )
        )
        candidate_workers = tuple(value for value in candidate_workers if 0 < value <= fingerprint.cpu_count)
        candidate_batches = tuple(sorted(set(batch_sizes)))
        if any(value <= 0 for value in candidate_batches):
            raise ValueError("batch_sizes must be positive")

        document: dict[str, object] = {
            "schema": "pulpo.memory-scaling-benchmark.v2",
            "machine": asdict(fingerprint),
            "parallel_threshold": parallel_threshold,
            "results": [],
        }
        results = document["results"]
        assert isinstance(results, list)

        usable_sizes = [size for size in sorted(set(sizes)) if 0 < size <= len(row_list)]
        if not usable_sizes:
            usable_sizes = [len(row_list)]

        for size in usable_sizes:
            sample = row_list[:size]
            for worker_count in candidate_workers:
                batches = (candidate_batches[0],) if worker_count == 1 else candidate_batches
                for batch_size in batches:
                    engine = AuditVerificationEngine(
                        workers=worker_count,
                        cache_size=0,
                        parallel_threshold=parallel_threshold,
                        batch_size=batch_size,
                    )
                    try:
                        if not engine.verify_rows(sample):
                            raise ValueError("calibration audit sample failed verification")
                        if worker_count > 1 and len(sample) >= parallel_threshold:
                            if not engine.verify_rows(sample):
                                raise ValueError("calibration worker warm-up failed verification")
                        samples = []
                        for _ in range(repeats):
                            started = time.perf_counter()
                            if not engine.verify_rows(sample):
                                raise ValueError("calibration verification failed")
                            samples.append(time.perf_counter() - started)
                    finally:
                        engine.close()
                    median = statistics.median(samples)
                    results.append(
                        {
                            "records": size,
                            "workers": worker_count,
                            "batch_size": batch_size,
                            "median_seconds": median,
                            "records_per_second": size / median,
                            "samples_seconds": samples,
                        }
                    )

        return cls.from_benchmark_document(
            document,
            min_improvement=min_improvement,
            require_machine_match=True,
        )


class AdaptiveAuditVerificationEngine:
    """Reuse warm verification engines selected by workload size."""

    def __init__(self, tuner: AuditPerformanceTuner, *, cache_size: int = 4096) -> None:
        self.tuner = tuner
        self.cache_size = cache_size
        self._engines: dict[tuple[int, int, int], AuditVerificationEngine] = {}

    def verify_rows(self, rows: Iterable[AuditRow]) -> bool:
        row_list = list(rows)
        profile = self.tuner.profile_for(len(row_list))
        key = (profile.workers, profile.batch_size, profile.parallel_threshold)
        engine = self._engines.get(key)
        if engine is None:
            engine = AuditVerificationEngine(
                workers=profile.workers,
                cache_size=self.cache_size,
                parallel_threshold=profile.parallel_threshold,
                batch_size=profile.batch_size,
            )
            self._engines[key] = engine
        return engine.verify_rows(row_list)

    def close(self) -> None:
        for engine in self._engines.values():
            engine.close()
        self._engines.clear()

    def __enter__(self) -> "AdaptiveAuditVerificationEngine":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

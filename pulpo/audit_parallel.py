"""Optional multi-core audit verification with bounded coordinator-side caching.

This module accelerates decoding and hashing only. It does not decide authority,
issue permits, mutate policy, write audit state, or replace canonical chain
verification. The coordinating process still checks current chain links and
compares every stored hash on every verification pass.
"""

from __future__ import annotations

from collections import OrderedDict
from concurrent.futures import ProcessPoolExecutor
from hashlib import sha256
import json
from threading import RLock
from typing import Iterable

AuditRow = tuple[str, str, str, int, str]
AuditBodyKey = tuple[str, str, str, int]


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest_body(key: AuditBodyKey) -> str:
    event, payload_json, previous_hash, timestamp_ns = key
    payload = json.loads(payload_json)
    body = {
        "event": event,
        "payload": payload,
        "previous_hash": previous_hash,
        "timestamp_ns": timestamp_ns,
    }
    return sha256(_canonical(body)).hexdigest()


def _digest_batch(keys: list[AuditBodyKey]) -> list[str]:
    """Hash one IPC batch inside a worker process."""
    return [_digest_body(key) for key in keys]


class AuditDigestCache:
    """Bounded exact-input LRU cache for expected audit-record digests."""

    def __init__(self, max_entries: int = 4096) -> None:
        if not isinstance(max_entries, int) or isinstance(max_entries, bool) or max_entries < 0:
            raise ValueError("max_entries must be a non-negative integer")
        self.max_entries = max_entries
        self._values: OrderedDict[AuditBodyKey, str] = OrderedDict()
        self._lock = RLock()

    def get(self, key: AuditBodyKey) -> str | None:
        if self.max_entries == 0:
            return None
        with self._lock:
            value = self._values.get(key)
            if value is None:
                return None
            self._values.move_to_end(key)
            return value

    def put(self, key: AuditBodyKey, digest: str) -> None:
        if self.max_entries == 0:
            return
        with self._lock:
            self._values[key] = digest
            self._values.move_to_end(key)
            while len(self._values) > self.max_entries:
                self._values.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._values.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._values)


class AuditVerificationEngine:
    """Reusable optional accelerator for immutable audit decoding and hashing.

    The first uncached verification is intentionally local. A process pool is
    created lazily only on a later substantial uncached verification. Parallel
    work is dispatched in bounded batches to avoid per-record Windows IPC and
    pickling overhead. Cache hits reuse only the expected digest for an exact
    immutable row body; current chain links and stored hashes are still checked
    every time.
    """

    def __init__(
        self,
        *,
        workers: int = 0,
        cache_size: int = 4096,
        parallel_threshold: int = 256,
        batch_size: int = 4096,
    ) -> None:
        if not isinstance(workers, int) or isinstance(workers, bool) or workers < 0:
            raise ValueError("workers must be a non-negative integer")
        if not isinstance(parallel_threshold, int) or isinstance(parallel_threshold, bool) or parallel_threshold <= 0:
            raise ValueError("parallel_threshold must be a positive integer")
        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
            raise ValueError("batch_size must be a positive integer")
        self.workers = workers
        self.parallel_threshold = parallel_threshold
        self.batch_size = batch_size
        self.cache = AuditDigestCache(cache_size)
        self._executor: ProcessPoolExecutor | None = None
        self._primed = False
        self._lock = RLock()

    def _executor_for_work(self) -> ProcessPoolExecutor:
        with self._lock:
            if self._executor is None:
                self._executor = ProcessPoolExecutor(max_workers=self.workers)
            return self._executor

    def verify_rows(self, rows: Iterable[AuditRow]) -> bool:
        row_list = list(rows)
        previous = "0" * 64
        misses: list[tuple[int, AuditBodyKey]] = []
        expected: list[str | None] = [None] * len(row_list)

        # These checks are deliberately coordinator-side and repeat on every pass.
        for index, row in enumerate(row_list):
            event, payload_json, previous_hash, timestamp_ns, stored_hash = row
            if previous_hash != previous:
                return False
            if not isinstance(stored_hash, str) or len(stored_hash) != 64:
                return False
            key: AuditBodyKey = (event, payload_json, previous_hash, timestamp_ns)
            cached = self.cache.get(key)
            if cached is None:
                misses.append((index, key))
            else:
                expected[index] = cached
            previous = stored_hash

        if misses:
            keys = [key for _, key in misses]
            use_pool = (
                self._primed
                and self.workers > 1
                and len(keys) >= self.parallel_threshold
            )
            if use_pool:
                batches = [
                    keys[start : start + self.batch_size]
                    for start in range(0, len(keys), self.batch_size)
                ]
                digest_batches = self._executor_for_work().map(_digest_batch, batches)
                digests = [digest for batch in digest_batches for digest in batch]
            else:
                digests = [_digest_body(key) for key in keys]

            for (index, key), digest in zip(misses, digests):
                expected[index] = digest
                self.cache.put(key, digest)

        self._primed = True

        for row, digest in zip(row_list, expected):
            if digest is None or row[4] != digest:
                return False
        return True

    def close(self) -> None:
        with self._lock:
            executor = self._executor
            self._executor = None
            self._primed = False
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)
        self.cache.clear()

    def __enter__(self) -> "AuditVerificationEngine":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

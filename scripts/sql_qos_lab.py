"""Portable benchmark-only fixtures and read-only resource observation."""
from pathlib import Path
import math
import os
import sys
import tempfile
from threading import Event, Thread
ROOT=Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT/'custody-service/src', ROOT/'custody-service/tests'):
    sys.path.insert(0,str(path))
from sql_qos_fixtures import CustodyFixtureTests
from pulpo_custody_service.sql_qos import SQLQoSSettings
MODES=('legacy','reuse','qos','reuse_qos')


def percentile(values,fraction):
    ordered=sorted(values)
    return ordered[max(0,math.ceil(len(ordered)*fraction)-1)] if ordered else None




def fixture_storage():
    root = Path(tempfile.gettempdir()).resolve()
    expected = os.environ.get('PULPO_BENCHMARK_SCRATCH')
    if expected is not None:
        requested = Path(expected)
        if not requested.is_absolute() or not requested.is_dir() or requested.resolve() != root:
            raise RuntimeError('benchmark scratch mismatch; refuse temporary-directory fallback')
    return dict(scratch_root=str(root), requested_scratch_root=expected)


def require_fixture_path(path):
    root = Path(fixture_storage()['scratch_root'])
    if not Path(path).resolve().is_relative_to(root):
        raise RuntimeError('fixture SQLite escaped benchmark scratch root')


class ProcessTreeSampler:
    """Sample this benchmark and descendants, not unrelated applications."""
    def __init__(self, psutil, interval):
        self.psutil = psutil
        self.root = psutil.Process(os.getpid())
        self.interval = interval
        self.stop_event = Event()
        self.thread = None
        self.baseline = {}
        self.last_cpu = {}
        self.peak_process_rss = {}
        self.peak_rss = 0
        self.peak_processes = 0
        self.samples = 0
        self.errors = 0

    def snapshot(self):
        try:
            processes = [self.root, *self.root.children(recursive=True)]
        except self.psutil.Error:
            processes = [self.root]
            self.errors += 1
        cpu, rss, count = {}, 0, 0
        for process in processes:
            try:
                key = (process.pid, process.create_time())
                times = process.cpu_times()
                cpu[key] = times.user + times.system
                process_rss = process.memory_info().rss
                rss += process_rss
                self.peak_process_rss[key] = max(self.peak_process_rss.get(key, 0), process_rss)
                count += 1
            except self.psutil.Error:
                self.errors += 1
        self.last_cpu.update(cpu)
        self.peak_rss = max(self.peak_rss, rss)
        self.peak_processes = max(self.peak_processes, count)
        self.samples += 1
        return cpu

    def start(self):
        self.baseline = self.snapshot()
        def sample():
            while not self.stop_event.wait(self.interval):
                self.snapshot()
        self.thread = Thread(target=sample, daemon=True)
        self.thread.start()

    def finish(self, wall_seconds, logical_cpus):
        self.stop_event.set()
        self.thread.join()
        self.snapshot()
        cpu_seconds = sum(max(0.0, total - self.baseline.get(key, 0.0))
                          for key, total in self.last_cpu.items())
        per_process = [{"pid": key[0], "created_at": key[1],
            "role": "coordinator" if key[0] == self.root.pid else "descendant",
            "cpu_seconds": max(0.0, total - self.baseline.get(key, 0.0)),
            "peak_rss_mib": self.peak_process_rss.get(key, 0) / 1024 ** 2}
            for key, total in sorted(self.last_cpu.items())]
        return {"cpu_seconds": cpu_seconds, "processes": per_process,
            "average_cpu_cores_equivalent": cpu_seconds / wall_seconds,
            "average_percent_logical_cpu_capacity": 100 * cpu_seconds / wall_seconds / logical_cpus,
            "peak_sum_rss_mib": self.peak_rss / 1024 ** 2,
            "peak_process_count": self.peak_processes,
            "sample_count": self.samples, "sampling_errors": self.errors}

"""Dedicated calculation processes, never a general task submission surface.

Fresh isolated interpreters receive JSON audit bodies only. They do not import
the caller's main module, Pulpo, site hooks, or inherited environment secrets.
This avoids fork custody duplication; it is not an OS filesystem/network sandbox.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from queue import Queue
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Thread


_WORKER_PATH = str(Path(__file__).with_name("_audit_calculation.py").resolve())


class _DigestWorker:
    def __init__(self, cwd):
        # Windows requires OS loader configuration. No caller environment,
        # application paths, tokens, Python hooks, or credentials are forwarded.
        env = {name: os.environ[name] for name in ("SYSTEMROOT", "WINDIR") if name in os.environ} if os.name == "nt" else {}
        self.process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-u", _WORKER_PATH],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", close_fds=True, cwd=cwd, env=env,
        )

    def digest(self, keys):
        result = Queue(maxsize=1)

        def exchange():
            try:
                self.process.stdin.write(json.dumps(keys) + "\n")
                self.process.stdin.flush()
                line = self.process.stdout.readline()
                if not line:
                    raise RuntimeError("audit calculation worker unavailable")
                result.put((True, json.loads(line)))
            except Exception as exc:
                result.put((False, exc))

        thread = Thread(target=exchange, daemon=True)
        thread.start()
        thread.join(30)
        if thread.is_alive():
            self.close()
            thread.join(5)
            raise RuntimeError("audit calculation worker timed out")
        ok, value = result.get()
        if not ok:
            raise RuntimeError("audit calculation worker failed") from value
        if not isinstance(value, list) or len(value) != len(keys) or any(type(digest) is not str or len(digest) != 64 for digest in value):
            raise RuntimeError("invalid audit calculation worker result")
        return value

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=5)
        for stream in (self.process.stdin, self.process.stdout):
            if stream is not None:
                try:
                    stream.close()
                except BrokenPipeError:
                    # A killed child cannot drain buffered input; close still
                    # releases the descriptor. This is cleanup, not acceptance.
                    pass


class DigestWorkerPool:
    """Bounded reusable workers with one fixed operation and JSON-only input."""
    def __init__(self, workers):
        self._directory = TemporaryDirectory(prefix="pulpo-audit-compute-")
        self._workers = []
        self._available = Queue()
        self._closed = False
        self._executor = ThreadPoolExecutor(max_workers=workers)
        try:
            for _ in range(workers):
                worker = _DigestWorker(self._directory.name)
                self._workers.append(worker)
                self._available.put(worker)
        except Exception:
            self.shutdown()
            raise

    def _digest(self, keys):
        worker = self._available.get()
        try:
            return worker.digest(keys)
        finally:
            self._available.put(worker)

    def digest_batches(self, batches):
        if self._closed:
            raise RuntimeError("audit calculation pool closed")
        return self._executor.map(self._digest, batches)

    def shutdown(self, **_kwargs):
        self._closed = True
        self._executor.shutdown(wait=True, cancel_futures=True)
        for worker in self._workers:
            worker.close()
        self._directory.cleanup()

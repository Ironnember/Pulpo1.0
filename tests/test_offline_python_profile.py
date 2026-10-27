"""Opt-in profile configuration and real Mac probes; no model or credentials."""
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import signal
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest

from scripts.run_local_intelligence_effect_proof import (
    ProofError, build_offline_python_profile, build_spawn_argv, sanitize_environment,
)


class OfflineProfileConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.runtime = self.root / "runtime"; self.runtime.mkdir()
        self.prefix = self.root / "python"; self.prefix.mkdir()
        self.executable = self.prefix / "python"; self.executable.write_bytes(b"fixture")
        self.worker = self.runtime / "worker.py"; self.worker.write_text("pass\n")
        self.protected = self.root / "protected"; self.protected.mkdir()
        self.kw = dict(executable=self.executable, python_prefix=self.prefix,
                       worker_script=self.worker, protected_read_roots=(self.protected,))

    def test_valid_configuration_is_deterministic_and_non_mutating(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        one = build_offline_python_profile(self.runtime, **self.kw)
        self.assertEqual(one, build_offline_python_profile(self.runtime, **self.kw))
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()})

    def test_relative_paths_rejected(self):
        with self.assertRaisesRegex(ProofError, "paths_must_be_absolute"):
            build_offline_python_profile(Path("runtime"), **self.kw)

    def test_missing_paths_rejected(self):
        with self.assertRaisesRegex(ProofError, "path_unavailable"):
            build_offline_python_profile(self.runtime, **{**self.kw, "executable": self.prefix / "missing"})

    def test_directory_cannot_be_worker(self):
        with self.assertRaisesRegex(ProofError, "regular_file_required"):
            build_offline_python_profile(self.runtime, **{**self.kw, "worker_script": self.runtime})

    def test_worker_outside_runtime_rejected(self):
        outside = self.root / "outside.py"; outside.write_text("pass\n")
        with self.assertRaisesRegex(ProofError, "worker_outside_runtime"):
            build_offline_python_profile(self.runtime, **{**self.kw, "worker_script": outside})

    def test_worker_symlink_escape_rejected(self):
        outside = self.root / "outside.py"; outside.write_text("pass\n")
        link = self.runtime / "linked.py"; link.symlink_to(outside)
        with self.assertRaisesRegex(ProofError, "worker_outside_runtime"):
            build_offline_python_profile(self.runtime, **{**self.kw, "worker_script": link})

    def test_executable_outside_prefix_rejected(self):
        with self.assertRaisesRegex(ProofError, "executable_outside_prefix"):
            build_offline_python_profile(self.runtime, **{**self.kw, "executable": self.worker})

    def test_filesystem_root_cannot_be_python_prefix(self):
        with self.assertRaisesRegex(ProofError, "root_scope_forbidden"):
            build_offline_python_profile(self.runtime, **{**self.kw, "python_prefix": Path("/")})

    def test_writable_runtime_cannot_overlap_interpreter(self):
        worker = self.prefix / "worker.py"; worker.write_text("pass\n")
        with self.assertRaisesRegex(ProofError, "runtime_prefix_overlap"):
            build_offline_python_profile(self.prefix, **{**self.kw, "worker_script": worker})

    def test_protected_directory_cannot_be_inside_allowed_interpreter(self):
        protected = self.prefix / "private"; protected.mkdir()
        with self.assertRaisesRegex(ProofError, "protected_read_overlap"):
            build_offline_python_profile(self.runtime, **{**self.kw, "protected_read_roots": (protected,)})

    def test_worker_cannot_be_in_protected_directory(self):
        with self.assertRaisesRegex(ProofError, "protected_read_overlap"):
            build_offline_python_profile(self.runtime, **{**self.kw, "protected_read_roots": (self.runtime,)})

    def test_control_characters_rejected(self):
        worker = self.runtime / "injected\nworker.py"; worker.write_text("pass\n")
        with self.assertRaisesRegex(ProofError, "control_character"):
            build_offline_python_profile(self.runtime, **{**self.kw, "worker_script": worker})


WORKER = r'''
import hashlib,json,os,pathlib,signal,socket,subprocess,sys
c=json.loads(sys.argv[1]);out={'stdin_hash':hashlib.sha256(sys.stdin.buffer.read()).hexdigest()}
def probe(name,fn):
    try:
        value=fn();out[name]={'allowed':True}
        if isinstance(value,bytes):out[name]['hash']=hashlib.sha256(value).hexdigest()
    except OSError as e:out[name]={'allowed':False,'errno':e.errno}
for name in ('raw','unlisted','state','alias','source'):
    probe(name,lambda name=name:pathlib.Path(c[name]).read_bytes())
def state_write():
    fd=os.open(c['state'],os.O_WRONLY);os.close(fd)
probe('state_write',state_write)
probe('extra_fd',lambda:os.pread(c['fd'],4096,0))
probe('signal',lambda:os.kill(c['pid'],signal.SIGUSR1))
probe('positive',lambda:pathlib.Path('positive.txt').write_text('ok'))
def unix():
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(2);s.connect(c['socket']);return s.recv(4096)
probe('unix',unix)
def tcp():
    with socket.create_connection(('127.0.0.1',c['port']),timeout=2) as s:return s.recv(4096)
probe('tcp',tcp)
try:
    p=subprocess.run(['/bin/cat',c['raw']],capture_output=True)
    out['descendant']={'allowed':p.returncode==0}
except OSError as e:out['descendant']={'allowed':False,'errno':e.errno}
def replace_code_with_alias():
    os.replace(c['alias'],c['worker'])
    return pathlib.Path(c['worker']).read_bytes()
probe('code_path_alias_replace',replace_code_with_alias)
print(json.dumps(out,sort_keys=True))
'''


@unittest.skipUnless(platform.system() == "Darwin" and Path("/usr/bin/sandbox-exec").is_file(),
                     "requires actual macOS Seatbelt; no simulated OS PASS")
class OfflineProfileMacExecutionTests(unittest.TestCase):
    def test_real_access_denials_positive_work_and_control_weakenings(self):
        import fcntl
        from pulpo.state import SQLiteKernelState
        records = []; signals = []; connections = []
        previous = signal.signal(signal.SIGUSR1, lambda *_: signals.append("fixture"))
        self.addCleanup(signal.signal, signal.SIGUSR1, previous)
        marker = b"SYNTHETIC_ONLY_OFFLINE_PROFILE_301"
        approved = b"synthetic-approved-input"

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                connections.append("fixture"); self.request.sendall(marker)

        with tempfile.TemporaryDirectory(prefix="pulpo-profile-review-") as temp:
            root = Path(temp).resolve()
            raw = root / "raw"; raw.mkdir()
            control = root / "control"; control.mkdir()
            protected = raw / "protected"; protected.write_bytes(marker)
            unlisted = root / "unlisted"; unlisted.write_bytes(marker)
            state = raw / "fixture.sqlite3"; SQLiteKernelState(state).close()
            state_hash = sha256(state.read_bytes()).hexdigest()
            with socketserver.ThreadingUnixStreamServer(str(control / "sock"), Handler) as unix, \
                 socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler) as tcp:
                threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (unix, tcp)]
                for thread in threads: thread.start()
                try:
                    for mode in ("unconfined", "restricted", "root_subtree_mutant", "injected_fd"):
                        with self.subTest(mode=mode):
                            runtime = root / mode; runtime.mkdir()
                            worker = runtime / "worker.py"; worker.write_text(WORKER)
                            alias = runtime / "alias"; os.link(protected, alias)
                            profile = build_offline_python_profile(runtime, executable=Path(sys.executable).resolve(),
                                python_prefix=Path(sys.base_prefix).resolve(), worker_script=worker,
                                protected_read_roots=(raw, control, Path(__file__).resolve().parents[1]))
                            if mode == "root_subtree_mutant":
                                self.assertEqual(1, profile.count('(allow file-read-data (literal "/"))'))
                                profile = profile.replace('(allow file-read-data (literal "/"))',
                                                          '(allow file-read-data (subpath "/"))')
                            profile_path = control / (mode + ".sb"); profile_path.write_text(profile)
                            original_fd = os.open(protected, os.O_RDONLY)
                            fd = fcntl.fcntl(original_fd, fcntl.F_DUPFD_CLOEXEC, 100); os.close(original_fd)
                            config = dict(worker=str(worker), raw=str(protected), unlisted=str(unlisted), state=str(state),
                                alias=str(alias), source=str(Path(__file__).resolve()), fd=fd,
                                pid=os.getpid(), socket=str(control / "sock"), port=tcp.server_address[1])
                            argv = (str(Path(sys.executable).resolve()), "-I", "-S", str(worker), json.dumps(config))
                            if mode != "unconfined": argv = build_spawn_argv(Path("/usr/bin/sandbox-exec"), profile_path, argv)
                            env = sanitize_environment({"HOME": str(runtime), "PATH": "/usr/bin:/bin"}, runtime)
                            before_signals, before_connections = len(signals), len(connections)
                            try:
                                child = subprocess.run(argv, input=approved.decode(), cwd=runtime, env=env,
                                    capture_output=True, text=True, timeout=15,
                                    pass_fds=(fd,) if mode == "injected_fd" else ())
                            finally: os.close(fd)
                            record = dict(mode=mode, exit=child.returncode, stdout=child.stdout, stderr=child.stderr,
                                profile=profile, profile_hash=sha256(profile.encode()).hexdigest(),
                                parent_signals=len(signals)-before_signals,
                                parent_connections=len(connections)-before_connections)
                            records.append(record)
                            self.assertEqual(0, child.returncode, child.stderr)
                            result = json.loads(child.stdout); record["observations"] = result
                            self.assertEqual(sha256(approved).hexdigest(), result["stdin_hash"])
                            self.assertTrue(result["positive"]["allowed"])
                            self.assertEqual("ok", (runtime / "positive.txt").read_text())
                            self.assertEqual(bool(record["parent_signals"]), result["signal"]["allowed"])
                            self.assertEqual(bool(record["parent_connections"]), result["unix"]["allowed"] or result["tcp"]["allowed"])
                            if mode == "unconfined":
                                for name in ("raw", "unlisted", "state", "alias", "source", "state_write", "signal", "unix", "tcp", "descendant", "code_path_alias_replace"):
                                    self.assertTrue(result[name]["allowed"], name)
                                self.assertEqual(sha256(marker).hexdigest(), result["code_path_alias_replace"]["hash"])
                            elif mode == "root_subtree_mutant":
                                self.assertTrue(result["unlisted"]["allowed"])
                                self.assertEqual(sha256(marker).hexdigest(), result["unlisted"]["hash"])
                            else:
                                for name in ("raw", "unlisted", "state", "alias", "source", "state_write", "signal", "unix", "tcp", "descendant", "code_path_alias_replace"):
                                    self.assertFalse(result[name]["allowed"], name)
                            if mode == "injected_fd":
                                self.assertEqual(sha256(marker).hexdigest(), result["extra_fd"]["hash"])
                            else:
                                self.assertFalse(result["extra_fd"]["allowed"])
                                self.assertEqual(9, result["extra_fd"]["errno"])
                finally:
                    for server in (unix, tcp): server.shutdown()
                    for thread in threads: thread.join(timeout=3)
                self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(marker, protected.read_bytes())
            self.assertEqual(state_hash, sha256(state.read_bytes()).hexdigest())
            temporary_root = root
        self.assertFalse(temporary_root.exists())
        evidence = os.environ.get("PULPO_OFFLINE_PROOF_EVIDENCE")
        if evidence:
            Path(evidence).write_text(json.dumps(dict(records=records, cleanup_verified=True,
                actual_model_ingress=False, independent_person_approval=False), indent=2) + "\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)

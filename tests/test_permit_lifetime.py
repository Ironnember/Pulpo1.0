"""Approval lifetime must survive permit storage, restart and contention."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from pulpo import GovernanceKernel, Intent, Policy, InMemoryKernelState, SQLiteKernelState
from tests.authority_support import HmacTestVerifier, signed_envelope, trust_for


class PermitLifetimeTests(unittest.TestCase):
    @contextmanager
    def fixture(self, backend):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'state.sqlite3'
            state = InMemoryKernelState() if backend == 'memory' else SQLiteKernelState(path)
            clock = [1500]
            verifier = HmacTestVerifier()
            policy = Policy(frozenset({'write'}), 0, frozenset({'write'}), authority_trust=trust_for(verifier))
            kernel = GovernanceKernel(policy, secret=b'lifetime-test', approval_verifier=verifier, clock=lambda: clock[0], state=state)
            intent = Intent('agent:test', 'write', 'fixture:one')
            approval = signed_envelope(kernel, intent, verifier, now_ns=1000, ttl_ns=1000)
            permit = kernel.evaluate_with_approval(intent, approval).permit
            self.assertIsNotNone(permit)
            try:
                yield kernel, state, clock, intent, permit, path, policy, verifier
            finally:
                if backend == 'sqlite': state.close()

    def test_valid_permit_consumes_exactly_once(self):
        for backend in ('memory', 'sqlite'):
            with self.subTest(backend=backend), self.fixture(backend) as (k,s,clock,i,p,*_):
                self.assertTrue(k.consume(p,i)); self.assertFalse(k.consume(p,i))
                self.assertTrue(k.verify_audit())

    def test_expiry_boundary_denies_and_does_not_revive_after_clock_rollback(self):
        for backend in ('memory', 'sqlite'):
            with self.subTest(backend=backend), self.fixture(backend) as (k,s,clock,i,p,*_):
                clock[0] = 2000
                self.assertFalse(k.consume(p,i))
                self.assertEqual('approval_expired', k.audit[-1]['payload']['approval_status'])
                clock[0] = 1500
                self.assertFalse(k.consume(p,i))
                self.assertTrue(k.verify_audit())

    def test_clock_before_approval_denies_but_preserves_valid_control(self):
        for backend in ('memory', 'sqlite'):
            with self.subTest(backend=backend), self.fixture(backend) as (k,s,clock,i,p,*_):
                clock[0] = 999
                self.assertFalse(k.consume(p,i))
                clock[0] = 1500
                self.assertTrue(k.consume(p,i))

    def test_invalid_kernel_clock_fails_closed(self):
        for backend in ('memory', 'sqlite'):
            with self.subTest(backend=backend), self.fixture(backend) as (k,s,clock,i,p,*_):
                for bad in (None, True, '1500'):
                    clock[0] = bad
                    self.assertFalse(k.consume(p,i))
                clock[0] = 1500
                self.assertTrue(k.consume(p,i))

    def test_expiry_survives_sqlite_restart(self):
        with self.fixture('sqlite') as (k,s,clock,i,p,path,policy,verifier):
            clock[0] = 2001
            other = SQLiteKernelState(path)
            try:
                restarted = GovernanceKernel(policy, secret=b'lifetime-test', approval_verifier=verifier, clock=lambda:clock[0], state=other)
                self.assertFalse(restarted.consume(p,i))
                self.assertTrue(restarted.verify_audit())
            finally: other.close()

    def test_two_sqlite_consumers_have_at_most_one_success(self):
        for now, successes in ((1999,1),(2000,0)):
            with self.subTest(now=now), self.fixture('sqlite') as (k,s,clock,i,p,path,policy,verifier):
                barrier = threading.Barrier(2)
                def consume():
                    other = SQLiteKernelState(path)
                    try:
                        worker = GovernanceKernel(policy, secret=b'lifetime-test', approval_verifier=verifier, clock=lambda:now, state=other)
                        barrier.wait(timeout=5)
                        return worker.consume(p,i)
                    finally: other.close()
                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [pool.submit(consume) for _ in range(2)]
                    self.assertEqual(successes, sum(f.result(timeout=10) for f in futures))

    def test_two_memory_consumers_have_at_most_one_success(self):
        with self.fixture('memory') as (k,s,clock,i,p,*_):
            barrier = threading.Barrier(2)
            def consume():
                barrier.wait(timeout=5)
                return k.consume(p,i)
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(consume) for _ in range(2)]
                self.assertEqual(1,sum(f.result(timeout=10) for f in futures))
            self.assertTrue(k.verify_audit())

    def test_legacy_unbound_permit_is_not_silently_reauthorized(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/'old.sqlite3'
            with closing(sqlite3.connect(path)) as c, c:
                c.execute('CREATE TABLE permits (permit TEXT PRIMARY KEY, intent_hash TEXT NOT NULL, spent INTEGER NOT NULL DEFAULT 0)')
                c.execute('INSERT INTO permits VALUES (?,?,0)',('legacy','a'*64))
            for _ in range(2):
                state = SQLiteKernelState(path)
                try:
                    self.assertFalse(state.consume_permit('legacy','a'*64,1500))
                    self.assertEqual('permit_lifetime_unbound',state.audit[-1]['payload']['permit_status'])
                finally: state.close()

    def test_parallel_legacy_bootstrap_preserves_denial(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'old.sqlite3'
            with closing(sqlite3.connect(path)) as c, c:
                c.execute('CREATE TABLE permits (permit TEXT PRIMARY KEY, intent_hash TEXT NOT NULL, spent INTEGER NOT NULL DEFAULT 0)')
                c.execute('INSERT INTO permits VALUES (?,?,0)',('legacy','a'*64))
            barrier=threading.Barrier(2)
            def bootstrap():
                barrier.wait(timeout=5)
                state=SQLiteKernelState(path)
                try:return state.consume_permit('legacy','a'*64,1500)
                finally:state.close()
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures=[pool.submit(bootstrap) for _ in range(2)]
                self.assertEqual([False,False],[f.result(timeout=10) for f in futures])

    def test_failed_lifetime_migration_rolls_back_and_can_recover(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'old.sqlite3'
            with closing(sqlite3.connect(path)) as c, c:
                c.execute('CREATE TABLE permits (permit TEXT PRIMARY KEY, intent_hash TEXT NOT NULL, spent INTEGER NOT NULL DEFAULT 0)')
            original=sqlite3.connect;connections=[]
            class FailingConnection(sqlite3.Connection):
                def execute(self,sql,*args,**kwargs):
                    if 'ADD COLUMN approval_expires_at_ns' in sql:
                        raise sqlite3.OperationalError('synthetic migration interruption')
                    return super().execute(sql,*args,**kwargs)
            def connect(*args,**kwargs):
                c=original(*args,factory=FailingConnection,**kwargs);connections.append(c);return c
            with patch('pulpo.state.sqlite3.connect',side_effect=connect):
                with self.assertRaises(sqlite3.OperationalError):SQLiteKernelState(path)
            for c in connections:
                with self.assertRaises(sqlite3.ProgrammingError):c.execute('SELECT 1')
            with closing(original(path)) as c:
                self.assertNotIn('approval_issued_at_ns',{row[1] for row in c.execute('PRAGMA table_info(permits)')})
            state=SQLiteKernelState(path);state.close()


if __name__ == '__main__': unittest.main()

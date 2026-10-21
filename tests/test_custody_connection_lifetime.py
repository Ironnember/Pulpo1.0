"""Keep references alive so GC cannot hide evidence connection leaks."""
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from pulpo import SQLiteKernelState
from pulpo.custody import SQLiteGovernanceCustody
from pulpo.custody_evidence import SQLiteCustodyEvidenceConvergence, CustodyEvidenceViolation
from pulpo.proposal_commitment import SQLiteProposalCommitments, ProposalCommitmentViolation


class EvidenceConnectionLifetimeTests(unittest.TestCase):
    def test_proposal_operations_close_connections_even_on_rejection(self):
        from tests.test_custody_executor import CustodyExecutorTests
        with tempfile.TemporaryDirectory() as td:
            original=sqlite3.connect;connections=[]
            def connect(*args,**kwargs):
                c=original(*args,**kwargs);connections.append(c);return c
            try:
                with patch('pulpo.proposal_commitment.sqlite3.connect',side_effect=connect):
                    store=SQLiteProposalCommitments(Path(td)/'proposal.sqlite3')
                    order=CustodyExecutorTests().order()
                    args=dict(availability_hash='a'*64,created_at_ns=11_000_000,expires_at_ns=order.expires_at_ns)
                    proposal=store.create(order,**args)
                    self.assertEqual(proposal,store.create(order,**args))
                    store.claim(proposal.commitment_id,now_ns=11_000_001)
                    self.assertEqual(order,store.order_for_hash(order.order_hash))
                    with self.assertRaises(ProposalCommitmentViolation):
                        store.claim(proposal.commitment_id,now_ns=11_000_002)
                self.assertGreaterEqual(len(connections),6)
                for c in connections:
                    with self.assertRaises(sqlite3.ProgrammingError):c.execute('SELECT 1')
            finally:
                for c in connections:c.close()

    def test_setup_failure_closes_custody_and_projection_connections(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'state.sqlite3';state=SQLiteKernelState(path)
            custody=SQLiteGovernanceCustody(path,signing_secret=b'test-only')
            original=sqlite3.connect;connections=[]
            class FailingConnection(sqlite3.Connection):
                def execute(self,sql,*args,**kwargs):
                    if sql.startswith('PRAGMA synchronous'):
                        raise sqlite3.OperationalError('synthetic PRAGMA failure')
                    return super().execute(sql,*args,**kwargs)
            def connect(*args,**kwargs):
                c=original(*args,factory=FailingConnection,**kwargs);connections.append(c);return c
            try:
                with patch('pulpo.custody.sqlite3.connect',side_effect=connect):
                    with self.assertRaises(sqlite3.OperationalError):custody._connect()
                    with self.assertRaises(CustodyEvidenceViolation):
                        SQLiteCustodyEvidenceConvergence(custody)
                for c in connections:
                    with self.assertRaises(sqlite3.ProgrammingError):c.execute('SELECT 1')
            finally:
                for c in connections:c.close()
                state.close()

    def test_initialization_and_observation_connections_are_closed(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/'state.sqlite3';state = SQLiteKernelState(path)
            custody = SQLiteGovernanceCustody(path,signing_secret=b'test-only')
            connections=[];original=sqlite3.connect
            def connect(*args,**kwargs):
                c=original(*args,**kwargs);connections.append(c);return c
            try:
                with patch('pulpo.custody_evidence.sqlite3.connect',side_effect=connect):
                    projection=SQLiteCustodyEvidenceConvergence(custody)
                    self.assertEqual(0,projection.pending_count())
                    self.assertEqual(0,projection.canonical_event_count('a'*64))
                self.assertGreaterEqual(len(connections),3)
                for c in connections:
                    with self.assertRaises(sqlite3.ProgrammingError): c.execute('SELECT 1')
            finally:
                for c in connections: c.close()
                state.close()

    def test_connection_is_closed_when_initialization_raises(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'state.sqlite3';state=SQLiteKernelState(path)
            custody=SQLiteGovernanceCustody(path,signing_secret=b'test-only')
            connections=[];original=sqlite3.connect
            class FailingConnection(sqlite3.Connection):
                def execute(self,sql,*args,**kwargs):
                    if 'CREATE TABLE IF NOT EXISTS custody_evidence_outbox' in sql:
                        raise sqlite3.OperationalError('synthetic initialization failure')
                    return super().execute(sql,*args,**kwargs)
            def connect(*args,**kwargs):
                c=original(*args,factory=FailingConnection,**kwargs);connections.append(c);return c
            try:
                with patch('pulpo.custody_evidence.sqlite3.connect',side_effect=connect):
                    with self.assertRaises(CustodyEvidenceViolation): SQLiteCustodyEvidenceConvergence(custody)
                for c in connections:
                    with self.assertRaises(sqlite3.ProgrammingError): c.execute('SELECT 1')
            finally:
                for c in connections:c.close()
                state.close()


if __name__=='__main__': unittest.main()

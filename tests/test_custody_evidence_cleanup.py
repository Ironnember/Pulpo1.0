from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from pulpo.custody import SQLiteGovernanceCustody
from pulpo.custody_evidence import CustodyEvidenceViolation, SQLiteCustodyEvidenceConvergence
from pulpo.state import SQLiteKernelState
from pulpo.proposal_commitment import ProposalCommitmentViolation, SQLiteProposalCommitments
from tests import test_namecom_proposal as proposal_fixture


class CustodyEvidenceCleanupTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'custody.sqlite3'
        self.state = SQLiteKernelState(self.path)
        self.addCleanup(self.state.close)
        self.custody = SQLiteGovernanceCustody(self.path, signing_secret=b'cleanup-test')
        self.connections = []
        connect = sqlite3.connect

        def tracked(*args, **kwargs):
            connection = connect(*args, **kwargs)
            self.connections.append(connection)
            return connection

        self.addCleanup(lambda: [connection.close() for connection in self.connections])
        self.connect = tracked

    def assert_closed(self):
        self.assertTrue(self.connections)
        for connection in self.connections:
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute('SELECT 1')

    def test_connections_close_after_initialization_reads_and_empty_projection(self):
        with patch('pulpo.custody_evidence.sqlite3.connect', side_effect=self.connect):
            evidence = SQLiteCustodyEvidenceConvergence(self.custody)
            self.assertEqual(0, evidence.pending_count())
            self.assertEqual(0, evidence.canonical_event_count('0' * 64))
            self.assertIsNone(evidence.project_one())
            self.assert_closed()

    def test_initialize_failure_rolls_back_and_closes(self):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute('DROP TABLE audit')
        with patch('pulpo.custody_evidence.sqlite3.connect', side_effect=self.connect):
            with self.assertRaisesRegex(CustodyEvidenceViolation, 'canonical_audit_missing'):
                SQLiteCustodyEvidenceConvergence(self.custody)
            self.assert_closed()
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual([], connection.execute(
                "SELECT name FROM sqlite_master WHERE name='custody_evidence_outbox'"
            ).fetchall())

    def test_query_failures_close_connections_and_preserve_denial(self):
        evidence = SQLiteCustodyEvidenceConvergence(self.custody)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute('DROP TABLE custody_evidence_outbox')
            connection.execute('DROP TABLE audit')
        with patch('pulpo.custody_evidence.sqlite3.connect', side_effect=self.connect):
            with self.assertRaisesRegex(CustodyEvidenceViolation, 'custody_evidence_read_failed'):
                evidence.pending_count()
            with self.assertRaisesRegex(CustodyEvidenceViolation, 'canonical_evidence_read_failed'):
                evidence.canonical_event_count('0' * 64)
            self.assert_closed()

    def test_configuration_failure_closes_before_returning_connection(self):
        connections = []
        connect = sqlite3.connect

        class BrokenConfiguration(sqlite3.Connection):
            def execute(self, sql, *args):
                if sql.startswith('PRAGMA'):
                    raise sqlite3.OperationalError('forced pragma failure')
                return super().execute(sql, *args)

        def broken(*args, **kwargs):
            connection = connect(*args, factory=BrokenConfiguration, **kwargs)
            connections.append(connection)
            return connection

        self.addCleanup(lambda: [connection.close() for connection in connections])
        for target, construct, error in (
            ('pulpo.custody_evidence.sqlite3.connect',
             lambda: SQLiteCustodyEvidenceConvergence(self.custody), CustodyEvidenceViolation),
            ('pulpo.proposal_commitment.sqlite3.connect',
             lambda: SQLiteProposalCommitments(self.path), ProposalCommitmentViolation),
        ):
            with self.subTest(target=target):
                with patch(target, side_effect=broken):
                    with self.assertRaises(error):
                        construct()
                self.connections = connections
                self.assert_closed()

    def test_proposal_connections_close_on_create_read_claim_and_replay_denial(self):
        builder, _ = proposal_fixture.NameComProposalTests().builder(proposal_fixture.availability())
        proposal = builder.propose(proposal_fixture.DOMAIN)
        now = proposal_fixture.NOW
        with patch('pulpo.proposal_commitment.sqlite3.connect', side_effect=self.connect):
            store = SQLiteProposalCommitments(self.path)
            commitment = store.create(proposal.order, availability_hash=proposal.availability_hash,
                                      created_at_ns=now, expires_at_ns=proposal.order.expires_at_ns)
            with self.assertRaisesRegex(ProposalCommitmentViolation, 'not_claimed'):
                store.order_for_hash(proposal.order.order_hash)
            _, order = store.claim(commitment.commitment_id, now_ns=now + 1)
            self.assertEqual(proposal.order, order)
            self.assertEqual(proposal.order, store.order_for_hash(proposal.order.order_hash))
            with self.assertRaisesRegex(ProposalCommitmentViolation, 'already_claimed'):
                store.claim(commitment.commitment_id, now_ns=now + 2)
            with self.assertRaises(ProposalCommitmentViolation):
                store.claim('unknown', now_ns=now + 2)
            self.assert_closed()

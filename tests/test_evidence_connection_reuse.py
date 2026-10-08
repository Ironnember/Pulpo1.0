from contextlib import closing
import sqlite3
import unittest
from unittest.mock import Mock, patch
import tests.test_custody_evidence as evidence_tests
from pulpo.custody_evidence import SQLiteCustodyEvidenceConvergence, CustodyEvidenceViolation


class ReusedEvidenceTests(evidence_tests.CustodyEvidenceConvergenceTests):
    def setUp(self):
        super().setUp()
        self.evidence._reuse_connection=True

    def test_drain_reuses_one_connection_but_preserves_all_commits(self):
        authorization=self.authorize()
        opened=[]
        original=self.evidence._connect
        class View:
            def __init__(self,connection):
                self.connection=connection
                self.commits=0
            def __getattr__(self,name):
                return getattr(self.connection,name)
            def commit(self):
                self.commits+=1
                return self.connection.commit()
        def connect():
            view=View(original())
            opened.append(view)
            return view
        with patch.object(self.evidence,'_connect',side_effect=connect):
            projected=self.evidence.project_all()
        self.assertEqual((1,2,1),(len(opened),opened[0].commits,len(projected)))
        with self.assertRaises(sqlite3.ProgrammingError):
            opened[0].connection.execute('SELECT 1')
        self.assertEqual(1,self.evidence.canonical_event_count(authorization.receipt.transition_hash))
        self.assertEqual(0,self.evidence.pending_count())

    def test_reused_drain_fault_rollback_restart_and_tamper(self):
        authorization=self.authorize()
        for point in ('after_audit_insert','before_projection_commit'):
            def fail(actual):
                if actual==point:
                    raise RuntimeError('simulated crash')
            faulty=SQLiteCustodyEvidenceConvergence(self.custody,reuse_connection=True,fault_hook=fail)
            with self.assertRaises(CustodyEvidenceViolation):
                faulty.project_all()
            self.assertEqual(1,self.evidence.pending_count())
            self.assertEqual(0,self.evidence.canonical_event_count(authorization.receipt.transition_hash))
        restarted=SQLiteCustodyEvidenceConvergence(self.custody,reuse_connection=True)
        self.assertEqual(1,len(restarted.project_all()))
        self.assertEqual((),restarted.project_all())
        self.assertEqual(1,restarted.canonical_event_count(authorization.receipt.transition_hash))

    def test_no_pending_drain_closes_and_full_durability_unchanged(self):
        self.assertEqual((),self.evidence.project_all())
        with closing(self.evidence._connect()) as connection:
            self.assertEqual(2,connection.execute('PRAGMA synchronous').fetchone()[0])
            self.assertEqual(0,self.evidence.pending_count())



class ConnectionSetupCleanupTests(unittest.TestCase):
    def test_setup_failure_closes_connection_without_masking_failure(self):
        from pulpo.commerce import SQLiteBudgetAccount
        from pulpo.custody import SQLiteGovernanceCustody
        from pulpo.proposal_commitment import SQLiteProposalCommitments
        for owner_type in (SQLiteBudgetAccount, SQLiteGovernanceCustody,
                           SQLiteProposalCommitments, SQLiteCustodyEvidenceConvergence):
            with self.subTest(owner=owner_type.__name__):
                owner = owner_type.__new__(owner_type)
                owner.path = ':memory:'
                failure = sqlite3.OperationalError('setup unavailable')
                connection = Mock()
                connection.execute.side_effect = failure
                with patch('sqlite3.connect', return_value=connection):
                    with self.assertRaises(sqlite3.OperationalError) as caught:
                        owner._connect()
                self.assertIs(failure, caught.exception)
                connection.close.assert_called_once_with()


if __name__=='__main__':
    unittest.main()

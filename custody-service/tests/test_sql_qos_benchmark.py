import unittest
from unittest.mock import patch
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
import benchmark_sql_qos as lab


class SustainedSQLTests(unittest.TestCase):
    def test_reused_owner_multiple_waves_complete_with_bounded_qos(self):
        for mode in ('qos','reuse_qos'):
            row=lab.run_sample(mode,'valid_stream',2,callers=4)
            self.assertEqual((8,8,8),(row['offered_valid'],row['effects'],row['replay_denials']))
            self.assertEqual((0,0,0),(row['admission_rejections'],row['retained_reserved_cents'],row['evidence_pending']))
            self.assertEqual(2,len(row['wave_results']))
            self.assertLessEqual(row['qos_peak_waiters'],7);self.assertEqual(1,row['qos_peak_active'])
            self.assertIsNone(row['resources']);self.assertIsNone(row['sql_observer'])

    def test_mixed_traffic_cannot_grant_authority_and_observer_preserves_results(self):
        rows=[lab.run_sample('reuse_qos','mixed_stream',2,callers=8,observe=enabled) for enabled in (False,True)]
        for row in rows:
            self.assertEqual((8,8,8),(row['offered_valid'],row['effects'],row['offered_noise']))
            self.assertEqual((0,0),(row['retained_reserved_cents'],row['evidence_pending']))
            self.assertEqual(8,row['noise_denials']+row['noise_admission_rejections']+row['malformed_denials'])
            self.assertEqual(2,row['malformed_denials'])
            self.assertEqual(8,row['replay_denials'])
        for key in ('effects','audit_records','sqlite_bytes','sql_connections','retained_reserved_cents'):
            self.assertEqual(rows[0][key],rows[1][key],key)
        self.assertTrue(rows[1]['sql_observer']['stages'])
        self.assertTrue(all(s['synchronous']==2 for s in rows[1]['sql_observer']['observed_sqlite_settings']))

    def test_ungated_mixed_counts_and_legacy_reuse_paths(self):
        rows=[lab.run_sample(mode,'mixed_stream',1,callers=4) for mode in ('legacy','reuse')]
        for row in rows:
            self.assertEqual(2,row['effects']+row['canonical_denials']+row['admission_rejections'])
            self.assertEqual(2,row['noise_denials']+row['noise_admission_rejections']+row['malformed_denials'])
            self.assertEqual(row['effects'],row['replay_denials'])
            self.assertEqual(0,row['evidence_pending'])

    def test_invalid_configuration_before_owner(self):
        with patch.object(lab.base.CustodyFixtureTests,'fixture',side_effect=AssertionError('writer reached')):
            for args in (('bad','valid_stream',1),('legacy','bad',1),('legacy','valid_stream',True)):
                with self.assertRaises(ValueError):lab.run_sample(*args)
            for kwargs in ({'callers':9},{'observe':1}):
                with self.assertRaises(ValueError):lab.run_sample('reuse_qos','mixed_stream',1,**kwargs)

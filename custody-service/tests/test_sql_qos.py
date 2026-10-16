from concurrent.futures import ThreadPoolExecutor
from time import monotonic, sleep
import unittest
from unittest.mock import patch
import sql_qos_fixtures as ingress_tests
import test_api as api_tests
from pulpo_custody_service.sql_qos import SQLAdmissionGate, SQLQoSSettings, SQLAdmissionRejected


def wait_for(operation):
    deadline=monotonic()+2
    while not operation():
        if monotonic()>=deadline:
            raise AssertionError('fixture synchronization deadline exhausted')
        sleep(.001)


class QoSExistingTests(api_tests.CustodyServiceApiTests):
    def build(self, **kwargs):
        return super().build(reuse_evidence_connection=True,sql_qos_settings=SQLQoSSettings(),**kwargs)


class SQLQoSTests(unittest.TestCase):
    def test_fifo_bounded_waiters_and_no_forged_release(self):
        gate=SQLAdmissionGate(SQLQoSSettings(max_waiters=2,wait_ns=1_000_000_000))
        lease=gate.acquire()
        order=[]
        def worker(index):
            with gate.slot():
                order.append(index)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first=pool.submit(worker,1)
            wait_for(lambda:gate.snapshot()['waiting']==1)
            second=pool.submit(worker,2)
            wait_for(lambda:gate.snapshot()['waiting']==2)
            with self.assertRaises(SQLAdmissionRejected):
                gate.acquire()
            with self.assertRaises(ValueError):
                gate.release(object())
            self.assertEqual(1,gate.snapshot()['active'])
            gate.release(lease)
            first.result(timeout=2)
            second.result(timeout=2)
        self.assertEqual([1,2],order)
        self.assertEqual((0,0),(gate.snapshot()['active'],gate.snapshot()['waiting']))
        self.assertEqual((1,2),(gate.snapshot()['peak_active'],gate.snapshot()['peak_waiters']))
        with self.assertRaises(ValueError):
            gate.release(lease)
        self.assertFalse(any(hasattr(gate,name) for name in ('kernel','service','connection','execute','permit','callback')))

    def test_timeout_and_operation_exception_release_capacity(self):
        gate=SQLAdmissionGate(SQLQoSSettings(wait_ns=1_000_000))
        lease=gate.acquire()
        with self.assertRaises(SQLAdmissionRejected):
            gate.acquire()
        self.assertEqual(0,gate.snapshot()['waiting'])
        gate.release(lease)
        with self.assertRaisesRegex(RuntimeError,'failure'):
            with gate.slot():
                raise RuntimeError('operation failure')
        self.assertEqual(0,gate.snapshot()['active'])
        with gate.slot():
            self.assertEqual(1,gate.snapshot()['active'])

    def test_cancelled_wait_and_regressing_clock_release_tickets(self):
        gate=SQLAdmissionGate(SQLQoSSettings())
        lease=gate.acquire()
        with patch.object(gate._condition,'wait',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                gate.acquire()
        self.assertEqual(0,gate.snapshot()['waiting'])
        with patch('pulpo_custody_service.sql_qos.monotonic_ns',return_value=0):
            with self.assertRaises(ValueError):
                gate.acquire()
        gate.release(lease)

    def test_invalid_host_settings_and_default_off(self):
        for kwargs in ({'max_active':True},{'max_active':5},{'max_waiters':65},{'wait_ns':-1}):
            with self.assertRaises(ValueError):
                SQLQoSSettings(**kwargs)
        with self.assertRaises(ValueError):
            SQLAdmissionGate({'max_active':1})
        helper=ingress_tests.CustodyFixtureTests()
        try:
            _,_,_,service,*_=helper.fixture()
            self.assertIsNone(service._sql_qos)
            self.assertFalse(service.evidence._reuse_connection)
        finally:
            helper.doCleanups()

    def test_exact_all_rows_objects_and_responses_match_legacy(self):
        helper=ingress_tests.CustodyFixtureTests()
        original_fixture=helper.fixture
        try:
            baseline=helper.flow()
            def fixture(*args,**kwargs):
                return original_fixture(*args,reuse_evidence_connection=True,sql_qos_settings=SQLQoSSettings(),**kwargs)
            with patch.object(helper,'fixture',side_effect=fixture):
                self.assertEqual(baseline,helper.flow())
        finally:
            helper.doCleanups()

    def test_overload_rejects_before_any_sql_or_effect_and_forged_body_denied(self):
        helper=ingress_tests.CustodyFixtureTests()
        try:
            case,client,app,service,registrar,_=helper.fixture(reuse_evidence_connection=True,
                sql_qos_settings=SQLQoSSettings(max_waiters=0))
            commitment=case.commit(service,case.order())
            before=helper.rows(case.path)
            lease=service._sql_qos.acquire()
            try:
                with patch.object(service.evidence,'project_all',side_effect=AssertionError('SQL ran before admission')):
                    response=client.post('/v1/domain-attempts',json={'proposal_commitment_id':commitment.commitment_id})
                    self.assertEqual(429,response.status_code)
            finally:
                service._sql_qos.release(lease)
            self.assertEqual(before,helper.rows(case.path))
            self.assertEqual(0,registrar.purchase_calls)
            self.assertEqual(422,client.post('/v1/domain-attempts',json={
                'proposal_commitment_id':commitment.commitment_id,'sql_qos_settings':{'max_active':4}}).status_code)
            self.assertEqual(200,client.post('/v1/domain-attempts',json={'proposal_commitment_id':commitment.commitment_id}).status_code)
        finally:
            helper.doCleanups()

    def test_status_read_is_not_rejected_after_a_completed_effect(self):
        helper=ingress_tests.CustodyFixtureTests()
        try:
            case,client,app,service,registrar,_=helper.fixture(reuse_evidence_connection=True,
                sql_qos_settings=SQLQoSSettings(max_waiters=0))
            commitment=case.commit(service,case.order())
            response=client.post('/v1/domain-attempts',json={'proposal_commitment_id':commitment.commitment_id})
            handle=response.json()
            self.assertEqual(200,client.post(f"/v1/domain-attempts/{handle['attempt_id']}/execute",json={'handle':handle}).status_code)
            before=helper.rows(case.path)
            lease=service._sql_qos.acquire()
            try:
                self.assertEqual(200,client.get(f"/v1/domain-attempts/{handle['attempt_id']}").status_code)
            finally:
                service._sql_qos.release(lease)
            self.assertEqual(1,registrar.purchase_calls)
            self.assertEqual(before,helper.rows(case.path))
        finally:
            helper.doCleanups()

    def test_reuse_admission_restart_replay_tamper_expiry_revocation(self):
        for name in ('check_restart_keeps_duplicate_and_execution_replay_governed',
                     'check_canonical_audit_tamper_still_denies',
                     'check_governed_expiry_still_denies','check_current_policy_revocation_still_denies'):
            helper=ingress_tests.CustodyFixtureTests(name)
            fixture=helper.fixture
            def configured(*args,**kwargs):
                return fixture(*args,reuse_evidence_connection=True,sql_qos_settings=SQLQoSSettings(),**kwargs)
            try:
                with patch.object(helper,'fixture',side_effect=configured):
                    getattr(helper,name)()
            finally:
                helper.doCleanups()


if __name__=='__main__':
    unittest.main()

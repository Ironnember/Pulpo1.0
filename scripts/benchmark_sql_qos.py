"""Sustained synthetic custody traffic; one unchanged owner/database per sample."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, nullcontext
from dataclasses import asdict, replace
import gc
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import subprocess
import sqlite3
import statistics
import sys
from threading import Barrier, Lock
from time import perf_counter, process_time
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import sql_qos_lab as base
from sql_qos_observer import OwnerMetrics, observe_owner
MODES=base.MODES
WORKLOADS=('valid_stream','mixed_stream')


def run_sample(mode,workload,waves,*,callers=8,measure=False,observe=False):
    if mode not in MODES or workload not in WORKLOADS or type(waves) is not int or not 1<=waves<=100 or type(callers) is not int or not 1<=callers<=8 or type(observe) is not bool:
        raise ValueError('invalid sustained experiment settings')
    valid_per_wave=callers if workload=='valid_stream' else max(1,callers//2)
    counts=dict(offered_valid=waves*valid_per_wave,offered_noise=waves*(callers-valid_per_wave),
        authorizations=0,effects=0,canonical_denials=0,admission_rejections=0,noise_denials=0,
        noise_admission_rejections=0,malformed_denials=0,replay_denials=0,sql_connections=0,
        evidence_connections=0,evidence_pending=0,retained_reservations=0,retained_reserved_cents=0)
    phase={}; wave_rows=[]; latencies=[]; accepted_latencies=[]; lock=Lock()
    metrics=OwnerMetrics(observe); sampler=None; whole=perf_counter() if measure else None
    if measure:
        import psutil
        sampler=base.ProcessTreeSampler(psutil,.01);sampler.start()
    helper=base.CustodyFixtureTests()
    settings=base.SQLQoSSettings(max_active=1,max_waiters=7,wait_ns=1_000_000_000) if mode in ('qos','reuse_qos') else None
    def http(name,operation):
        started=perf_counter() if measure else None
        try:
            return operation()
        finally:
            if measure:
                elapsed=perf_counter()-started
                with lock:
                    row=phase.setdefault(name,dict(count=0,wall_seconds=0.,max_wall_seconds=0.))
                    row['count']+=1;row['wall_seconds']+=elapsed;row['max_wall_seconds']=max(row['max_wall_seconds'],elapsed)
    try:
        case,client,app,service,registrar,observer=helper.fixture(
            reuse_evidence_connection=mode in ('reuse','reuse_qos'),sql_qos_settings=settings)
        base.require_fixture_path(case.path)
        prepared=[]; originals=[]; all_orders=[]
        for wave in range(waves):
            orders=[replace(case.order(f'stream-{wave}-{i}'),purchase_price_cents=1) for i in range(valid_per_wave)]
            originals.extend(asdict(order) for order in orders);all_orders.extend(orders)
            jobs=[('valid',{'proposal_commitment_id':case.commit(service,order).commitment_id},i) for i,order in enumerate(orders)]
            if workload=='mixed_stream':
                from test_api import NOW
                expired=replace(case.order(f'expired-{wave}'),purchase_price_cents=1,expires_at_ns=NOW-1)
                expired_ref=case.commit(service,expired).commitment_id
                noise=[('malformed',{'proposal_commitment_id':'invalid','sql_qos_settings':{'max_active':4}},None),
                    ('missing',{'proposal_commitment_id':'missing-fixture-reference'},None),
                    ('expired',{'proposal_commitment_id':expired_ref},None),('duplicate',None,None)]
                jobs+=noise[:callers-valid_per_wave]
            prepared.append((orders,jobs))
        previous_ref='missing-fixture-reference'
        with observe_owner(service,case.path,metrics):
            native=sqlite3.connect; evidence_original=service.evidence._connect
            def connect(database,*args,**kwargs):
                if Path(database)!=case.path: raise RuntimeError('SQL escaped sustained fixture')
                with lock: counts['sql_connections']+=1
                return native(database,*args,**kwargs)
            def evidence_open():
                with lock: counts['evidence_connections']+=1
                return evidence_original()
            began,began_cpu=(perf_counter(),process_time()) if measure else (None,None)
            with patch.object(sqlite3,'connect',connect),patch.object(service.evidence,'_connect',evidence_open):
                for wave,(orders,jobs) in enumerate(prepared):
                    barrier=Barrier(len(jobs)); wave_start=perf_counter() if measure else None
                    def authorize(job):
                        kind,payload,index=job
                        if kind=='duplicate': payload={'proposal_commitment_id':previous_ref}
                        barrier.wait(timeout=10)
                        start=perf_counter() if measure else None
                        response=http('authorize_'+kind,lambda:client.post('/v1/domain-attempts',json=payload))
                        return kind,index,response,(perf_counter()-start)*1000 if measure else None
                    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
                        responses=list(pool.map(authorize,jobs))
                    accepted=[]
                    for kind,index,response,elapsed in responses:
                        status=response.status_code
                        if kind=='valid':
                            if status not in (200,403,429): raise RuntimeError('unexpected valid authorization status '+str(status))
                            counts['authorizations']+=status==200;counts['canonical_denials']+=status==403;counts['admission_rejections']+=status==429
                            if measure:
                                latencies.append(elapsed)
                                if status==200: accepted_latencies.append(elapsed)
                            if status==200: accepted.append((index,response.json()))
                        else:
                            expected=(422,) if kind=='malformed' else (403,429)
                            if status not in expected: raise RuntimeError('noise gained authority or changed decoder outcome')
                            counts['noise_denials']+=status==403;counts['noise_admission_rejections']+=status==429;counts['malformed_denials']+=status==422
                    with closing(sqlite3.connect(case.path)) as db:
                        reservations=db.execute('SELECT order_hash,reserved_cents,state FROM commerce_reservations').fetchall()
                        attempts=db.execute('SELECT object_hash,state FROM custody_attempts').fetchall()
                    attempt_hashes={row[0] for row in attempts}
                    retained=[row for row in reservations if row[0] not in attempt_hashes and row[2] in ('active','attempted')]
                    retained_cents=sum(row[1] for row in retained)
                    if len(attempts)!=counts['effects']+len(accepted) or service.budget.reserved_cents!=retained_cents+len(accepted):
                        raise RuntimeError('sustained attempt/handle/budget boundary mismatch; no completion allowed')
                    for index,handle in accepted:
                        if service.custody.attempt(handle['attempt_id']).object_hash!=orders[index].order_hash: raise RuntimeError('governed object changed')
                        previous_ref=jobs[index][1]['proposal_commitment_id']
                        for operation,expected in (('execute',200),('reconcile',200),('execute',409)):
                            response=http('replay' if expected==409 else operation,lambda:client.post(f"/v1/domain-attempts/{handle['attempt_id']}/{operation}",json={'handle':handle}))
                            if response.status_code!=expected: raise RuntimeError('sustained completion/replay changed '+str(response.status_code))
                            counts['replay_denials']+=expected==409
                        counts['effects']+=1
                    pending=service.evidence.pending_count()
                    if pending or service.budget.spent_cents!=counts['effects'] or service.budget.reserved_cents!=retained_cents:
                        raise RuntimeError('sustained evidence/budget mismatch')
                    if registrar.purchase_calls!=counts['effects'] or observer.calls!=counts['effects']: raise RuntimeError('provider effect mismatch')
                    gate=service._sql_qos.snapshot() if settings else None
                    if gate and (gate['active'] or gate['waiting']): raise RuntimeError('sustained gate leaked capacity')
                    wave_rows.append(dict(wave=wave,effects=len(accepted),evidence_pending=pending,
                        retained_reservations=len(retained),reserved_cents=retained_cents,
                        wall_seconds=perf_counter()-wave_start if measure else None))
                    if measure:
                        print(json.dumps(dict(mode=mode,workload=workload,**wave_rows[-1])),flush=True)
                elapsed=perf_counter()-began if measure else None; cpu=process_time()-began_cpu if measure else None
        if originals!=[asdict(order) for order in all_orders]: raise RuntimeError('order bytes changed')
        counts['retained_reservations']=len(retained);counts['retained_reserved_cents']=retained_cents
        if counts['effects']+counts['canonical_denials']+counts['admission_rejections']!=counts['offered_valid']: raise RuntimeError('valid work disappeared')
        if sum(counts[k] for k in ('noise_denials','noise_admission_rejections','malformed_denials'))!=counts['offered_noise']: raise RuntimeError('noise disappeared')
        with closing(sqlite3.connect(case.path)) as db:
            counts['audit_records']=db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
            counts['sqlite_bytes']=db.execute('PRAGMA page_count').fetchone()[0]*db.execute('PRAGMA page_size').fetchone()[0]
        with closing(service.evidence._connect()) as db:
            if db.execute('PRAGMA synchronous').fetchone()[0]!=2: raise RuntimeError('FULL changed')
        gate=service._sql_qos.snapshot() if settings else None
        resources=sampler.finish(perf_counter()-whole,os.cpu_count() or 1) if measure else None
        return dict(mode=mode,workload=workload,waves=waves,callers=callers,**counts,
            completion_percent=100*counts['effects']/counts['offered_valid'],wall_seconds=elapsed,cpu_seconds=cpu,
            useful_completions_per_second=counts['effects']/elapsed if measure else None,
            cpu_seconds_per_effect=cpu/counts['effects'] if measure and counts['effects'] else None,
            sql_connections_per_effect=counts['sql_connections']/counts['effects'] if counts['effects'] else None,
            valid_authorization_p95_ms=base.percentile(latencies,.95),accepted_authorization_p95_ms=base.percentile(accepted_latencies,.95),
            max_wave_seconds=max(row['wall_seconds'] for row in wave_rows) if measure else None,
            http_stages=phase,sql_observer=metrics.snapshot() if observe else None,observer_enabled=observe,
            wave_results=wave_rows,
            qos_peak_active=gate['peak_active'] if gate else 0,qos_peak_waiters=gate['peak_waiters'] if gate else 0,
            qos_timeouts=gate['timed_out'] if gate else 0,peak_rss_mib=resources['peak_sum_rss_mib'] if measure else None,resources=resources)
    except BaseException:
        if sampler: sampler.finish(perf_counter()-whole,os.cpu_count() or 1)
        raise
    finally:
        helper.doCleanups();gc.collect()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--iterations',type=int,default=10);parser.add_argument('--repeats',type=int,default=4)
    parser.add_argument('--callers',type=int,default=8);parser.add_argument('--observe',action='store_true')
    parser.add_argument('--json',type=Path,default=ROOT/'perf-results/sql-qos.json')
    parser.add_argument('--check-only',action='store_true');parser.add_argument('--self-test',action='store_true')
    args=parser.parse_args();storage=base.fixture_storage()
    if not 1<=args.iterations<=100 or not 1<=args.repeats<=20 or not 1<=args.callers<=8: parser.error('1-100 waves, 1-20 repeats, 1-8 callers required')
    if args.check_only:
        print('Sustained SQL ready; one owner/database, bounded pilot, no performance run');return
    if args.self_test:
        import unittest,warnings
        failures=[];previous=sys.unraisablehook
        class StrictResult(unittest.TextTestResult):
            def stopTest(self,test): gc.collect();super().stopTest(test)
        try:
            sys.unraisablehook=lambda event:failures.append(type(event.exc_value).__name__)
            with warnings.catch_warnings():
                warnings.simplefilter('error',ResourceWarning)
                suite=unittest.TestSuite([unittest.defaultTestLoader.discover(str(ROOT/'custody-service/tests')),
                    unittest.defaultTestLoader.loadTestsFromName('tests.test_evidence_connection_reuse'),
])
                result=unittest.TextTestRunner(stream=sys.stdout,verbosity=2,resultclass=StrictResult).run(suite);gc.collect()
            print('UNRAISABLE EXCEPTIONS:',len(failures))
            if not result.wasSuccessful() or failures: raise RuntimeError('Sustained correctness failed')
        finally: sys.unraisablehook=previous
        return
    rows=[]
    for repeat in range(args.repeats):
        for workload in WORKLOADS:
            for mode in MODES[repeat%4:]+MODES[:repeat%4]:
                print(f'[{repeat+1}/{args.repeats}] {workload}: {mode}, {args.iterations} waves on same SQLite',flush=True)
                rows.append(dict(repeat=repeat,**run_sample(mode,workload,args.iterations,callers=args.callers,measure=True,observe=args.observe)))
    summaries=[]
    for workload in WORKLOADS:
        for mode in MODES:
            samples=[row for row in rows if row['mode']==mode and row['workload']==workload];summary=dict(workload=workload,mode=mode)
            for key,value in samples[0].items():
                if type(value) in (int,float) and key not in ('repeat','peak_rss_mib'):
                    summary[key]=statistics.median(row[key] for row in samples) if all(row[key] is not None for row in samples) else None
            summary['peak_rss_mib']=max(row['peak_rss_mib'] for row in samples);summaries.append(summary);print(json.dumps(summary),flush=True)
    sources=['scripts/benchmark_sql_qos.py','scripts/sql_qos_lab.py','scripts/sql_qos_observer.py',
        'pulpo/kernel.py','pulpo/state.py','pulpo/custody.py','pulpo/custody_domain.py','pulpo/custody_evidence.py','pulpo/commerce.py',
        'custody-service/src/pulpo_custody_service/core.py','custody-service/src/pulpo_custody_service/sql_qos.py',
        'custody-service/tests/test_sql_qos.py','custody-service/tests/test_sql_qos_benchmark.py']
    args.json.parent.mkdir(parents=True,exist_ok=True)
    args.json.write_text(json.dumps(dict(method='Canonical HTTP; sustained authorization waves on one owner/SQLite, complete admitted handles sequentially; no retry/reset',
        timing='Prepared commitments outside timer; HTTP, thread/counter and wave-boundary checks inside; final footprint/cleanup outside; RSS whole sample',
        budget='Synthetic one-cent orders; at most 800 cents total offered valid work; existing 3000-cent ceiling unchanged',
        qos=dict(max_active=1,max_waiters=7,wait_ns=1_000_000_000),observer_enabled=args.observe,
        observer_limits='Optional observer delegates same existing SQL connections, adds read-only close probes and measured overhead; no SQL/parameters logged; phase wall sums overlap across concurrent calls',
        storage=storage,python=sys.version,platform=platform.platform(),sqlite=sqlite3.sqlite_version,
        host=dict(logical_cpus=os.cpu_count(),processor=platform.processor()),
        git_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        source_sha256={name:sha256((ROOT/name).read_bytes()).hexdigest() for name in sources},rows=rows,summaries=summaries),indent=2)+'\n')


if __name__=='__main__':main()

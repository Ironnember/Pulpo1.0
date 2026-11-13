import argparse, gc, hashlib, json, os, platform, statistics, subprocess, sys, tempfile, time
from pathlib import Path
import psutil
setup = argparse.ArgumentParser(add_help=False)
setup.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
setup.add_argument('--output', type=Path)
locations, _ = setup.parse_known_args()
REPO = locations.repo.resolve()
OUT = (locations.output or REPO / 'perf-results/json-encoder-local').resolve()
sys.path.insert(0, str(REPO))
from pulpo import GovernanceKernel, Policy
from pulpo import state, kernel
if (REPO / 'pulpo/audit_parallel.py').is_file():
    from pulpo import audit_parallel
else:
    audit_parallel = None

def git(*args):
    return subprocess.check_output(['git', *args], cwd=REPO, text=True).strip()

def freeze():
    names = git('ls-files','-z').split('\0')
    names += [p for p in git('ls-files','--others','--exclude-standard','-z').split('\0') if not p.startswith(('work/', 'perf-results/'))]
    manifest = {p:hashlib.sha256((REPO/p).read_bytes()).hexdigest() for p in names if p and (REPO/p).is_file()}
    doc = {'branch':git('branch','--show-current'),'commit':git('rev-parse','HEAD'),'status':git('status','--porcelain=v1'),'files':manifest}
    (OUT/'preservation-before.json').write_text(json.dumps(doc,indent=2))
    print('Frozen',len(manifest),'source/config/doc/test files')

def payload(i):
    return {'index':i,'resource':'repo:benchmark','detail':'x'*100,'unicode':'café 🐙','optional':None,'enabled':True,'cost':i%100,'nested':{'values':[1,2.5,False],'empty':[]}}

def legacy(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def worker(n, workload):
    values = [payload(i) for i in range(n)]
    # Independent legacy serialization generates fixture chain before timing.
    rows=[]
    records=[]
    if workload.startswith('verify'):
        previous='0'*64
        for i,p in enumerate(values):
            body={'event':'benchmark','payload':p,'previous_hash':previous,'timestamp_ns':i+1}
            digest=hashlib.sha256(legacy(body)).hexdigest()
            rows.append(('benchmark',legacy(p).decode(),previous,i+1,digest))
            records.append({**body,'hash':digest})
            previous=digest
    engine = audit_parallel.AuditVerificationEngine(workers=0,cache_size=0,batch_size=4096) if audit_parallel is not None else None
    # Minimal read-only state bypasses bootstrap and SQL to isolate full audit record processing.
    class ReadState:
        @property
        def audit(self): return records
    if workload=='verify_full':
        subject=object.__new__(GovernanceKernel)
        subject._state=ReadState()
        subject._audit_verification_engine=None
    gc.collect()
    proc=psutil.Process()
    mem0=proc.memory_info()
    c0=time.process_time_ns(); t0=time.perf_counter_ns()
    result=[]
    if workload=='serialize':
        for p in values: result.append(state._canonical(p))
    elif workload=='audit_record':
        previous='0'*64
        for i,p in enumerate(values):
            record=state._audit_record(previous,'benchmark',p,i+1)
            result.append(record)
            previous=record['hash']
    elif workload=='verify_engine':
        assert engine.verify_rows(rows)
    elif workload=='verify_full':
        assert subject.verify_audit()
    wall=(time.perf_counter_ns()-t0)/1e6; cpu=(time.process_time_ns()-c0)/1e6
    mem1=proc.memory_info()
    # Native Windows high water mark includes untimed fixture setup and imports.
    observed={'records':n,'workload':workload,'wall_ms':wall,'records_per_ms':n/wall,'cpu_ms':cpu,'cpu_ms_per_record':cpu/n,'peak_rss_mb':mem1.peak_wset/1e6,'rss_start_mb':mem0.rss/1e6,'rss_end_mb':mem1.rss/1e6,'memory_delta_mb':(mem1.rss-mem0.rss)/1e6,'peak_rss_increase_mb':(mem1.peak_wset-mem0.peak_wset)/1e6,'workers':0,'execution_processes':1,'batch_size':4096 if workload=='verify_engine' else n,'cache_size':0}
    # Validate work outside timing using unchanged independent legacy definition.
    if workload=='serialize':
        assert all(b==legacy(p) for b,p in zip(result,values))
    elif workload=='audit_record':
        previous='0'*64
        for i,(p,r) in enumerate(zip(values,result)):
            body={'event':'benchmark','payload':p,'previous_hash':previous,'timestamp_ns':i+1}
            assert r['hash']==hashlib.sha256(legacy(body)).hexdigest()
            previous=r['hash']
    print(json.dumps(observed))

def phase(name):
    doc={'phase':name,'commit':git('rev-parse','HEAD'),'branch':git('branch','--show-current'),'dirty':bool(git('status','--porcelain=v1')),'python':sys.version,'executable':sys.executable,'platform':platform.platform(),'physical_cores':psutil.cpu_count(logical=False),'logical_cpus':psutil.cpu_count(),'ram_bytes':psutil.virtual_memory().total,'source_hashes':{p:hashlib.sha256((REPO/p).read_bytes()).hexdigest() for p in ['pulpo/state.py','pulpo/kernel.py','pulpo/audit_parallel.py'] if (REPO/p).is_file()},'repetitions':5,'memory_units':'decimal MB (1,000,000 bytes)','measurement':'Fresh process per sample; imports, payload/legacy-chain setup, GC and independent result validation excluded from wall/CPU; CPU measured by process_time_ns (all process threads); native Windows peak working set includes imports and untimed fixture setup; RSS end-start is memory delta. Single local process, no pool, no digest cache. Results retained until memory observation. In-memory synthetic records; no database I/O or end-to-end effect execution; OS caches not flushed. Workload order alternates per repetition.','samples':[],'medians':[]}
    workloads=['serialize','audit_record','verify_full']
    if audit_parallel is not None: workloads.insert(2, 'verify_engine')
    for n in [10000,50000,100000]:
        for rep in range(5):
            for workload in (workloads if rep%2==0 else list(reversed(workloads))):
                sample=json.loads(subprocess.check_output([sys.executable,__file__,'--worker',str(n),'--workload',workload,'--repo',str(REPO),'--output',str(OUT)],text=True,cwd=REPO))
                sample['repetition']=rep+1
                doc['samples'].append(sample)
            (OUT/(name+'.json')).write_text(json.dumps(doc,indent=2))
            print(name,n,'repetition',rep+1,flush=True)
        for workload in workloads:
            group=[s for s in doc['samples'] if s['records']==n and s['workload']==workload]
            summary={'records':n,'workload':workload}
            for k in ['wall_ms','records_per_ms','cpu_ms','cpu_ms_per_record','peak_rss_mb','memory_delta_mb','peak_rss_increase_mb','rss_start_mb']:
                summary[k]=statistics.median(s[k] for s in group)
            doc['medians'].append(summary)
    (OUT/(name+'.json')).write_text(json.dumps(doc,indent=2))
    print(json.dumps(doc['medians'],indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser(parents=[setup]); parser.add_argument('--freeze',action='store_true'); parser.add_argument('--phase'); parser.add_argument('--worker',type=int); parser.add_argument('--workload'); args=parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    if args.freeze: freeze()
    elif args.worker: worker(args.worker,args.workload)
    else: phase(args.phase)

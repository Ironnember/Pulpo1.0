"""Benchmark-only owner SQL timing. Never installed in production or transport."""
from contextlib import contextmanager, ExitStack
import cProfile
from pathlib import Path
import sqlite3
from threading import RLock, local
from time import perf_counter, thread_time
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]

class OwnerMetrics:
    def __init__(self, enabled=True, *, function_cpu=False):
        if type(enabled) is not bool or type(function_cpu) is not bool:
            raise ValueError("explicit boolean observation modes required")
        self.enabled=enabled
        self.function_cpu=function_cpu
        self.identities={}
        self.lock=RLock()
        self.context=local()
        self.stages={}
        self.functions={}
        self.sqlite_settings=set()

    def key(self,name):
        phase=getattr(self.context,'phase','owner')
        component=getattr(self.context,'component','')
        return '/'.join(x for x in (phase,component,name) if x)

    def run(self,name,operation):
        if not self.enabled:
            return operation()
        key=self.key(name)
        wall,cpu=perf_counter(),thread_time()
        ok=False
        try:
            result=operation()
            ok=True
            return result
        finally:
            elapsed,cost=perf_counter()-wall,thread_time()-cpu
            with self.lock:
                if key not in self.stages and len(self.stages)>=512:
                    raise RuntimeError('profile stage budget exhausted')
                row=self.stages.setdefault(key,dict(count=0,failures=0,wall_seconds=0.,thread_cpu_seconds=0.,max_wall_seconds=0.))
                row['count']+=1
                row['failures']+=not ok
                row['wall_seconds']+=elapsed
                row['thread_cpu_seconds']+=cost
                row['max_wall_seconds']=max(row['max_wall_seconds'],elapsed)

    def cpu_profile(self,name,operation):
        if not self.function_cpu:
            return self.run('service_total',operation)
        profiler=cProfile.Profile(timer=thread_time)
        profiler.enable()
        try:
            return self.run('service_total',operation)
        finally:
            profiler.disable()
            self.run('observer_cpu_aggregation',lambda:self.aggregate_cpu(name,profiler))

    def aggregate_cpu(self,name,profiler):
        # Lexical code identity: no filesystem resolution/stat per function.
        # Cache at most 4096 identities; no code frames/arguments/locals retained.
        with self.lock:
            for row in profiler.getstats():
                identity=self.identities.get(row.code)
                if identity is None:
                    if len(self.identities)>=4096:
                        raise RuntimeError('CPU identity budget exhausted')
                    if isinstance(row.code,str):
                        identity=row.code
                    else:
                        file=Path(row.code.co_filename)
                        try:
                            filename=str(file.relative_to(ROOT))
                        except ValueError:
                            filename=file.name
                        identity=f'{filename}:{row.code.co_firstlineno}:{row.code.co_name}'
                    self.identities[row.code]=identity
                key=name+'/'+identity
                if key not in self.functions and len(self.functions)>=4096:
                    raise RuntimeError('CPU profile function budget exhausted')
                entry=self.functions.setdefault(key,dict(calls=0,self_cpu_seconds=0.,inclusive_cpu_seconds=0.))
                entry['calls']+=row.callcount
                entry['self_cpu_seconds']+=row.inlinetime
                entry['inclusive_cpu_seconds']+=row.totaltime

    def snapshot(self):
        with self.lock:
            top={phase:sorted((dict(function=key.split('/',1)[1],**v)
                  for key,v in self.functions.items() if key.startswith(phase+'/')),
                  key=lambda r:r['self_cpu_seconds'],reverse=True)[:20]
                 for phase in ('authorize','execute','reconcile')}
            return dict(function_cpu=self.function_cpu,stages={k:dict(v) for k,v in self.stages.items()},cpu_functions=top,
                        observed_sqlite_settings=[dict(synchronous=s,journal_mode=j) for s,j in sorted(self.sqlite_settings)])


def sql_kind(sql):
    kind=sql.split(None,1)[0].upper() if isinstance(sql,str) and sql.strip() else 'EMPTY'
    return kind if kind in {'SELECT','INSERT','UPDATE','DELETE','BEGIN','COMMIT','ROLLBACK','PRAGMA','CREATE','ALTER','WITH','EMPTY'} else 'OTHER'


class ProfileCursor:
    def __init__(self,cursor,metrics,kind):
        self._cursor,self._metrics,self._kind=cursor,metrics,kind
    def fetchone(self):
        return self._metrics.run('sql_'+self._kind+'_fetchone',self._cursor.fetchone)
    def fetchall(self):
        return self._metrics.run('sql_'+self._kind+'_fetchall',self._cursor.fetchall)
    def fetchmany(self,*args):
        return self._metrics.run('sql_'+self._kind+'_fetchmany',lambda:self._cursor.fetchmany(*args))
    def __iter__(self):
        return self
    def __next__(self):
        return self._metrics.run('sql_'+self._kind+'_next',lambda:next(self._cursor))
    def __getattr__(self,name):
        return getattr(self._cursor,name)


class ProfileConnection:
    def __init__(self,connection,metrics):
        object.__setattr__(self,'_connection',connection)
        object.__setattr__(self,'_metrics',metrics)
        object.__setattr__(self,'_closed',False)
    def __setattr__(self,name,value):
        setattr(self._connection,name,value)
    def __getattr__(self,name):
        return getattr(self._connection,name)
    def execute(self,sql,*args,**kwargs):
        cursor=self._metrics.run('sql_'+sql_kind(sql)+'_execute',lambda:self._connection.execute(sql,*args,**kwargs))
        return ProfileCursor(cursor,self._metrics,sql_kind(sql))
    def executemany(self,sql,*args,**kwargs):
        cursor=self._metrics.run('sql_'+sql_kind(sql)+'_executemany',lambda:self._connection.executemany(sql,*args,**kwargs))
        return ProfileCursor(cursor,self._metrics,sql_kind(sql))
    def executescript(self,script):
        cursor=self._metrics.run('sql_script',lambda:self._connection.executescript(script))
        return ProfileCursor(cursor,self._metrics,'OTHER')
    def __enter__(self):
        self._connection.__enter__()
        return self
    def __exit__(self,exc_type,exc_value,traceback):
        stage=('transaction_rollback_exit' if exc_type else 'transaction_commit_exit') if self._connection.in_transaction else 'transaction_noop_exit'
        return self._metrics.run(stage,lambda:self._connection.__exit__(exc_type,exc_value,traceback))
    def commit(self):
        return self._metrics.run('explicit_commit',self._connection.commit)
    def rollback(self):
        return self._metrics.run('explicit_rollback',self._connection.rollback)
    def close(self):
        if self._closed:
            return self._connection.close()
        try:
            # Read-only observer probes on the SAME owner connection. Their
            # cost is included in instrumented HTTP totals, not SQL verb totals.
            if self._metrics.enabled:
                sync=self._connection.execute('PRAGMA synchronous').fetchone()[0]
                journal=self._connection.execute('PRAGMA journal_mode').fetchone()[0]
                with self._metrics.lock:
                    self._metrics.sqlite_settings.add((sync,journal))
        finally:
            try:
                self._metrics.run('connection_close',self._connection.close)
            finally:
                object.__setattr__(self,'_closed',True)


@contextmanager
def observe_owner(service,path,metrics):
    if not metrics.enabled:
        yield
        return
    original_connect=sqlite3.connect
    def connect(database,*args,**kwargs):
        if Path(database).resolve()!=Path(path).resolve():
            raise RuntimeError('profile connection escaped its existing fixture owner')
        connection=metrics.run('connection_open',lambda:original_connect(database,*args,**kwargs))
        return ProfileConnection(connection,metrics)
    def phase_wrapper(original,phase):
        def wrapped(*args,**kwargs):
            before=getattr(metrics.context,'phase','owner')
            metrics.context.phase=phase
            try:
                return metrics.cpu_profile(phase,lambda:original(*args,**kwargs))
            finally:
                metrics.context.phase=before
        return wrapped
    def evidence_wrapper(original):
        def wrapped(*args,**kwargs):
            before=getattr(metrics.context,'component','')
            metrics.context.component='evidence'
            try:
                return metrics.run('projection_total',lambda:original(*args,**kwargs))
            finally:
                metrics.context.component=before
        return wrapped
    with ExitStack() as stack:
        stack.enter_context(patch.object(sqlite3,'connect',connect))
        for name,phase in (('authorize_commitment','authorize'),('execute','execute'),('reconcile','reconcile')):
            stack.enter_context(patch.object(service,name,phase_wrapper(getattr(service,name),phase)))
        # Executor may already hold the original bound _project_evidence callback.
        # Observe its existing evidence object instead of replacing that callback.
        stack.enter_context(patch.object(service.evidence,'project_all',evidence_wrapper(service.evidence.project_all)))
        yield

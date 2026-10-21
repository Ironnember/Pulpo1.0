"""Opt-in owner admission only. No SQL handles, callbacks, authority or routing."""
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from threading import Condition
from time import monotonic_ns


@dataclass(frozen=True, slots=True)
class SQLQoSSettings:
    max_active: int = 1
    max_waiters: int = 8
    wait_ns: int = 250_000_000

    def __post_init__(self):
        for name,low,high in (('max_active',1,4),('max_waiters',0,64),('wait_ns',0,30_000_000_000)):
            value=getattr(self,name)
            if type(value) is not int or not low<=value<=high:
                raise ValueError(f'{name} must be an integer in [{low}, {high}]')


class SQLAdmissionRejected(RuntimeError):
    """Terminal pre-operation overload; no implicit retry or authority change."""


class SQLAdmissionGate:
    __slots__=('settings','_condition','_active','_waiters','_counts','_last')

    def __init__(self,settings):
        if type(settings) is not SQLQoSSettings:
            raise ValueError('trusted SQLQoSSettings required')
        self.settings=settings
        self._condition=Condition()
        self._active=set()
        self._waiters=deque()
        self._last=-1
        self._counts=dict(admitted=0,rejected=0,timed_out=0,peak_active=0,peak_waiters=0)

    def _now(self):
        now=monotonic_ns()
        if type(now) is not int or now<0 or now<self._last:
            raise ValueError('invalid SQL admission clock')
        self._last=now
        return now

    def _grant(self):
        lease=object()
        self._active.add(lease)
        self._counts['admitted']+=1
        self._counts['peak_active']=max(self._counts['peak_active'],len(self._active))
        return lease

    def acquire(self):
        with self._condition:
            now=self._now()
            if not self._waiters and len(self._active)<self.settings.max_active:
                return self._grant()
            if len(self._waiters)>=self.settings.max_waiters or self.settings.wait_ns==0:
                self._counts['rejected']+=1
                raise SQLAdmissionRejected('sql_admission_budget_exhausted')
            ticket=object()
            self._waiters.append(ticket)
            self._counts['peak_waiters']=max(self._counts['peak_waiters'],len(self._waiters))
            deadline=now+self.settings.wait_ns
            try:
                while True:
                    remaining=deadline-self._now()
                    if remaining<=0:
                        self._counts['timed_out']+=1
                        raise SQLAdmissionRejected('sql_admission_wait_exhausted')
                    if self._waiters[0] is ticket and len(self._active)<self.settings.max_active:
                        self._waiters.popleft()
                        return self._grant()
                    self._condition.wait(remaining/1_000_000_000)
            finally:
                if ticket in self._waiters:
                    self._waiters.remove(ticket)
                self._condition.notify_all()

    def release(self,lease):
        with self._condition:
            if lease not in self._active:
                raise ValueError('unknown or already released SQL admission lease')
            self._active.remove(lease)
            self._condition.notify_all()

    @contextmanager
    def slot(self):
        lease=self.acquire()
        try:
            yield
        finally:
            self.release(lease)

    def snapshot(self):
        with self._condition:
            return dict(self._counts,active=len(self._active),waiting=len(self._waiters))


def sql_admitted(original):
    """Trusted service owner retains its original method; gate retains no owner."""
    @wraps(original)
    def wrapped(self,*args,**kwargs):
        gate=self._sql_qos
        if gate is None:
            return original(self,*args,**kwargs)
        with gate.slot():
            return original(self,*args,**kwargs)
    return wrapped

"""Bounded service-edge admission controls for the existing authority routes."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import threading
import time
from typing import Iterator


class AdmissionRejected(RuntimeError):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("authority service admission limit exceeded")
        self.retry_after_seconds = max(1, retry_after_seconds)


@dataclass(frozen=True)
class AdmissionConfig:
    window_seconds: float = 60.0
    requests_per_window: int = 60
    polls_per_window: int = 30
    max_concurrent: int = 32
    principal_budget: int = 120

    def __post_init__(self) -> None:
        if self.window_seconds <= 0 or any(
            value <= 0
            for value in (
                self.requests_per_window,
                self.polls_per_window,
                self.max_concurrent,
                self.principal_budget,
            )
        ):
            raise ValueError("authority admission limits must be positive")


class AdmissionController:
    """Process-local edge limiter; canonical authority semantics remain in core."""

    def __init__(
        self,
        config: AdmissionConfig | None = None,
        *,
        clock: callable = time.monotonic,
    ) -> None:
        self.config = config or AdmissionConfig()
        self._clock = clock
        self._lock = threading.Lock()
        self._active = 0
        self._requests: dict[str, deque[float]] = {}
        self._polls: dict[str, deque[float]] = {}
        self._budget: dict[str, deque[float]] = {}

    def _trim(self, events: deque[float], now: float) -> None:
        cutoff = now - self.config.window_seconds
        while events and events[0] <= cutoff:
            events.popleft()

    def _retry_after(self, events: deque[float], now: float) -> int:
        return max(1, int(events[0] + self.config.window_seconds - now + 0.999))

    def enter(self, principal: str, *, poll: bool = False) -> Iterator[None]:
        now = self._clock()
        with self._lock:
            if not principal or principal != principal.strip():
                raise AdmissionRejected(1)
            events = (self._polls if poll else self._requests).setdefault(principal, deque())
            self._trim(events, now)
            if len(events) >= (
                self.config.polls_per_window if poll else self.config.requests_per_window
            ):
                raise AdmissionRejected(self._retry_after(events, now))
            budget = self._budget.setdefault(principal, deque())
            self._trim(budget, now)
            if len(budget) >= self.config.principal_budget:
                raise AdmissionRejected(self._retry_after(budget, now))
            if self._active >= self.config.max_concurrent:
                raise AdmissionRejected(1)
            events.append(now)
            budget.append(now)
            self._active += 1

        class _Lease:
            def __enter__(_self) -> None:
                return None

            def __exit__(_self, exc_type, exc, tb) -> bool:
                with self._lock:
                    self._active -= 1
                return False

        return _Lease()

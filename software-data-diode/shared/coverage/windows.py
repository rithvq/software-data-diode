"""Injected time and conservative scheduling, without admission/recovery I/O."""
from dataclasses import dataclass
from datetime import datetime, timezone
import time
from typing import Protocol

from .models import CoverageLimitation, WindowIdentity


WINDOW_US = 10000000
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def utc_microseconds(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("ingress clock must be timezone-aware")
    elapsed = value.astimezone(timezone.utc) - UNIX_EPOCH
    return (elapsed.days * 86400 + elapsed.seconds) * 1000000 + elapsed.microseconds


def window_identity(*, ledger_epoch: str, device_id: str, contract_hash: str,
                    ingress_time: datetime) -> WindowIdentity:
    return WindowIdentity(ledger_epoch=ledger_epoch, device_id=device_id,
                          contract_hash=contract_hash, window_index=utc_microseconds(ingress_time) // WINDOW_US)


class Clock(Protocol):
    def utc_now(self) -> datetime: ...
    def monotonic_ns(self) -> int: ...


class SystemClock:
    def utc_now(self):
        return datetime.now(timezone.utc)

    def monotonic_ns(self):
        return time.monotonic_ns()


@dataclass(frozen=True)
class ClosedWindow:
    window_index: int
    limitations: tuple[CoverageLimitation, ...]

    @property
    def eligible_for_negative(self):
        return not self.limitations


@dataclass(frozen=True)
class WindowUpdate:
    active_window_index: int | None
    closed_window: ClosedWindow | None = None
    skipped_window_count: int = 0


class WindowSchedule:
    """Call under the future admission writer lock. Never reopen a sealed index.

    A discontinuity halts this instance; a caller must reconcile state before
    creating another one. Skipped windows are not fabricated as healthy empties.
    """
    def __init__(self, clock: Clock, *, jump_tolerance_us: int = 100000, interrupted: bool = False):
        if type(jump_tolerance_us) is not int or not 0 <= jump_tolerance_us <= 1000000:
            raise ValueError("invalid clock jump tolerance")
        self.clock, self.tolerance = clock, jump_tolerance_us
        self.last_utc_us = utc_microseconds(clock.utc_now())
        self.last_monotonic_ns = self._monotonic()
        self.active_index = self.last_utc_us // WINDOW_US
        self.limitations = ()
        if self.last_utc_us % WINDOW_US:
            self.limitations += (CoverageLimitation.STARTUP_PARTIAL,)
        if interrupted:
            self.limitations += (CoverageLimitation.INTERRUPTED,)
        self.deadline_ns = self.last_monotonic_ns + (WINDOW_US - self.last_utc_us % WINDOW_US) * 1000
        self.halted = False

    def _monotonic(self):
        value = self.clock.monotonic_ns()
        if type(value) is not int or value < 0:
            raise ValueError("clock must return nonnegative integer nanoseconds")
        return value

    def interrupt(self) -> WindowUpdate:
        if self.halted:
            raise ValueError("window schedule already halted")
        self.halted = True
        return WindowUpdate(None, ClosedWindow(self.active_index,
                            tuple(dict.fromkeys((*self.limitations, CoverageLimitation.INTERRUPTED)))))

    def poll(self) -> WindowUpdate:
        if self.halted:
            raise ValueError("window schedule halted; recovery is required")
        now_us = utc_microseconds(self.clock.utc_now())
        now_ns = self._monotonic()
        delta_ns = now_ns - self.last_monotonic_ns
        deviation_ns = (now_us - self.last_utc_us) * 1000 - delta_ns
        index = now_us // WINDOW_US
        if (delta_ns < 0 or abs(deviation_ns) > self.tolerance * 1000
                or (index != self.active_index and now_ns < self.deadline_ns)
                or (now_ns >= self.deadline_ns and index <= self.active_index)):
            self.halted = True
            limited = tuple(dict.fromkeys((*self.limitations, CoverageLimitation.CLOCK_DISCONTINUITY)))
            return WindowUpdate(None, ClosedWindow(self.active_index, limited))
        self.last_utc_us, self.last_monotonic_ns = now_us, now_ns
        if now_ns < self.deadline_ns:
            return WindowUpdate(self.active_index)
        skipped = index - self.active_index - 1
        old_limits = self.limitations
        if skipped:
            old_limits += (CoverageLimitation.INTERRUPTED,)
        closed = ClosedWindow(self.active_index, tuple(dict.fromkeys(old_limits)))
        self.active_index = index
        self.limitations = (CoverageLimitation.INTERRUPTED,) if skipped else ()
        self.deadline_ns = now_ns + (WINDOW_US - now_us % WINDOW_US) * 1000
        return WindowUpdate(index, closed, skipped)

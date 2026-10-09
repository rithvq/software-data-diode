from __future__ import annotations

from dataclasses import dataclass
import time
import math
from threading import Lock


@dataclass
class TokenBucketRateLimiter:
    max_messages_per_second: float
    burst_limit: int

    def __post_init__(self) -> None:
        if not math.isfinite(self.max_messages_per_second) or self.max_messages_per_second <= 0 or self.burst_limit < 1:
            raise ValueError("rate and burst capacity must be positive and finite")
        self._tokens = float(self.burst_limit)
        self._last_refill = time.monotonic()
        self._lock = Lock()

    def allow(self) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                float(self.burst_limit),
                self._tokens + elapsed * self.max_messages_per_second,
            )
            self._last_refill = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

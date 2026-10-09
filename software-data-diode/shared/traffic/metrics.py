from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from statistics import median
from threading import Lock
import time

from shared.models import CongestionState, PriorityLevel


@dataclass
class PriorityTrafficMetrics:
    delivered_count: int = 0
    dropped_count: int = 0
    filtered_count: int = 0
    queued_count: int = 0
    latencies: deque[float] = field(default_factory=lambda: deque(maxlen=2000))
    queue_waits: deque[float] = field(default_factory=lambda: deque(maxlen=2000))


class TrafficMetrics:
    def __init__(self) -> None:
        self._lock = Lock()
        self.started_at = time.monotonic()
        self.total_bytes_generated = 0
        self.bytes_filtered = 0
        self.bytes_transmitted = 0
        self.queue_utilization = 0.0
        self.congestion_state = CongestionState.NORMAL
        self.by_priority: dict[PriorityLevel, PriorityTrafficMetrics] = defaultdict(
            PriorityTrafficMetrics
        )

    def record_generated(self, byte_count: int) -> None:
        with self._lock:
            self.total_bytes_generated += byte_count

    def record_filtered(self, priority: PriorityLevel, byte_count: int) -> None:
        with self._lock:
            self.by_priority[priority].filtered_count += 1
            self.bytes_filtered += byte_count

    def record_queued(self, priority: PriorityLevel) -> None:
        with self._lock:
            self.by_priority[priority].queued_count += 1

    def record_dropped(self, priority: PriorityLevel) -> None:
        with self._lock:
            self.by_priority[priority].dropped_count += 1

    def record_delivered(
        self,
        priority: PriorityLevel,
        byte_count: int,
        latency_seconds: float,
        queue_wait_seconds: float,
    ) -> None:
        with self._lock:
            priority_metrics = self.by_priority[priority]
            priority_metrics.delivered_count += 1
            priority_metrics.latencies.append(latency_seconds)
            priority_metrics.queue_waits.append(queue_wait_seconds)
            self.bytes_transmitted += byte_count

    def update_queue_state(
        self,
        queue_length: int,
        max_queue_size: int,
        congestion_state: CongestionState,
    ) -> None:
        with self._lock:
            self.queue_utilization = queue_length / max_queue_size if max_queue_size else 0.0
            self.congestion_state = congestion_state

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            elapsed = max(time.monotonic() - self.started_at, 0.001)
            return {
                "total_bytes_generated": self.total_bytes_generated,
                "bytes_filtered": self.bytes_filtered,
                "bytes_transmitted": self.bytes_transmitted,
                "latency_sample_count": sum(len(m.latencies) for m in self.by_priority.values()),
                "average_latency": self._latency_average(),
                "latency_p95": _percentile([v for m in self.by_priority.values() for v in m.latencies], 95),
                "throughput_messages_per_second": self._total_delivered() / elapsed,
                "queue_utilization": self.queue_utilization,
                "congestion_state": self.congestion_state,
                "by_priority": {
                    priority: _priority_snapshot(metrics)
                    for priority, metrics in self.by_priority.items()
                },
            }

    def _total_delivered(self) -> int:
        return sum(metrics.delivered_count for metrics in self.by_priority.values())

    def _latency_average(self):
        values = [v for metrics in self.by_priority.values() for v in metrics.latencies]
        return sum(values) / len(values) if values else None


def _priority_snapshot(metrics: PriorityTrafficMetrics) -> dict[str, object]:
    return {
        "delivered_count": metrics.delivered_count,
        "dropped_count": metrics.dropped_count,
        "filtered_count": metrics.filtered_count,
        "queued_count": metrics.queued_count,
        "latency_p50": _percentile(metrics.latencies, 50),
        "latency_p95": _percentile(metrics.latencies, 95),
        "latency_p99": _percentile(metrics.latencies, 99),
        "queue_wait_p50": _percentile(metrics.queue_waits, 50),
        "queue_wait_p95": _percentile(metrics.queue_waits, 95),
        "queue_wait_p99": _percentile(metrics.queue_waits, 99),
        "average_latency": (
            sum(metrics.latencies) / len(metrics.latencies) if metrics.latencies else None
        ),
        "average_queue_wait": (
            sum(metrics.queue_waits) / len(metrics.queue_waits) if metrics.queue_waits else None
        ),
    }


def _percentile(values: list[float], percentile: int) -> float | None:
    if not values:
        return None
    if percentile == 50:
        return median(values)
    ordered = sorted(values)
    index = min(len(ordered) - 1, round((percentile / 100) * (len(ordered) - 1)))
    return ordered[index]

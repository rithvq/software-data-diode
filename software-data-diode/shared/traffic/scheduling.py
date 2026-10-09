from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import os
import time
from uuid import uuid4

from shared.models import CongestionState, PriorityLevel, SecureTelemetryEnvelope


PRIORITY_VALUE = {
    PriorityLevel.LOW: 1,
    PriorityLevel.MEDIUM: 2,
    PriorityLevel.HIGH: 3,
    PriorityLevel.CRITICAL: 4,
}

CONGESTION_VALUE = {
    CongestionState.NORMAL: 0.0,
    CongestionState.ELEVATED: 0.5,
    CongestionState.CONGESTED: 1.0,
    CongestionState.CRITICAL: 1.5,
}


@dataclass(frozen=True)
class SchedulerWeights:
    priority: float = 10.0
    waiting_age: float = 1.0
    urgency: float = 8.0
    congestion: float = 1.0
    starvation: float = 12.0
    transmission_cost: float = 0.01
    aging_seconds_per_priority: float = 30.0
    starvation_after_seconds: float = 10.0
    max_starvation_factor: float = 4.0


def load_scheduler_weights_from_env() -> SchedulerWeights:
    return SchedulerWeights(
        priority=float(os.getenv("SCHEDULER_WEIGHT_PRIORITY", "10")),
        waiting_age=float(os.getenv("SCHEDULER_WEIGHT_WAITING_AGE", "1")),
        urgency=float(os.getenv("SCHEDULER_WEIGHT_URGENCY", "8")),
        congestion=float(os.getenv("SCHEDULER_WEIGHT_CONGESTION", "1")),
        starvation=float(os.getenv("SCHEDULER_WEIGHT_STARVATION", "12")),
        transmission_cost=float(os.getenv("SCHEDULER_WEIGHT_TRANSMISSION_COST", "0.01")),
        aging_seconds_per_priority=float(os.getenv("AGING_SECONDS_PER_PRIORITY", "30")),
        starvation_after_seconds=float(os.getenv("STARVATION_AFTER_SECONDS", "10")),
        max_starvation_factor=float(os.getenv("MAX_STARVATION_FACTOR", "4")),
    )


@dataclass(frozen=True)
class ScheduledMessage:
    envelope: SecureTelemetryEnvelope
    enqueued_at: float
    size_bytes: int
    arrival_index: int


@dataclass(frozen=True)
class QueuePushResult:
    accepted: bool
    dropped: ScheduledMessage | None = None
    reason: str = ""


class AdaptiveScheduler:
    def __init__(self, weights: SchedulerWeights) -> None:
        self.weights = weights

    def score(
        self,
        item: ScheduledMessage,
        now: float,
        congestion_state: CongestionState,
    ) -> float:
        waiting_age = max(now - item.enqueued_at, 0.0)
        priority_term = PRIORITY_VALUE[item.envelope.priority]
        effective_priority = self.effective_priority(item.envelope.priority, waiting_age)
        urgency = self.urgency(item.envelope)
        congestion_factor = CONGESTION_VALUE[congestion_state] * priority_term
        starvation_factor = min(
            max(waiting_age - self.weights.starvation_after_seconds, 0.0)
            / max(self.weights.starvation_after_seconds, 0.001),
            self.weights.max_starvation_factor,
        )
        return (
            self.weights.priority * effective_priority
            + self.weights.waiting_age * waiting_age
            + self.weights.urgency * urgency
            + self.weights.congestion * congestion_factor
            + self.weights.starvation * starvation_factor
            - self.weights.transmission_cost * item.envelope.estimated_transmission_cost
        )

    def choose(
        self,
        items: list[ScheduledMessage],
        now: float,
        congestion_state: CongestionState,
    ) -> ScheduledMessage:
        return max(
            items,
            key=lambda item: (
                self.score(item, now, congestion_state),
                -item.arrival_index,
            ),
        )

    def effective_priority(self, priority: PriorityLevel, waiting_age: float) -> float:
        boost = waiting_age / max(self.weights.aging_seconds_per_priority, 0.001)
        return min(PRIORITY_VALUE[PriorityLevel.CRITICAL], PRIORITY_VALUE[priority] + boost)

    def urgency(self, envelope: SecureTelemetryEnvelope) -> float:
        if envelope.priority == PriorityLevel.CRITICAL:
            return 1.0
        if envelope.priority == PriorityLevel.HIGH:
            return 0.8
        if envelope.payload.temperature >= 38.0:
            return 0.8
        if envelope.payload.cpu_usage is not None and envelope.payload.cpu_usage >= 90.0:
            return 0.6
        return 0.2 if envelope.priority == PriorityLevel.MEDIUM else 0.0


class BoundedMessageQueue:
    def __init__(self, max_queue_size: int, *, preserve_device_order: bool = False) -> None:
        if max_queue_size <= 0:
            raise ValueError("queue capacity must be positive")
        self.max_queue_size = max_queue_size
        self.preserve_device_order = preserve_device_order
        self._items: deque[ScheduledMessage] = deque()
        self._arrival_counter = 0

    def __len__(self) -> int:
        return len(self._items)

    def push(
        self,
        envelope: SecureTelemetryEnvelope,
        size_bytes: int,
        now: float | None = None,
        reserved: int = 0,
    ) -> QueuePushResult:
        now = time.monotonic() if now is None else now
        self._arrival_counter += 1
        incoming = ScheduledMessage(
            envelope=envelope,
            enqueued_at=now,
            size_bytes=size_bytes,
            arrival_index=self._arrival_counter,
        )

        if len(self._items) < self.max_queue_size - reserved:
            self._items.append(incoming)
            return QueuePushResult(True)

        victim = self._select_overflow_victim(envelope.priority)
        if victim is None:
            return QueuePushResult(False, dropped=incoming, reason="incoming_dropped")

        self._items.remove(victim)
        self._items.append(incoming)
        return QueuePushResult(True, dropped=victim, reason="queued_message_evicted")

    def pop_fifo(self) -> ScheduledMessage | None:
        if not self._items:
            return None
        return self._items.popleft()

    def pop_adaptive(
        self,
        scheduler: AdaptiveScheduler,
        now: float,
        congestion_state: CongestionState,
    ) -> ScheduledMessage | None:
        if not self._items:
            return None
        candidates = list(self._items)
        if self.preserve_device_order:
            # Signed per-device sequences must not overtake earlier queued messages.
            heads = {}
            for item in candidates:
                heads.setdefault(item.envelope.device_id, item)
            candidates = list(heads.values())
        selected = scheduler.choose(candidates, now, congestion_state)
        self._items.remove(selected)
        return selected

    def snapshot(self) -> list[ScheduledMessage]:
        return list(self._items)

    def _select_overflow_victim(
        self,
        incoming_priority: PriorityLevel,
    ) -> ScheduledMessage | None:
        if incoming_priority == PriorityLevel.LOW:
            return None

        lower_priority_items = [
            item
            for item in self._items
            if PRIORITY_VALUE[item.envelope.priority] < PRIORITY_VALUE[incoming_priority]
        ]
        if not lower_priority_items:
            return None

        return min(
            lower_priority_items,
            key=lambda item: (
                PRIORITY_VALUE[item.envelope.priority],
                item.arrival_index,
            ),
        )


class CongestionMonitor:
    def __init__(
        self,
        window_seconds: float = 10.0,
        elevated_threshold: float = 0.5,
        congested_threshold: float = 0.75,
        critical_threshold: float = 0.9,
    ) -> None:
        self.window_seconds = window_seconds
        self.elevated_threshold = elevated_threshold
        self.congested_threshold = congested_threshold
        self.critical_threshold = critical_threshold
        self._incoming_times: deque[float] = deque()
        self._outgoing_times: deque[float] = deque()
        self._latencies: deque[float] = deque(maxlen=200)

    def record_incoming(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self._incoming_times.append(now)
        self._prune(now)

    def record_outgoing(self, latency_seconds: float, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self._outgoing_times.append(now)
        self._latencies.append(latency_seconds)
        self._prune(now)

    def snapshot(self, queue_length: int, max_queue_size: int) -> dict[str, object]:
        now = time.monotonic()
        self._prune(now)
        utilization = queue_length / max_queue_size if max_queue_size else 0.0
        return {
            "queue_length": queue_length,
            "queue_utilization": utilization,
            "incoming_rate": len(self._incoming_times) / self.window_seconds,
            "outgoing_rate": len(self._outgoing_times) / self.window_seconds,
            "recent_latency": self._recent_latency(),
            "processing_load": utilization,
            "congestion_state": self.state(queue_length, max_queue_size),
        }

    def state(self, queue_length: int, max_queue_size: int) -> CongestionState:
        utilization = queue_length / max_queue_size if max_queue_size else 0.0
        if utilization >= self.critical_threshold:
            return CongestionState.CRITICAL
        if utilization >= self.congested_threshold:
            return CongestionState.CONGESTED
        if utilization >= self.elevated_threshold:
            return CongestionState.ELEVATED
        return CongestionState.NORMAL

    def _recent_latency(self) -> float:
        if not self._latencies:
            return 0.0
        return sum(self._latencies) / len(self._latencies)

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._incoming_times and self._incoming_times[0] < cutoff:
            self._incoming_times.popleft()
        while self._outgoing_times and self._outgoing_times[0] < cutoff:
            self._outgoing_times.popleft()


def new_simulated_envelope(
    priority: PriorityLevel,
    created_at,
    sequence_number: int,
    estimated_transmission_cost: float = 1.0,
) -> SecureTelemetryEnvelope:
    from shared.models import TelemetryPayload

    payload = TelemetryPayload(
        temperature=39.0 if priority == PriorityLevel.HIGH else 25.0,
        humidity=50.0,
        status="critical" if priority == PriorityLevel.CRITICAL else "normal",
        event_type="intrusion" if priority == PriorityLevel.CRITICAL else "telemetry",
    )
    return SecureTelemetryEnvelope(
        message_id=uuid4(),
        device_id="simulated-edge",
        created_at=created_at,
        sequence_number=sequence_number,
        priority=priority,
        payload=payload,
        payload_hash="0" * 64,
        signature="simulated",
        estimated_transmission_cost=estimated_transmission_cost,
    )

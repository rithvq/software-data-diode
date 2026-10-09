import asyncio
from collections import OrderedDict, deque
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from .components import default_components
from .interfaces import PipelineComponents, QueuedMessage
from .models import Telemetry, TransferRecord


class QueueFullError(Exception):
    pass


class IdentityConflictError(Exception):
    pass


class PolicyRejectedError(Exception):
    pass


class Pipeline:
    """Bounded admission and transport lifecycle, independent of queue ordering."""

    def __init__(self, service: str, capacity: int = 100,
                 components: PipelineComponents | None = None,
                 log_directory: Path | None = None, history_size: int = 1000):
        if capacity <= 0 or history_size <= 0:
            raise ValueError("capacity and history size must be positive")
        self.service = service
        self.capacity = capacity
        self.components = components or default_components()
        self.in_flight: QueuedMessage | None = None
        self.attempt = 0
        self.accepted_ids: dict[str, str] = {}
        self.completed_ids: OrderedDict[str, str] = OrderedDict()
        self.history_size = history_size
        self.records: deque[dict] = deque(maxlen=history_size)
        self.log_path = log_directory / f"{service}.jsonl" if log_directory else None
        if log_directory:
            log_directory.mkdir(parents=True, exist_ok=True)
        self.wakeup = asyncio.Event()
        self.transmitted = 0
        self.failures = 0

    @property
    def queue_length(self):
        return len(self.components.scheduler) + int(self.in_flight is not None)

    @staticmethod
    def body(message: Telemetry) -> bytes:
        return message.model_dump_json().encode("utf-8")

    @staticmethod
    def digest(body: bytes) -> str:
        return hashlib.sha256(body).hexdigest()

    def admit(self, message: Telemetry, arrival: datetime | None = None) -> bool:
        arrival = arrival or datetime.now(timezone.utc)
        body = self.body(message)
        self.components.estimator.observe_arrival(len(body))
        identifier, digest = str(message.message_id), self.digest(body)
        previous = self.accepted_ids.get(identifier) or self.completed_ids.get(identifier)
        if previous is not None:
            if previous != digest:
                raise IdentityConflictError("message_id already belongs to different telemetry")
            return False
        if self.queue_length >= self.capacity:
            raise QueueFullError("local queue capacity reached")
        state = self.components.estimator.snapshot(self.queue_length)
        information = self.components.analyzer.analyze(message)
        prediction = self.components.predictor.predict(state)
        decision = self.components.policy.decide(message, information, state, prediction)
        if not decision.admit:
            raise PolicyRejectedError(decision.reason)
        item = QueuedMessage(message, body, arrival, datetime.now(timezone.utc))
        self.record(item, "queued", queue_length=self.queue_length + 1, reason=decision.reason)
        self.components.scheduler.enqueue(item)
        self.accepted_ids[identifier] = digest
        self.wakeup.set()
        return True

    def record(self, item: QueuedMessage, event: str, transmission: datetime | None = None,
               queue_length: int | None = None, reason: str = ""):
        record = TransferRecord(
            service=self.service, event=event, message_id=item.message.message_id,
            device_id=item.message.device_id, sequence_number=item.message.sequence_number,
            arrival_timestamp=item.arrival_timestamp, queue_entry_timestamp=item.queue_entry_timestamp,
            transmission_timestamp=transmission, message_size_bytes=len(item.body),
            queue_length=self.queue_length if queue_length is None else queue_length,
            attempt=self.attempt if event != "queued" else 0, reason=reason,
        ).model_dump(mode="json")
        if self.log_path:
            with self.log_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
        self.records.append(record)

    async def transmit_next(self, sender) -> bool:
        if self.in_flight is None:
            self.in_flight = self.components.scheduler.select(
                self.components.estimator.snapshot(self.queue_length)
            )
            self.attempt = 0
        if self.in_flight is None:
            return False
        item = self.in_flight
        self.attempt += 1
        stamp = datetime.now(timezone.utc)
        self.components.estimator.observe_dispatch()
        self.record(item, "transmission_attempt", stamp)
        try:
            await sender(item.body)
        except Exception as exc:
            self.failures += 1
            self.record(item, "retry", stamp, reason=str(exc))
            raise
        # Record before forgetting admission state. If logging fails, a repeat
        # remains safe because the next hop treats the same message ID idempotently.
        self.record(item, "transmitted", stamp, queue_length=self.queue_length - 1)
        identifier = str(item.message.message_id)
        self.completed_ids[identifier] = self.accepted_ids.pop(identifier)
        while len(self.completed_ids) > self.history_size:
            self.completed_ids.popitem(last=False)
        self.in_flight = None
        self.transmitted += 1
        return True

    async def run(self, sender, retry_seconds: float = .5):
        while True:
            if not self.queue_length:
                self.wakeup.clear()
                await self.wakeup.wait()
            try:
                await self.transmit_next(sender)
            except Exception:
                await asyncio.sleep(min(retry_seconds * 2 ** min(self.attempt - 1, 5), 10))

    def snapshot(self):
        return {
            "service": self.service, "queue_length": self.queue_length,
            "capacity": self.capacity, "transmitted_messages": self.transmitted,
            "failed_attempts": self.failures,
            "local_state": asdict(self.components.estimator.snapshot(self.queue_length)),
            "recent_records": list(self.records),
        }

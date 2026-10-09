from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import time
from threading import Lock
from uuid import UUID

from shared.models import RejectionReason, SecureTelemetryEnvelope


@dataclass
class DeviceReplayState:
    highest_sequence_number: int
    latest_timestamp: datetime


class ReplayDetector:
    """In-memory replay and duplicate detector designed for later persistence."""

    def __init__(self, duplicate_ttl_seconds: float, freshness_window_seconds: float) -> None:
        self.duplicate_ttl_seconds = duplicate_ttl_seconds
        self.freshness_window_seconds = freshness_window_seconds
        self._seen_message_ids: dict[UUID, float] = {}
        self._device_state: dict[str, DeviceReplayState] = {}
        self._lock = Lock()

    def check_and_record(self, envelope: SecureTelemetryEnvelope, *, record: bool = True) -> RejectionReason | None:
        with self._lock:
            self._prune()

            now = datetime.now(timezone.utc)
            created_at = envelope.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)

            age_seconds = (now - created_at).total_seconds()
            if age_seconds > self.freshness_window_seconds or age_seconds < -30:
                return RejectionReason.EXPIRED_MESSAGE

            if envelope.message_id in self._seen_message_ids:
                return RejectionReason.DUPLICATE_MESSAGE

            state = self._device_state.get(envelope.device_id)
            if state is not None:
                if envelope.sequence_number <= state.highest_sequence_number:
                    return RejectionReason.REPLAY_DETECTED
                latest_timestamp = state.latest_timestamp
                if latest_timestamp.tzinfo is None:
                    latest_timestamp = latest_timestamp.replace(tzinfo=timezone.utc)
                if created_at <= latest_timestamp:
                    return RejectionReason.REPLAY_DETECTED

            if record:
                self._record(envelope)
            return None

    def record(self, envelope: SecureTelemetryEnvelope) -> None:
        with self._lock:
            self._record(envelope)

    def _record(self, envelope: SecureTelemetryEnvelope) -> None:
        self._seen_message_ids[envelope.message_id] = time.monotonic()
        self._device_state[envelope.device_id] = DeviceReplayState(
            highest_sequence_number=envelope.sequence_number, latest_timestamp=envelope.created_at,
        )

    def _prune(self) -> None:
        cutoff = time.monotonic() - self.duplicate_ttl_seconds
        expired_ids = [
            message_id
            for message_id, seen_at in self._seen_message_ids.items()
            if seen_at < cutoff
        ]
        for message_id in expired_ids:
            del self._seen_message_ids[message_id]

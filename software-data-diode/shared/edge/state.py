from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from threading import Lock
import time

from shared.models import DeviceHealth, DeviceStatistics, PriorityLevel


@dataclass
class _DeviceState:
    sequence_number: int = 0
    received_count: int = 0
    forwarded_count: int = 0
    filtered_count: int = 0
    rejected_count: int = 0
    last_seen: datetime | None = None
    recent_activity: deque[float] = field(default_factory=deque)
    filtering_statistics: Counter[str] = field(default_factory=Counter)
    priority_statistics: Counter[PriorityLevel] = field(default_factory=Counter)


class DeviceRegistry:
    """Thread-safe, per-device gateway state and sequence allocation."""

    def __init__(
        self,
        health_timeout_seconds: float = 30.0,
        rate_window_seconds: float = 60.0,
        sequence_state_path: str | Path | None = None,
    ):
        self.health_timeout_seconds = health_timeout_seconds
        self.rate_window_seconds = rate_window_seconds
        self._devices: dict[str, _DeviceState] = {}
        self._lock = Lock()
        self._sequence_state_path = Path(sequence_state_path) if sequence_state_path else None
        self._load_sequences()

    def record_received(self, device_id: str, priority: PriorityLevel) -> None:
        with self._lock:
            state = self._devices.setdefault(device_id, _DeviceState())
            state.received_count += 1
            state.last_seen = datetime.now(timezone.utc)
            state.recent_activity.append(time.monotonic())
            state.priority_statistics[priority] += 1
            self._prune(state)

    def record_filtered(self, device_id: str, reason: str) -> None:
        with self._lock:
            state = self._devices.setdefault(device_id, _DeviceState())
            state.filtered_count += 1
            state.filtering_statistics[reason] += 1

    def record_rejected(self, device_id: str) -> None:
        with self._lock:
            self._devices.setdefault(device_id, _DeviceState()).rejected_count += 1

    def next_sequence(self, device_id: str) -> int:
        with self._lock:
            state = self._devices.setdefault(device_id, _DeviceState())
            state.sequence_number += 1
            self._persist_sequences()
            return state.sequence_number

    def record_forwarded(self, device_id: str) -> None:
        with self._lock:
            self._devices.setdefault(device_id, _DeviceState()).forwarded_count += 1

    def snapshot(self, device_id: str) -> DeviceStatistics | None:
        with self._lock:
            state = self._devices.get(device_id)
            if state is None:
                return None
            self._prune(state)
            return self._snapshot(device_id, state)

    def snapshots(self) -> list[DeviceStatistics]:
        with self._lock:
            for state in self._devices.values():
                self._prune(state)
            return [self._snapshot(device_id, state) for device_id, state in sorted(self._devices.items())]

    def _snapshot(self, device_id: str, state: _DeviceState) -> DeviceStatistics:
        health = DeviceHealth.UNKNOWN
        if state.last_seen is not None:
            age = (datetime.now(timezone.utc) - state.last_seen).total_seconds()
            health = DeviceHealth.ACTIVE if age <= self.health_timeout_seconds else DeviceHealth.STALE
        return DeviceStatistics(
            device_id=device_id,
            health=health,
            last_seen=state.last_seen,
            last_sequence_number=state.sequence_number,
            received_count=state.received_count,
            forwarded_count=state.forwarded_count,
            filtered_count=state.filtered_count,
            rejected_count=state.rejected_count,
            message_rate_per_minute=round(
                len(state.recent_activity) * 60.0 / self.rate_window_seconds, 3
            ),
            recent_activity_count=len(state.recent_activity),
            filtering_statistics=dict(state.filtering_statistics),
            priority_statistics=dict(state.priority_statistics),
        )

    def _prune(self, state: _DeviceState) -> None:
        cutoff = time.monotonic() - self.rate_window_seconds
        while state.recent_activity and state.recent_activity[0] < cutoff:
            state.recent_activity.popleft()

    def _load_sequences(self) -> None:
        if self._sequence_state_path is None or not self._sequence_state_path.exists():
            return
        document = json.loads(self._sequence_state_path.read_text(encoding="utf-8"))
        for device_id, sequence in document.items():
            parsed = int(sequence)
            if parsed < 0:
                raise ValueError("invalid persisted sequence for " + str(device_id))
            self._devices[str(device_id)] = _DeviceState(sequence_number=parsed)

    def _persist_sequences(self) -> None:
        if self._sequence_state_path is None:
            return
        self._sequence_state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._sequence_state_path.with_suffix(
            self._sequence_state_path.suffix + ".tmp"
        )
        temporary.write_text(
            json.dumps(
                {
                    device_id: state.sequence_number
                    for device_id, state in sorted(self._devices.items())
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        temporary.replace(self._sequence_state_path)

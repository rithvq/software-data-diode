from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
import time

from shared.models import (
    AggregationSummary,
    CongestionState,
    EdgeTelemetryMessage,
    PriorityLevel,
    RejectionReason,
)
from shared.security.crypto import canonical_json


@dataclass(frozen=True)
class EdgeFilterConfig:
    temperature_delta_threshold: float = 0.25
    humidity_delta_threshold: float = 1.0
    duplicate_ttl_seconds: float = 30.0
    low_sampling_interval_seconds: float = 5.0
    aggregation_sample_count: int = 5
    enable_aggregation: bool = True

    @classmethod
    def from_env(cls) -> "EdgeFilterConfig":
        return cls(
            temperature_delta_threshold=float(os.getenv("FILTER_TEMPERATURE_DELTA", "0.25")),
            humidity_delta_threshold=float(os.getenv("FILTER_HUMIDITY_DELTA", "1.0")),
            duplicate_ttl_seconds=float(os.getenv("EDGE_DEDUP_TTL_SECONDS", "30")),
            low_sampling_interval_seconds=float(os.getenv("LOW_SAMPLING_INTERVAL_SECONDS", "5")),
            aggregation_sample_count=int(os.getenv("AGGREGATION_SAMPLE_COUNT", "5")),
            enable_aggregation=os.getenv("ENABLE_AGGREGATION", "true").lower() == "true",
        )


@dataclass(frozen=True)
class EdgeFilterDecision:
    action: str
    message: EdgeTelemetryMessage | None
    reason: RejectionReason | None = None
    generated_bytes: int = 0
    filtered_bytes: int = 0


class EdgeFilter:
    def __init__(self, config: EdgeFilterConfig) -> None:
        self.config = config
        self._last_forwarded: dict[str, EdgeTelemetryMessage] = {}
        self._last_low_forwarded_at: dict[str, float] = {}
        self._fingerprints: dict[str, float] = {}
        self._aggregation_buffers: dict[str, list[EdgeTelemetryMessage]] = {}

    def evaluate(
        self,
        message: EdgeTelemetryMessage,
        priority: PriorityLevel,
        congestion_state: CongestionState = CongestionState.NORMAL,
    ) -> EdgeFilterDecision:
        generated_bytes = len(canonical_json(message.model_dump(mode="json")).encode("utf-8"))

        if priority == PriorityLevel.CRITICAL:
            self._remember_forwarded(message, generated_bytes)
            return EdgeFilterDecision("forward", message, generated_bytes=generated_bytes)

        fingerprint = self._fingerprint(message)
        now = time.monotonic()
        self._prune_fingerprints(now)
        if fingerprint in self._fingerprints:
            return self._filtered_or_aggregate(
                message,
                RejectionReason.FILTERED_DUPLICATE,
                generated_bytes,
            )
        self._fingerprints[fingerprint] = now

        if priority == PriorityLevel.LOW and self._has_no_significant_change(message):
            return self._filtered_or_aggregate(
                message,
                RejectionReason.FILTERED_NO_SIGNIFICANT_CHANGE,
                generated_bytes,
            )

        if (
            priority == PriorityLevel.LOW
            and congestion_state in {CongestionState.CONGESTED, CongestionState.CRITICAL}
            and not self._sampling_window_elapsed(message.device_id, now)
        ):
            return self._filtered_or_aggregate(
                message,
                RejectionReason.FILTERED_NO_SIGNIFICANT_CHANGE,
                generated_bytes,
            )

        self._remember_forwarded(message, generated_bytes)
        return EdgeFilterDecision("forward", message, generated_bytes=generated_bytes)

    def _filtered_or_aggregate(
        self,
        message: EdgeTelemetryMessage,
        reason: RejectionReason,
        generated_bytes: int,
    ) -> EdgeFilterDecision:
        if not self.config.enable_aggregation:
            return EdgeFilterDecision(
                "filtered",
                None,
                reason=reason,
                generated_bytes=generated_bytes,
                filtered_bytes=generated_bytes,
            )

        buffer_key = f"{message.device_id}:{message.event_type}:{message.status}"
        buffer = self._aggregation_buffers.setdefault(buffer_key, [])
        buffer.append(message)
        if len(buffer) < self.config.aggregation_sample_count:
            return EdgeFilterDecision(
                "filtered",
                None,
                reason=reason,
                generated_bytes=generated_bytes,
                filtered_bytes=generated_bytes,
            )

        aggregate = self._make_aggregate(message.device_id, buffer)
        self._aggregation_buffers[buffer_key] = []
        self._remember_forwarded(aggregate, generated_bytes)
        return EdgeFilterDecision(
            "aggregate",
            aggregate,
            reason=reason,
            generated_bytes=generated_bytes,
            filtered_bytes=generated_bytes,
        )

    def _has_no_significant_change(self, message: EdgeTelemetryMessage) -> bool:
        previous = self._last_forwarded.get(message.device_id)
        if previous is None:
            return False
        base_unchanged = (
            abs(message.temperature - previous.temperature)
            < self.config.temperature_delta_threshold
            and abs(message.humidity - previous.humidity) < self.config.humidity_delta_threshold
            and message.status == previous.status
            and message.event_type == previous.event_type
            and message.telemetry_type == previous.telemetry_type
            and message.cpu_usage == previous.cpu_usage
            and message.memory_usage == previous.memory_usage
            and message.attributes == previous.attributes
        )
        metric_keys = set(message.measurements) | set(previous.measurements)
        metrics_unchanged = all(
            key in message.measurements and key in previous.measurements
            and abs(message.measurements[key] - previous.measurements[key]) < 0.01
            for key in metric_keys
        )
        return base_unchanged and metrics_unchanged

    def _sampling_window_elapsed(self, device_id: str, now: float) -> bool:
        last_sent = self._last_low_forwarded_at.get(device_id, 0.0)
        return now - last_sent >= self.config.low_sampling_interval_seconds

    def _remember_forwarded(self, message: EdgeTelemetryMessage, generated_bytes: int) -> None:
        self._last_forwarded[message.device_id] = message
        if message.event_type == "telemetry":
            self._last_low_forwarded_at[message.device_id] = time.monotonic()

    def _fingerprint(self, message: EdgeTelemetryMessage) -> str:
        payload = {
            "device_id": message.device_id,
            "temperature": message.temperature,
            "humidity": message.humidity,
            "status": message.status,
            "event_type": message.event_type,
            "cpu_usage": message.cpu_usage,
            "memory_usage": message.memory_usage,
            "telemetry_type": message.telemetry_type,
            "measurements": message.measurements,
            "attributes": message.attributes,
        }
        return canonical_json(payload)

    def _prune_fingerprints(self, now: float) -> None:
        cutoff = now - self.config.duplicate_ttl_seconds
        expired = [
            fingerprint
            for fingerprint, seen_at in self._fingerprints.items()
            if seen_at < cutoff
        ]
        for fingerprint in expired:
            del self._fingerprints[fingerprint]

    def _make_aggregate(
        self,
        device_id: str,
        samples: list[EdgeTelemetryMessage],
    ) -> EdgeTelemetryMessage:
        temperatures = [sample.temperature for sample in samples]
        humidities = [sample.humidity for sample in samples]
        average_temperature = sum(temperatures) / len(temperatures)
        average_humidity = sum(humidities) / len(humidities)
        metric_names = set().union(*(sample.measurements for sample in samples))
        metric_averages = {
            metric: round(
                sum(sample.measurements.get(metric, 0.0) for sample in samples) / len(samples),
                3,
            )
            for metric in metric_names
        }
        def optional_mean(field):
            values = [getattr(sample, field) for sample in samples if getattr(sample, field) is not None]
            return sum(values) / len(values) if values else None

        return EdgeTelemetryMessage(
            device_id=device_id,
            timestamp=datetime.now(timezone.utc),
            temperature=round(average_temperature, 3),
            humidity=round(average_humidity, 3),
            status="aggregated",
            event_type="aggregate",
            telemetry_type=samples[-1].telemetry_type,
            cpu_usage=optional_mean("cpu_usage"),
            memory_usage=optional_mean("memory_usage"),
            measurements=metric_averages,
            attributes=samples[-1].attributes,
            aggregation=AggregationSummary(
                average_temperature=round(average_temperature, 3),
                minimum_temperature=min(temperatures),
                maximum_temperature=max(temperatures),
                average_humidity=round(average_humidity, 3),
                sample_count=len(samples),
                metric_averages=metric_averages,
            ),
        )

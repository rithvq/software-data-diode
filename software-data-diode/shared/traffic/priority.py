from __future__ import annotations

from dataclasses import dataclass
import os

from shared.models import EdgeTelemetryMessage, PriorityLevel, TelemetryPayload


@dataclass(frozen=True)
class PriorityRuleConfig:
    critical_event_types: tuple[str, ...] = ("intrusion", "attack")
    high_temperature_threshold: float = 38.0
    medium_temperature_threshold: float = 34.0
    medium_cpu_threshold: float = 85.0
    medium_memory_threshold: float = 85.0
    medium_status_values: tuple[str, ...] = ("warning", "abnormal", "degraded")
    high_packet_rate_threshold: float = 8000.0
    critical_failed_logins_threshold: float = 5.0
    high_vibration_threshold: float = 8.0


def load_priority_config_from_env() -> PriorityRuleConfig:
    return PriorityRuleConfig(
        critical_event_types=_csv_tuple(
            os.getenv("CRITICAL_EVENT_TYPES", "intrusion,attack")
        ),
        high_temperature_threshold=float(os.getenv("HIGH_TEMPERATURE_THRESHOLD", "38.0")),
        medium_temperature_threshold=float(os.getenv("MEDIUM_TEMPERATURE_THRESHOLD", "34.0")),
        medium_cpu_threshold=float(os.getenv("MEDIUM_CPU_THRESHOLD", "85.0")),
        medium_memory_threshold=float(os.getenv("MEDIUM_MEMORY_THRESHOLD", "85.0")),
        medium_status_values=_csv_tuple(
            os.getenv("MEDIUM_STATUS_VALUES", "warning,abnormal,degraded")
        ),
        high_packet_rate_threshold=float(os.getenv("HIGH_PACKET_RATE_THRESHOLD", "8000")),
        critical_failed_logins_threshold=float(
            os.getenv("CRITICAL_FAILED_LOGINS_THRESHOLD", "5")
        ),
        high_vibration_threshold=float(os.getenv("HIGH_VIBRATION_THRESHOLD", "8")),
    )


def classify_priority(
    message: EdgeTelemetryMessage | TelemetryPayload,
    config: PriorityRuleConfig,
) -> PriorityLevel:
    event_type = message.event_type.lower()
    status = message.status.lower()

    if status == "critical" or any(rule in event_type for rule in config.critical_event_types) or any(
        rule in status for rule in config.critical_event_types
    ):
        return PriorityLevel.CRITICAL

    if message.measurements.get("failed_logins", 0) >= config.critical_failed_logins_threshold:
        return PriorityLevel.CRITICAL

    if message.measurements.get("packets_per_second", 0) >= config.high_packet_rate_threshold:
        return PriorityLevel.HIGH

    if message.measurements.get("vibration_mm_s", 0) >= config.high_vibration_threshold:
        return PriorityLevel.HIGH

    if message.temperature >= config.high_temperature_threshold:
        return PriorityLevel.HIGH

    if message.temperature >= config.medium_temperature_threshold:
        return PriorityLevel.MEDIUM

    if message.cpu_usage is not None and message.cpu_usage >= config.medium_cpu_threshold:
        return PriorityLevel.MEDIUM

    if message.memory_usage is not None and message.memory_usage >= config.medium_memory_threshold:
        return PriorityLevel.MEDIUM

    if status in config.medium_status_values:
        return PriorityLevel.MEDIUM

    return PriorityLevel.LOW


def _csv_tuple(value: str) -> tuple[str, ...]:
    return tuple(item.strip().lower() for item in value.split(",") if item.strip())

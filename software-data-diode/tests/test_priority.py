from datetime import datetime, timezone

from shared.models import EdgeTelemetryMessage, PriorityLevel
from shared.traffic import PriorityRuleConfig, classify_priority


def message(**updates) -> EdgeTelemetryMessage:
    data = {
        "device_id": "edge-device-001",
        "timestamp": datetime.now(timezone.utc),
        "temperature": 25.0,
        "humidity": 50.0,
        "status": "normal",
        "event_type": "telemetry",
    }
    data.update(updates)
    return EdgeTelemetryMessage(**data)


def test_priority_rules_are_centralized_and_deterministic() -> None:
    config = PriorityRuleConfig(
        critical_event_types=("intrusion",),
        high_temperature_threshold=38.0,
        medium_temperature_threshold=34.0,
        medium_cpu_threshold=85.0,
        medium_memory_threshold=85.0,
        medium_status_values=("warning",),
    )

    assert classify_priority(message(event_type="intrusion"), config) == PriorityLevel.CRITICAL
    assert classify_priority(message(temperature=39.0), config) == PriorityLevel.HIGH
    assert classify_priority(message(cpu_usage=90.0), config) == PriorityLevel.MEDIUM
    assert classify_priority(message(status="warning"), config) == PriorityLevel.MEDIUM
    assert classify_priority(message(), config) == PriorityLevel.LOW

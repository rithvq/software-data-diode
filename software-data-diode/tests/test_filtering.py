from datetime import datetime, timezone

from shared.models import EdgeTelemetryMessage, PriorityLevel, RejectionReason
from shared.traffic import EdgeFilter, EdgeFilterConfig


def message(temperature: float, humidity: float = 50.0, **updates) -> EdgeTelemetryMessage:
    data = {
        "device_id": "edge-device-001",
        "timestamp": datetime.now(timezone.utc),
        "temperature": temperature,
        "humidity": humidity,
        "status": "normal",
        "event_type": "telemetry",
    }
    data.update(updates)
    return EdgeTelemetryMessage(**data)


def test_change_based_filtering_reduces_low_value_telemetry() -> None:
    edge_filter = EdgeFilter(
        EdgeFilterConfig(
            temperature_delta_threshold=0.5,
            humidity_delta_threshold=2.0,
            enable_aggregation=False,
        )
    )

    first = edge_filter.evaluate(message(25.0), PriorityLevel.LOW)
    second = edge_filter.evaluate(message(25.2, 50.5), PriorityLevel.LOW)

    assert first.action == "forward"
    assert second.action == "filtered"
    assert second.reason == RejectionReason.FILTERED_NO_SIGNIFICANT_CHANGE
    assert second.filtered_bytes > 0


def test_low_priority_samples_can_be_aggregated() -> None:
    edge_filter = EdgeFilter(
        EdgeFilterConfig(
            temperature_delta_threshold=1.0,
            humidity_delta_threshold=5.0,
            aggregation_sample_count=3,
            enable_aggregation=True,
        )
    )

    assert edge_filter.evaluate(message(25.0), PriorityLevel.LOW).action == "forward"
    assert edge_filter.evaluate(message(25.1), PriorityLevel.LOW).action == "filtered"
    assert edge_filter.evaluate(message(25.2), PriorityLevel.LOW).action == "filtered"
    decision = edge_filter.evaluate(message(25.3), PriorityLevel.LOW)

    assert decision.action == "aggregate"
    assert decision.message is not None
    assert decision.message.aggregation is not None
    assert decision.message.aggregation.sample_count == 3
    assert decision.message.status == "aggregated"


def test_critical_events_are_never_aggregated() -> None:
    edge_filter = EdgeFilter(EdgeFilterConfig(aggregation_sample_count=1))

    decision = edge_filter.evaluate(
        message(25.0, status="critical", event_type="intrusion"),
        PriorityLevel.CRITICAL,
    )

    assert decision.action == "forward"
    assert decision.message is not None
    assert decision.message.event_type == "intrusion"

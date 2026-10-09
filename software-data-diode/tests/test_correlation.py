from datetime import datetime, timezone

from shared.analytics.correlation import CorrelationEngine, CorrelationRule, RuleCondition
from shared.models import AlertSeverity, FogEvent, TelemetryType
from tests.conftest import make_signed_envelope


def make_event(
    private_key: object,
    device_id: str,
    telemetry_type: TelemetryType,
    measurements: dict[str, float],
    sequence: int,
    cpu_usage: float | None = None,
) -> FogEvent:
    return FogEvent(
        received_at=datetime.now(timezone.utc),
        envelope=make_signed_envelope(
            private_key,
            device_id=device_id,
            telemetry_type=telemetry_type,
            measurements=measurements,
            sequence_number=sequence,
            cpu_usage=cpu_usage,
        ),
    )


def test_cross_device_rule_creates_security_event_and_alert(private_key: object) -> None:
    rule = CorrelationRule(
        rule_id="incident",
        alert_type="POTENTIAL_SECURITY_INCIDENT",
        description="Correlated incident",
        severity=AlertSeverity.CRITICAL,
        window_seconds=60,
        cooldown_seconds=120,
        conditions=(
            RuleCondition("network", "packets_per_second", ">=", 8000),
            RuleCondition("system", "cpu_usage", ">=", 90),
            RuleCondition("security", "failed_logins", ">=", 5),
        ),
    )
    engine = CorrelationEngine((rule,))

    engine.process(make_event(private_key, "edge-device-03", TelemetryType.NETWORK, {"packets_per_second": 9000}, 1))
    engine.process(make_event(private_key, "edge-device-02", TelemetryType.SYSTEM, {}, 1, cpu_usage=95))
    events, alerts = engine.process(
        make_event(private_key, "edge-device-04", TelemetryType.SECURITY, {"failed_logins": 8}, 1)
    )

    assert len(events) == 1
    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.CRITICAL
    assert alerts[0].source_devices == ["edge-device-02", "edge-device-03", "edge-device-04"]
    assert len(alerts[0].evidence) == 3

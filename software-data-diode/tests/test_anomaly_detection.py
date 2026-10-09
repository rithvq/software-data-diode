from datetime import datetime, timezone

from shared.analytics import AnomalyDetector, DetectionConfig, ThresholdRule
from shared.models import AlertSeverity, FogEvent
from tests.conftest import make_signed_envelope


def event(private_key: object, value: float, sequence: int) -> FogEvent:
    envelope = make_signed_envelope(
        private_key,
        sequence_number=sequence,
        temperature=value,
    )
    return FogEvent(received_at=datetime.now(timezone.utc), envelope=envelope)


def test_threshold_detector_explains_out_of_range_value(private_key: object) -> None:
    detector = AnomalyDetector(
        DetectionConfig(thresholds=(ThresholdRule("temperature", maximum=40.0),))
    )

    anomalies = detector.detect(event(private_key, 45.0, 1))

    assert len(anomalies) == 1
    assert anomalies[0].detector == "threshold"
    assert anomalies[0].expected_value == 40.0
    assert "outside the configured range" in anomalies[0].explanation


def test_moving_average_and_zscore_detect_a_spike(private_key: object) -> None:
    detector = AnomalyDetector(
        DetectionConfig(
            thresholds=(),
            moving_average_window=5,
            moving_average_minimum_samples=3,
            moving_average_deviation_ratio=0.2,
            zscore_window=5,
            zscore_minimum_samples=5,
            zscore_threshold=3.0,
        )
    )
    for sequence, value in enumerate([10.0, 10.5, 9.5, 10.2, 9.8], start=1):
        detector.detect(event(private_key, value, sequence))

    anomalies = detector.detect(event(private_key, 30.0, 6))
    methods = {anomaly.detector for anomaly in anomalies}

    assert methods == {"moving_average", "zscore"}
    assert next(item for item in anomalies if item.detector == "zscore").severity == AlertSeverity.HIGH

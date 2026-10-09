from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
from pathlib import Path
from statistics import fmean, pstdev

from shared.models import AlertSeverity, AnomalyRecord, FogEvent, TelemetryPayload


@dataclass(frozen=True)
class ThresholdRule:
    metric: str
    minimum: float | None = None
    maximum: float | None = None
    severity: AlertSeverity = AlertSeverity.WARNING


@dataclass(frozen=True)
class DetectionConfig:
    thresholds: tuple[ThresholdRule, ...]
    moving_average_window: int = 5
    moving_average_minimum_samples: int = 3
    moving_average_deviation_ratio: float = 0.25
    zscore_window: int = 20
    zscore_minimum_samples: int = 5
    zscore_threshold: float = 3.0

    def __post_init__(self):
        for window, minimum in ((self.moving_average_window, self.moving_average_minimum_samples),
                                (self.zscore_window, self.zscore_minimum_samples)):
            if not isinstance(window, int) or not isinstance(minimum, int) or not 1 <= minimum <= window:
                raise ValueError("detector minimum samples must be between 1 and window size")
        for value in (self.moving_average_deviation_ratio, self.zscore_threshold):
            if not math.isfinite(value) or value <= 0:
                raise ValueError("detector thresholds must be finite and positive")
        for rule in self.thresholds:
            bounds = [value for value in (rule.minimum, rule.maximum) if value is not None]
            if not bounds or any(not math.isfinite(value) for value in bounds):
                raise ValueError("threshold rule needs finite bounds")
            if len(bounds) == 2 and rule.minimum > rule.maximum:
                raise ValueError("threshold minimum exceeds maximum")

    @classmethod
    def from_file(cls, path: str | Path) -> "DetectionConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            thresholds=tuple(
                ThresholdRule(
                    metric=item["metric"],
                    minimum=item.get("minimum"),
                    maximum=item.get("maximum"),
                    severity=AlertSeverity(item.get("severity", "WARNING")),
                )
                for item in data.get("thresholds", [])
            ),
            moving_average_window=data.get("moving_average", {}).get("window", 5),
            moving_average_minimum_samples=data.get("moving_average", {}).get(
                "minimum_samples", 3
            ),
            moving_average_deviation_ratio=data.get("moving_average", {}).get(
                "deviation_ratio", 0.25
            ),
            zscore_window=data.get("zscore", {}).get("window", 20),
            zscore_minimum_samples=data.get("zscore", {}).get("minimum_samples", 5),
            zscore_threshold=data.get("zscore", {}).get("threshold", 3.0),
        )


def extract_metrics(payload: TelemetryPayload) -> dict[str, float]:
    metrics = {
        "temperature": payload.temperature,
        "humidity": payload.humidity,
    }
    if payload.cpu_usage is not None:
        metrics["cpu_usage"] = payload.cpu_usage
    if payload.memory_usage is not None:
        metrics["memory_usage"] = payload.memory_usage
    metrics.update(payload.measurements)
    return metrics


class AnomalyDetector:
    """Stateful deterministic threshold, moving-average, and z-score detectors."""

    def __init__(self, config: DetectionConfig) -> None:
        self.config = config
        max_window = max(config.moving_average_window, config.zscore_window)
        self._history: dict[tuple[str, str], deque[float]] = defaultdict(
            lambda: deque(maxlen=max_window)
        )

    def detect(self, event: FogEvent) -> list[AnomalyRecord]:
        anomalies: list[AnomalyRecord] = []
        for metric, value in extract_metrics(event.envelope.payload).items():
            history = self._history[(event.envelope.device_id, metric)]
            anomalies.extend(self._threshold_anomalies(event, metric, value))
            moving = self._moving_average_anomaly(event, metric, value, history)
            if moving is not None:
                anomalies.append(moving)
            zscore = self._zscore_anomaly(event, metric, value, history)
            if zscore is not None:
                anomalies.append(zscore)
            history.append(value)
        return anomalies

    def _threshold_anomalies(
        self, event: FogEvent, metric: str, value: float
    ) -> list[AnomalyRecord]:
        results = []
        for rule in self.config.thresholds:
            if rule.metric != metric:
                continue
            outside = (rule.minimum is not None and value < rule.minimum) or (
                rule.maximum is not None and value > rule.maximum
            )
            if outside:
                boundary = (
                    rule.minimum
                    if rule.minimum is not None and value < rule.minimum
                    else rule.maximum
                )
                results.append(
                    self._record(
                        event,
                        "threshold",
                        metric,
                        value,
                        boundary,
                        None,
                        rule.severity,
                        f"{metric}={value:.3f} is outside the configured range",
                    )
                )
        return results

    def _moving_average_anomaly(
        self, event: FogEvent, metric: str, value: float, history: deque[float]
    ) -> AnomalyRecord | None:
        samples = list(history)[-self.config.moving_average_window :]
        if len(samples) < self.config.moving_average_minimum_samples:
            return None
        expected = fmean(samples)
        denominator = max(abs(expected), 1.0)
        deviation = abs(value - expected) / denominator
        if deviation < self.config.moving_average_deviation_ratio:
            return None
        return self._record(
            event,
            "moving_average",
            metric,
            value,
            expected,
            deviation,
            AlertSeverity.WARNING,
            f"{metric} deviates {deviation:.2%} from its recent moving average",
        )

    def _zscore_anomaly(
        self, event: FogEvent, metric: str, value: float, history: deque[float]
    ) -> AnomalyRecord | None:
        samples = list(history)[-self.config.zscore_window :]
        if len(samples) < self.config.zscore_minimum_samples:
            return None
        standard_deviation = pstdev(samples)
        if standard_deviation == 0:
            return None
        expected = fmean(samples)
        score = abs(value - expected) / standard_deviation
        if score < self.config.zscore_threshold:
            return None
        return self._record(
            event,
            "zscore",
            metric,
            value,
            expected,
            score,
            AlertSeverity.HIGH,
            f"{metric} has a z-score of {score:.3f}",
        )

    @staticmethod
    def _record(
        event: FogEvent,
        detector: str,
        metric: str,
        observed: float,
        expected: float | None,
        score: float | None,
        severity: AlertSeverity,
        explanation: str,
    ) -> AnomalyRecord:
        return AnomalyRecord(
            timestamp=datetime.now(timezone.utc),
            message_id=event.envelope.message_id,
            device_id=event.envelope.device_id,
            detector=detector,
            metric=metric,
            observed_value=observed,
            expected_value=expected,
            score=score,
            severity=severity,
            explanation=explanation,
        )

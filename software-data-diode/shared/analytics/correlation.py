from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import math
import operator
from pathlib import Path

from shared.analytics.detection import extract_metrics
from shared.models import AlertRecord, AlertSeverity, FogEvent, SecurityEvent


OPERATORS = {
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
    "==": operator.eq,
}


@dataclass(frozen=True)
class RuleCondition:
    telemetry_type: str
    metric: str
    operator: str
    value: float


@dataclass(frozen=True)
class CorrelationRule:
    rule_id: str
    alert_type: str
    description: str
    severity: AlertSeverity
    window_seconds: float
    cooldown_seconds: float
    conditions: tuple[RuleCondition, ...]

    def __post_init__(self):
        if not self.conditions:
            raise ValueError("correlation rule needs at least one condition")
        if not math.isfinite(self.window_seconds) or self.window_seconds <= 0:
            raise ValueError("correlation window must be finite and positive")
        if not math.isfinite(self.cooldown_seconds) or self.cooldown_seconds < 0:
            raise ValueError("correlation cooldown must be finite and nonnegative")
        for condition in self.conditions:
            if condition.operator not in OPERATORS or not math.isfinite(condition.value):
                raise ValueError("invalid correlation operator or threshold")

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "CorrelationRule":
        return cls(
            rule_id=str(data["rule_id"]),
            alert_type=str(data["alert_type"]),
            description=str(data["description"]),
            severity=AlertSeverity(str(data["severity"])),
            window_seconds=float(data.get("window_seconds", 60)),
            cooldown_seconds=float(data.get("cooldown_seconds", 60)),
            conditions=tuple(RuleCondition(**item) for item in data["conditions"]),
        )


class CorrelationEngine:
    def __init__(self, rules: tuple[CorrelationRule, ...]) -> None:
        self.rules = rules
        self._matches: dict[tuple[str, int], list[dict[str, object]]] = {}
        self._last_alert: dict[str, datetime] = {}

    @classmethod
    def from_file(cls, path: str | Path) -> "CorrelationEngine":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(tuple(CorrelationRule.from_dict(rule) for rule in data.get("rules", [])))

    def process(self, event: FogEvent) -> tuple[list[SecurityEvent], list[AlertRecord]]:
        now = event.received_at
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        metrics = extract_metrics(event.envelope.payload)
        security_events: list[SecurityEvent] = []
        alerts: list[AlertRecord] = []

        for rule in self.rules:
            self._prune(rule, now)
            for index, condition in enumerate(rule.conditions):
                if self._matches_condition(event, metrics, condition):
                    bucket = self._matches.setdefault((rule.rule_id, index), [])
                    bucket.append(
                        {
                            "timestamp": now,
                            "device_id": event.envelope.device_id,
                            "message_id": str(event.envelope.message_id),
                            "metric": condition.metric,
                            "value": metrics[condition.metric],
                        }
                    )

            evidence = []
            for index in range(len(rule.conditions)):
                candidates = self._matches.get((rule.rule_id, index), [])
                if not candidates:
                    break
                evidence.append(candidates[-1])
            else:
                last_alert = self._last_alert.get(rule.rule_id)
                if last_alert and (now - last_alert).total_seconds() < rule.cooldown_seconds:
                    continue
                self._last_alert[rule.rule_id] = now
                serializable_evidence = [
                    {**item, "timestamp": item["timestamp"].isoformat()} for item in evidence
                ]
                devices = sorted({str(item["device_id"]) for item in evidence})
                security_event = SecurityEvent(
                    timestamp=now,
                    event_type=rule.alert_type,
                    severity=rule.severity,
                    source_devices=devices,
                    evidence=serializable_evidence,
                    description=rule.description,
                )
                alert = AlertRecord(
                    timestamp=now,
                    source_devices=devices,
                    alert_type=rule.alert_type,
                    severity=rule.severity,
                    evidence=serializable_evidence,
                    description=rule.description,
                )
                security_events.append(security_event)
                alerts.append(alert)
        return security_events, alerts

    def _prune(self, rule: CorrelationRule, now: datetime) -> None:
        cutoff = now - timedelta(seconds=rule.window_seconds)
        for index in range(len(rule.conditions)):
            key = (rule.rule_id, index)
            self._matches[key] = [
                item for item in self._matches.get(key, []) if item["timestamp"] >= cutoff
            ]

    @staticmethod
    def _matches_condition(
        event: FogEvent, metrics: dict[str, float], condition: RuleCondition
    ) -> bool:
        if event.envelope.payload.telemetry_type != condition.telemetry_type:
            return False
        if condition.metric not in metrics or condition.operator not in OPERATORS:
            return False
        return OPERATORS[condition.operator](metrics[condition.metric], condition.value)

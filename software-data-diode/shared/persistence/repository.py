from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from threading import Lock
from typing import Protocol
from uuid import UUID

from shared.models import (
    AlertRecord,
    AnomalyRecord,
    FogEvent,
    ObservabilitySnapshot,
    SecurityEvent,
)


class Repository(Protocol):
    def healthcheck(self) -> bool: ...

    def save_telemetry(self, event: FogEvent) -> None: ...

    def save_rejection(
        self,
        reason: str,
        message_id: UUID | None = None,
        device_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> None: ...

    def save_anomaly(self, anomaly: AnomalyRecord) -> None: ...

    def save_security_event(self, event: SecurityEvent) -> None: ...

    def save_alert(self, alert: AlertRecord) -> None: ...

    def save_performance_metric(
        self, service: str, metric_name: str, metric_value: float, labels: dict[str, object]
    ) -> None: ...

    def save_experiment_metadata(
        self,
        experiment_id: UUID,
        name: str,
        started_at: datetime,
        completed_at: datetime,
        configuration: dict[str, object],
        results: object,
    ) -> None: ...

    def save_observability_snapshot(self, snapshot: ObservabilitySnapshot) -> None: ...


class InMemoryRepository:
    """Test and local fallback repository with the same persistence contract."""

    def __init__(self) -> None:
        self.telemetry: list[FogEvent] = []
        self.rejections: list[dict[str, object]] = []
        self.anomalies: list[AnomalyRecord] = []
        self.security_events: list[SecurityEvent] = []
        self.alerts: list[AlertRecord] = []
        self.performance_metrics: list[dict[str, object]] = []
        self.experiments: list[dict[str, object]] = []
        self.observability_snapshots: list[ObservabilitySnapshot] = []
        self._lock = Lock()

    def healthcheck(self) -> bool:
        return True

    def save_telemetry(self, event: FogEvent) -> None:
        with self._lock:
            if not any(item.envelope.message_id == event.envelope.message_id for item in self.telemetry):
                self.telemetry.append(event)

    def save_rejection(
        self,
        reason: str,
        message_id: UUID | None = None,
        device_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> None:
        with self._lock:
            self.rejections.append(
                {
                    "timestamp": datetime.now(timezone.utc),
                    "reason": reason,
                    "message_id": message_id,
                    "device_id": device_id,
                    "metadata": metadata or {},
                }
            )

    def save_anomaly(self, anomaly: AnomalyRecord) -> None:
        with self._lock:
            if not any(item.anomaly_id == anomaly.anomaly_id for item in self.anomalies):
                self.anomalies.append(anomaly)

    def save_security_event(self, event: SecurityEvent) -> None:
        with self._lock:
            if not any(item.event_id == event.event_id for item in self.security_events):
                self.security_events.append(event)

    def save_alert(self, alert: AlertRecord) -> None:
        with self._lock:
            if not any(item.alert_id == alert.alert_id for item in self.alerts):
                self.alerts.append(alert)

    def save_performance_metric(
        self, service: str, metric_name: str, metric_value: float, labels: dict[str, object]
    ) -> None:
        with self._lock:
            self.performance_metrics.append(
                {
                    "service": service,
                    "metric_name": metric_name,
                    "metric_value": metric_value,
                    "labels": labels,
                }
            )

    def save_experiment_metadata(
        self,
        experiment_id: UUID,
        name: str,
        started_at: datetime,
        completed_at: datetime,
        configuration: dict[str, object],
        results: object,
    ) -> None:
        with self._lock:
            self.experiments.append(
                {
                    "experiment_id": experiment_id,
                    "name": name,
                    "started_at": started_at,
                    "completed_at": completed_at,
                    "configuration": configuration,
                    "results": results,
                }
            )

    def save_observability_snapshot(self, snapshot: ObservabilitySnapshot) -> None:
        with self._lock:
            self.observability_snapshots.append(snapshot)


class PostgresRepository:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    def _connect(self):
        import psycopg

        return psycopg.connect(self.database_url, connect_timeout=3,
                               options="-c statement_timeout=5000 -c lock_timeout=3000")

    def healthcheck(self) -> bool:
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                return cursor.fetchone() == (1,)
        except Exception:
            return False

    def save_telemetry(self, event: FogEvent) -> None:
        envelope = event.envelope
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO accepted_telemetry
                    (event_id, message_id, device_id, sequence_number, priority,
                     telemetry_type, created_at, received_at, payload, payload_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (message_id) DO NOTHING
                """,
                (
                    event.event_id,
                    envelope.message_id,
                    envelope.device_id,
                    envelope.sequence_number,
                    envelope.priority,
                    envelope.payload.telemetry_type,
                    envelope.created_at,
                    event.received_at,
                    _json(envelope.payload.model_dump(mode="json")),
                    envelope.payload_hash,
                ),
            )

    def save_rejection(
        self,
        reason: str,
        message_id: UUID | None = None,
        device_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO rejected_messages (reason, message_id, device_id, metadata)
                VALUES (%s, %s, %s, %s::jsonb)
                """,
                (reason, message_id, device_id, _json(metadata or {})),
            )

    def save_anomaly(self, anomaly: AnomalyRecord) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO anomalies
                    (anomaly_id, timestamp, message_id, device_id, detector, metric,
                     observed_value, expected_value, score, severity, explanation)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (anomaly_id) DO NOTHING
                """,
                (
                    anomaly.anomaly_id,
                    anomaly.timestamp,
                    anomaly.message_id,
                    anomaly.device_id,
                    anomaly.detector,
                    anomaly.metric,
                    anomaly.observed_value,
                    anomaly.expected_value,
                    anomaly.score,
                    anomaly.severity,
                    anomaly.explanation,
                ),
            )

    def save_security_event(self, event: SecurityEvent) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO security_events
                    (event_id, timestamp, event_type, severity, source_devices, evidence, description)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (event_id) DO NOTHING
                """,
                (
                    event.event_id,
                    event.timestamp,
                    event.event_type,
                    event.severity,
                    event.source_devices,
                    _json(event.evidence),
                    event.description,
                ),
            )

    def save_alert(self, alert: AlertRecord) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO alerts
                    (alert_id, timestamp, source_devices, alert_type, severity, evidence, description)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (alert_id) DO NOTHING
                """,
                (
                    alert.alert_id,
                    alert.timestamp,
                    alert.source_devices,
                    alert.alert_type,
                    alert.severity,
                    _json(alert.evidence),
                    alert.description,
                ),
            )

    def save_performance_metric(
        self, service: str, metric_name: str, metric_value: float, labels: dict[str, object]
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO performance_metrics (service, metric_name, metric_value, labels)
                VALUES (%s, %s, %s, %s::jsonb)
                """,
                (service, metric_name, metric_value, _json(labels)),
            )

    def save_experiment_metadata(
        self,
        experiment_id: UUID,
        name: str,
        started_at: datetime,
        completed_at: datetime,
        configuration: dict[str, object],
        results: object,
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO experiment_metadata
                    (experiment_id, name, started_at, completed_at, configuration, results)
                VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb)
                ON CONFLICT (experiment_id) DO NOTHING
                """,
                (
                    experiment_id,
                    name,
                    started_at,
                    completed_at,
                    _json(configuration),
                    _json(results),
                ),
            )

    def save_observability_snapshot(self, snapshot: ObservabilitySnapshot) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO observability_snapshots (timestamp, service, metrics, labels)
                VALUES (%s, %s, %s::jsonb, %s::jsonb)
                """,
                (
                    snapshot.timestamp,
                    snapshot.service,
                    _json(snapshot.metrics),
                    _json(snapshot.labels),
                ),
            )


def repository_from_env() -> Repository:
    database_url = os.getenv("DATABASE_URL", "")
    return PostgresRepository(database_url) if database_url else InMemoryRepository()


def _json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), default=str)

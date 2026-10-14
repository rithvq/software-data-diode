from __future__ import annotations

from datetime import datetime, timezone
import json
import math
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

    def save_coverage_evidence(self, encoded, record, frames=(), verification_seconds=0): ...

    def save_coverage_outcome(self, outcome): ...


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

    def coverage_ready(self) -> bool:
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute("SELECT 1 FROM coverage_publications LIMIT 0")
            return True
        except Exception:
            return False

    def save_coverage_outcome(self, outcome):
        with self._connect() as connection, connection.cursor() as cursor:
            self._coverage_outcome(cursor, outcome)

    @staticmethod
    def _coverage_outcome(cursor, outcome):
        cursor.execute("""INSERT INTO coverage_outcomes VALUES (%s,%s,%s,%s,%s::jsonb)
            ON CONFLICT (outcome_id) DO NOTHING""", (outcome["outcome_id"], outcome["timestamp_us"],
            outcome["reason_code"], outcome.get("artifact_digest"), _json(outcome.get("details", {}))))

    def save_coverage_evidence(self, encoded, record, frames=(), verification_seconds=0):
        from shared.coverage.capsules import EvidenceError, artifact_digest, parse_artifact
        from shared.coverage.verification import VerificationRecord
        record = VerificationRecord.model_validate(record)
        body = parse_artifact(encoded).body
        fields = ("gateway_id", "signing_key_id", "ledger_epoch", "contract_hash", "device_id", "window_index", "created_at_utc_us")
        if (artifact_digest(encoded) != record.artifact_digest or body.capsule_id != record.scope_id
                or any(getattr(body, field) != getattr(record, field) for field in fields)
                or len(frames) != record.part_count or sum(map(len, frames)) != record.transport_bytes
                or not math.isfinite(verification_seconds) or verification_seconds < 0):
            raise EvidenceError("PERSISTENCE_RECORD_BODY_MISMATCH")
        binding = {"key": record.signing_key_id, "public_key": record.public_key_sha256,
                   "contract": record.contract_hash, "replay_width": record.replay_width_windows}
        with self._connect() as connection, connection.cursor() as cursor:
            # Serialize this provisioned epoch, including identity acceptance and
            # publication, so two concurrent valid forks cannot both stay usable.
            cursor.execute("""INSERT INTO coverage_epochs (gateway_id,ledger_epoch,binding)
                VALUES (%s,%s,%s::jsonb) ON CONFLICT DO NOTHING""",
                (record.gateway_id, record.ledger_epoch, _json(binding)))
            cursor.execute("SELECT binding,retired FROM coverage_epochs WHERE gateway_id=%s AND ledger_epoch=%s FOR UPDATE",
                           (record.gateway_id, record.ledger_epoch))
            approved, retired = cursor.fetchone()
            if retired or approved != binding:
                raise EvidenceError("RETIRED_OR_CHANGED_PERSISTED_TRUST")
            cursor.execute("SELECT 1 FROM coverage_capsules WHERE artifact_digest=%s", (record.artifact_digest,))
            if cursor.fetchone():
                return "DUPLICATE"
            cursor.execute("SELECT quarantined FROM coverage_scopes WHERE scope_id=%s", (record.scope_id,))
            known = cursor.fetchone()
            cursor.execute("SELECT high_window FROM coverage_heads WHERE gateway_id=%s AND ledger_epoch=%s AND device_id=%s",
                           (record.gateway_id, record.ledger_epoch, record.device_id))
            head = cursor.fetchone()
            if known is None and head and record.window_index <= head[0]-record.replay_width_windows:
                raise EvidenceError("STALE_DURABLE_EVIDENCE_WINDOW")
            cursor.execute("""INSERT INTO coverage_scopes (scope_id,gateway_id,ledger_epoch,contract_hash,device_id,window_index)
                VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (record.scope_id, record.gateway_id, record.ledger_epoch, record.contract_hash, record.device_id, record.window_index))
            cursor.execute("SELECT artifact_digest FROM coverage_capsules WHERE scope_id=%s ORDER BY artifact_digest", (record.scope_id,))
            others = [row[0] for row in cursor.fetchall()]
            document = record.model_dump(mode="json")
            if others:
                document.update(status="CONFLICT", continuity_status="CONFLICT")
                document["reason_codes"].append("VALID_SIGNED_SCOPE_FORK")
            cursor.execute("""INSERT INTO coverage_capsules (artifact_digest,scope_id,encoded,body,verification,received_at_us)
                VALUES (%s,%s,%s,%s::jsonb,%s::jsonb,%s)""", (record.artifact_digest, record.scope_id,
                encoded, _json(body.model_dump(mode="json")), _json(document), record.received_at_utc_us))
            for frame in frames:
                part_index = json.loads(frame)["body"]["part_index"]
                cursor.execute("INSERT INTO coverage_parts VALUES (%s,%s,%s)", (record.artifact_digest, part_index, frame))
            for fact in body.per_condition_facts:
                cursor.execute("INSERT INTO coverage_facts VALUES (%s,%s,%s::jsonb)",
                    (record.artifact_digest, fact.condition_id, _json(fact.model_dump(mode="json"))))
            cursor.execute("""INSERT INTO coverage_heads VALUES (%s,%s,%s,%s)
                ON CONFLICT (gateway_id,ledger_epoch,device_id)
                DO UPDATE SET high_window=GREATEST(coverage_heads.high_window,excluded.high_window)""",
                (record.gateway_id, record.ledger_epoch, record.device_id, record.window_index))
            cursor.execute("INSERT INTO coverage_performance (artifact_digest,verification_seconds,transport_bytes) VALUES (%s,%s,%s)",
                           (record.artifact_digest, verification_seconds, record.transport_bytes))
            if others:
                cursor.execute("UPDATE coverage_scopes SET quarantined=TRUE WHERE scope_id=%s", (record.scope_id,))
                cursor.execute("""UPDATE coverage_capsules SET verification=verification ||
                    '{"status":"CONFLICT","continuity_status":"CONFLICT","reason_codes":["VALID_SIGNED_SCOPE_FORK","HIDDEN_INPUTS_NOT_RECOMPUTED"]}'::jsonb
                    WHERE scope_id=%s""", (record.scope_id,))
                for other in others:
                    first, second = sorted((other, record.artifact_digest))
                    cursor.execute("INSERT INTO coverage_conflicts (scope_id,first_digest,second_digest) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING",
                                   (record.scope_id, first, second))
                cursor.execute("""UPDATE coverage_rule_verdicts SET verdict='UNKNOWN', verification_status='CONFLICT',verifier_version='rccd-fog-verifier-v1',
                    reasons='["VALID_SIGNED_SCOPE_FORK"]'::jsonb WHERE gateway_id=%s AND ledger_epoch=%s
                    AND contract_hash=%s AND window_index=%s""",
                    (record.gateway_id, record.ledger_epoch, record.contract_hash, record.window_index))
            self._coverage_outcome(cursor, {"outcome_id": record.artifact_digest, "timestamp_us": record.received_at_utc_us,
                "reason_code": "VALID_SIGNED_SCOPE_FORK" if others else "EVIDENCE_COMMITTED",
                "artifact_digest": record.artifact_digest, "details": document})
            cursor.execute("""INSERT INTO coverage_publications (scope_id) VALUES (%s)
                ON CONFLICT (scope_id) DO UPDATE SET revision=coverage_publications.revision+1""", (record.scope_id,))
            self._coverage_continuity(cursor, record)
            return "CONFLICT" if others else "ACCEPTED"

    @staticmethod
    def _coverage_continuity(cursor, record):
        # Reassess only this window and signed successors directly referencing it.
        # A gap or broken chain does not erase independent predicate facts.
        cursor.execute("""SELECT c.artifact_digest,c.scope_id,c.body,c.verification,s.quarantined
            FROM coverage_capsules c JOIN coverage_scopes s USING(scope_id)
            WHERE (c.scope_id=%s OR c.body->>'previous_capsule_digest' IN
                (SELECT artifact_digest FROM coverage_capsules WHERE scope_id=%s))""", (record.scope_id, record.scope_id))
        for digest, scope, body, verification, quarantined in cursor.fetchall():
            previous = body["previous_capsule_digest"]
            continuity = "CONFLICT" if quarantined else "ROOT" if previous is None else "GAP"
            if previous is not None and not quarantined:
                cursor.execute("""SELECT p.body,s.quarantined FROM coverage_capsules p
                    JOIN coverage_scopes s USING(scope_id) WHERE artifact_digest=%s""", (previous,))
                predecessor = cursor.fetchone()
                if predecessor:
                    parent, conflicted = predecessor
                    same = all(parent[k] == body[k] for k in ("gateway_id", "ledger_epoch", "device_id", "contract_hash"))
                    continuity = "COMPLETE" if same and not conflicted and parent["window_index"] < body["window_index"] else "BROKEN"
            if verification["continuity_status"] != continuity:
                verification["continuity_status"] = continuity
                cursor.execute("UPDATE coverage_capsules SET verification=%s::jsonb WHERE artifact_digest=%s", (_json(verification), digest))
                if scope != record.scope_id:
                    cursor.execute("UPDATE coverage_publications SET revision=revision+1 WHERE scope_id=%s", (scope,))

    def retire_coverage_epoch(self, gateway_id, ledger_epoch):
        """Local operator action; packet declarations cannot invoke this method."""
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute("UPDATE coverage_epochs SET retired=TRUE WHERE gateway_id=%s AND ledger_epoch=%s AND NOT retired RETURNING gateway_id",
                           (gateway_id, ledger_epoch))
            if cursor.fetchone():
                cursor.execute("""UPDATE coverage_rule_verdicts SET verdict='UNKNOWN',verification_status='RETIRED',verifier_version='rccd-fog-verifier-v1',
                    reasons='["RETIRED_EPOCH"]'::jsonb WHERE gateway_id=%s AND ledger_epoch=%s""", (gateway_id, ledger_epoch))
                cursor.execute("""UPDATE coverage_publications p SET revision=revision+1 FROM coverage_scopes s
                    WHERE p.scope_id=s.scope_id AND s.gateway_id=%s AND s.ledger_epoch=%s""", (gateway_id, ledger_epoch))

    def consume_coverage_publication(self, scope_id, revision, handler):
        """Idempotent internal DB consumer. Handler must use this transaction's cursor."""
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT revision,published_revision FROM coverage_publications WHERE scope_id=%s FOR UPDATE", (scope_id,))
            row = cursor.fetchone()
            if row is None or row[0] != revision or row[1] >= revision:
                return False
            handler(cursor, scope_id, revision)
            cursor.execute("UPDATE coverage_publications SET published_revision=%s WHERE scope_id=%s", (revision, scope_id))
            return True

    def coverage_status(self):
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*),COUNT(*) FILTER (WHERE quarantined) FROM coverage_scopes")
            scopes, conflicts = cursor.fetchone()
            cursor.execute("SELECT COUNT(*) FROM coverage_publications WHERE published_revision<revision")
            pending = cursor.fetchone()[0]
            return {"postgres_verified_scopes": scopes, "quarantined_scopes": conflicts,
                    "pending_coverage_publications": pending, "rule_evaluation": "NOT_IMPLEMENTED_N6"}

    def coverage_evidence(self, limit=20):
        from shared.coverage.verification import VerificationRecord
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("evidence query limit must be 1..100")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute("""SELECT c.verification,c.body,s.quarantined,e.retired
                FROM coverage_capsules c JOIN coverage_scopes s USING(scope_id)
                JOIN coverage_epochs e ON (e.gateway_id=s.gateway_id AND e.ledger_epoch=s.ledger_epoch)
                ORDER BY c.received_at_us DESC,c.artifact_digest LIMIT %s""", (limit,))
            return [{"verification": VerificationRecord.model_validate(verification).model_dump(mode="json"),
                     "quarantined": quarantined, "retired_epoch": retired,
                     "facts": body["per_condition_facts"], "accepted_observation_count": body["accepted_observation_count"],
                     "population_complete": body["population_complete"], "previous_capsule_digest": body["previous_capsule_digest"]}
                    for verification, body, quarantined, retired in cursor.fetchall()]

    def process_coverage_rules(self, monitor):
        return monitor.process_one(self)

    def pending_coverage_alert(self):
        from shared.coverage.monitoring import pending_alert
        return pending_alert(self)

    def deliver_coverage_alert(self, delivery):
        from shared.persistence.coverage_alerts import deliver_alert
        return deliver_alert(self, delivery)

    def save_coverage_original_witness(self, framer, digest, record):
        from shared.coverage.monitoring import store_original_witness
        return store_original_witness(self, framer, digest, record)

    def coverage_rules(self, limit=20, history=False):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("rule query limit must be 1..100")
        with self._connect() as connection, connection.cursor() as cursor:
            if history:
                cursor.execute("SELECT record FROM coverage_rule_history ORDER BY recorded_at DESC,decision_id,revision DESC LIMIT %s", (limit,))
                return [row[0] for row in cursor.fetchall()]
            cursor.execute("""SELECT result,revision FROM coverage_rule_verdicts WHERE decision_id IS NOT NULL
                ORDER BY window_index DESC,rule_id LIMIT %s""", (limit,))
            return [{**result,"revision":revision} for result,revision in cursor.fetchall()]

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

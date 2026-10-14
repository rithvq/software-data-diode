from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
from threading import Lock, Thread
from time import monotonic

from psycopg.rows import dict_row

from shared.security.audit import verify_audit_log


PRIORITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SECURITY_REASONS = {
    "INVALID_SIGNATURE": "invalid_signatures",
    "HASH_MISMATCH": "hash_mismatches",
    "REPLAY_DETECTED": "replay_attempts",
    "DUPLICATE_MESSAGE": "duplicates",
    "INVALID_SCHEMA": "malformed_messages",
    "RATE_LIMIT_EXCEEDED": "rate_limit_violations",
}


class MonitoringStore:
    def __init__(
        self,
        database_url: str,
        audit_log_directory: str = "/logs",
        audit_verification_interval_seconds: float = 30.0,
    ) -> None:
        self.database_url = database_url
        self.audit_log_directory = Path(audit_log_directory)
        self.audit_verification_interval_seconds = max(
            float(audit_verification_interval_seconds), 1.0
        )
        self._audit_cache: tuple[float, list[dict[str, object]]] | None = None
        self._audit_refresh_in_progress = False
        self._audit_cache_lock = Lock()
        self.coverage_enabled = os.getenv("COVERAGE_DASHBOARD_ENABLED", "false").lower() == "true"
        self.coverage_contract = None
        if self.coverage_enabled:
            from shared.coverage.contracts import load_contract
            self.coverage_contract = load_contract(os.environ["COVERAGE_CONTRACT_PATH"])

    def coverage(self, operation, *args):
        if not self.coverage_enabled:
            raise LookupError("coverage dashboard disabled")
        from shared.persistence import coverage_queries
        functions = {"overview": coverage_queries.overview, "verdicts": coverage_queries.verdict_page,
                     "decision": coverage_queries.decision_detail, "capsule": coverage_queries.capsule_detail,
                     "witnesses": coverage_queries.witnesses}
        with self._connect() as connection:
            # A coherent page/detail snapshot; no writes even if a query is changed.
            connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            if operation == "overview":
                return functions[operation](connection, *args, self.coverage_contract)
            return functions[operation](connection, *args)

    def _connect(self):
        import psycopg

        return psycopg.connect(self.database_url, row_factory=dict_row, connect_timeout=3,
                               options="-c statement_timeout=5000 -c lock_timeout=3000")

    def healthcheck(self) -> bool:
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                row = cursor.fetchone()
                available = row is not None and next(iter(row.values())) == 1
                if available and self.coverage_enabled:
                    cursor.execute("SELECT decision_id,revision,result FROM coverage_rule_verdicts LIMIT 0")
                    cursor.execute("SELECT 1 FROM coverage_original_witnesses LIMIT 0")
                return available
        except Exception:
            return False

    def snapshot(self) -> dict[str, object]:
        with self._connect() as connection:
            latest = self._latest_observability(connection)
            counts = self._counts(connection)
            latency = self._latency(connection)
            throughput = self._priority_throughput(connection)
            security = self._security(connection)
            anomalies = self._rows(
                connection,
                """
                SELECT timestamp, device_id, detector, metric, observed_value,
                       expected_value, score, severity, explanation, message_id
                FROM anomalies ORDER BY timestamp DESC LIMIT 50
                """,
            )
            alerts = self._rows(
                connection,
                """
                SELECT alert_id, timestamp, source_devices, alert_type, severity,
                       evidence, description, acknowledged_at
                FROM alerts ORDER BY timestamp DESC LIMIT 50
                """,
            )
            active_predicate = ""
            if self.coverage_enabled:
                active_predicate = """AND NOT EXISTS (SELECT 1 FROM coverage_alert_intents i
                    WHERE i.alert_id=alerts.alert_id AND NOT i.active)"""
            active_alerts = self._rows(connection, f"""
                SELECT alert_id, timestamp, source_devices, alert_type, severity,
                       evidence, description, acknowledged_at
                FROM alerts WHERE acknowledged_at IS NULL {active_predicate} ORDER BY timestamp DESC LIMIT 50
            """)
            anomaly_timeline = self._rows(
                connection,
                """
                SELECT date_trunc('minute', timestamp) AS timestamp, severity,
                       COUNT(*) AS count
                FROM anomalies
                WHERE timestamp >= NOW() - INTERVAL '60 minutes'
                GROUP BY 1, severity ORDER BY 1
                """,
            )
            telemetry_trends = self._rows(
                connection,
                """
                SELECT date_trunc('minute', received_at) AS timestamp, telemetry_type,
                       COUNT(*) AS messages,
                       AVG((payload->>'temperature')::double precision) AS temperature
                FROM accepted_telemetry
                WHERE received_at >= NOW() - INTERVAL '60 minutes'
                GROUP BY 1, telemetry_type ORDER BY 1
                """,
            )

        gateway = latest.get("edge-gateway", {})
        diode = latest.get("data-diode", {})
        gateway_metrics = gateway.get("metrics", {})
        diode_metrics = diode.get("metrics", {})
        edge_traffic = gateway_metrics.get("traffic", {})
        diode_traffic = diode_metrics.get("traffic", {})
        queue = diode_metrics.get("queue", {})
        diode_priority_metrics = diode_traffic.get("by_priority", {})
        diode_fresh = self._snapshot_health(diode)["status"] == "HEALTHY"
        average_latency = diode_traffic.get("average_latency") if diode_fresh else None
        p95_latency = diode_traffic.get("latency_p95") if diode_fresh else None
        if average_latency is None:
            average_latency = latency.get("average", 0.0)
        if p95_latency is None:
            p95_latency = latency.get("p95", 0.0)
        generated = sum(
            int(device.get("accepted_observations" if self.coverage_enabled else "received_count", 0))
            for device in gateway_metrics.get("devices", [])
        )
        filtered_bytes = int(edge_traffic.get("bytes_filtered", 0))
        generated_bytes = int(edge_traffic.get("total_bytes_generated", 0))
        filtering_percentage = 100 * filtered_bytes / generated_bytes if generated_bytes else 0.0
        policy = gateway_metrics.get("information_policy")
        if policy:
            policy_generated = int(policy.get("generated_bytes", 0))
            # Pending candidates are not savings: exclude their original bytes.
            reduced = policy_generated - int(policy.get("dispatched_bytes", 0)) - int(policy.get("pending_generated_bytes", 0))
            filtering_percentage = 100 * reduced / policy_generated if policy_generated else 0.0
        devices = [dict(item) for item in gateway_metrics.get("devices", [])]
        gateway_fresh = self._snapshot_health(gateway)["status"] == "HEALTHY"
        for item in devices:
            seen = self._timestamp(item.get("last_seen"))
            if not gateway_fresh or seen is None or not -5 <= (datetime.now(timezone.utc) - seen).total_seconds() <= 30:
                item["health"] = "STALE" if seen else "UNKNOWN"
                item["message_rate_per_minute"] = 0
        active_edges = sum(item.get("health") == "ACTIVE" for item in devices)

        scheduler_rows = []
        diode_by_priority = diode_priority_metrics
        for priority in PRIORITIES:
            values = diode_by_priority.get(priority, {})
            scheduler_rows.append(
                {
                    "priority": priority,
                    "throughput": throughput.get(priority, 0.0),
                    "delivered": values.get("delivered_count", 0),
                    "dropped": values.get("dropped_count", 0),
                    "average_latency": values.get("average_latency"),
                    "average_queue_wait": values.get("average_queue_wait"),
                    "p95_latency": values.get("latency_p95"),
                }
            )

        diode_rejections = diode_metrics.get("security_rejections", {})
        security["rate_limit_violations"] += int(
            diode_rejections.get("RATE_LIMIT_EXCEEDED", 0)
        )
        security["malformed_messages"] += int(
            diode_rejections.get("INVALID_SCHEMA", 0)
        )

        return {
            "observed_at": datetime.now(timezone.utc),
            "overview": {
                "generated_messages": generated,
                "generated_label": "Gateway accepted" if self.coverage_enabled else "Gateway inputs",
                "generated_scope": "Signed sender, ledger epoch" if self.coverage_enabled else "Gateway, current process",
                "counter_comparison": "NOT_COMPARABLE_WITH_HISTORICAL_FOG_TOTAL",
                "accepted_messages": counts["accepted"],
                "rejected_messages": counts["rejected"],
                "messages_per_second": counts["recent_accepted"] / 60.0,
                "bytes_per_second": counts["recent_bytes"] / 60.0,
                "average_latency": average_latency,
                "p95_latency": p95_latency,
                "current_queue_size": queue.get("queue_length", 0),
                "queue_utilization": queue.get("queue_utilization", 0.0),
                "active_edge_nodes": active_edges,
                "critical_alerts": counts["critical_alerts"],
                "filtering_percentage": filtering_percentage,
            },
            "architecture": {
                "edge_devices": devices,
                "gateway": self._snapshot_health(gateway),
                "data_diode": self._snapshot_health(diode),
            },
            "scheduler": {
                "information_policy": gateway_metrics.get("information_policy"),
                "mode": diode_metrics.get("scheduler_mode", "unknown"),
                "congestion_state": queue.get("congestion_state", "UNKNOWN"),
                "queue": queue,
                "by_priority": scheduler_rows,
                "score_distribution": diode_metrics.get("scheduler_scores", {}),
            },
            "security": {
                "counts": security,
                "audit_logs": [] if self.coverage_enabled else self._audit_states(),
            },
            "analytics": {
                "latest_anomalies": anomalies,
                "active_alerts": active_alerts,
                "alerts": alerts,
                "anomaly_timeline": anomaly_timeline,
                "telemetry_trends": telemetry_trends,
            },
        }

    @staticmethod
    def _rows(connection, query: str, params: tuple[object, ...] = ()) -> list[dict[str, object]]:
        with connection.cursor() as cursor:
            cursor.execute(query, params)
            return list(cursor.fetchall())

    def _latest_observability(self, connection) -> dict[str, dict[str, object]]:
        rows = self._rows(
            connection,
            "SELECT service, timestamp, metrics FROM latest_observability_snapshots",
        )
        return {row["service"]: row for row in rows}

    def _counts(self, connection) -> dict[str, int]:
        active_predicate = ""
        if self.coverage_enabled:
            active_predicate = """AND NOT EXISTS (SELECT 1 FROM coverage_alert_intents i
                WHERE i.alert_id=alerts.alert_id AND NOT i.active)"""
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT
                    (SELECT COUNT(*) FROM accepted_telemetry) AS accepted,
                    (SELECT COUNT(*) FROM rejected_messages) AS rejected,
                    (SELECT COUNT(*) FROM accepted_telemetry
                     WHERE received_at >= NOW() - INTERVAL '60 seconds') AS recent_accepted,
                    (SELECT COALESCE(SUM(octet_length(payload::text)), 0)
                     FROM accepted_telemetry
                     WHERE received_at >= NOW() - INTERVAL '60 seconds') AS recent_bytes,
                    (SELECT COUNT(*) FROM alerts
                     WHERE severity = 'CRITICAL' AND acknowledged_at IS NULL {active_predicate}) AS critical_alerts
                """
            )
            return dict(cursor.fetchone())

    def _latency(self, connection) -> dict[str, float]:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT COALESCE(AVG(GREATEST(EXTRACT(EPOCH FROM received_at - created_at), 0)), 0) AS average,
                       COALESCE(percentile_cont(0.95) WITHIN GROUP
                         (ORDER BY GREATEST(EXTRACT(EPOCH FROM received_at - created_at), 0)), 0) AS p95
                FROM accepted_telemetry
                WHERE received_at >= NOW() - INTERVAL '10 minutes'
                """
            )
            return dict(cursor.fetchone())

    def _priority_throughput(self, connection) -> dict[str, float]:
        rows = self._rows(
            connection,
            """
            SELECT priority, COUNT(*) / 60.0 AS throughput
            FROM accepted_telemetry
            WHERE received_at >= NOW() - INTERVAL '60 seconds'
            GROUP BY priority
            """,
        )
        return {row["priority"]: float(row["throughput"]) for row in rows}

    def _security(self, connection) -> dict[str, int]:
        counts = {name: 0 for name in SECURITY_REASONS.values()}
        rows = self._rows(
            connection,
            "SELECT reason, COUNT(*) AS count FROM rejected_messages GROUP BY reason",
        )
        for row in rows:
            key = SECURITY_REASONS.get(row["reason"])
            if key:
                counts[key] = int(row["count"])
        return counts

    def _audit_states(self) -> list[dict[str, object]]:
        now = monotonic()
        with self._audit_cache_lock:
            cache_is_fresh = (
                self._audit_cache is not None
                and now - self._audit_cache[0] < self.audit_verification_interval_seconds
            )
            if cache_is_fresh:
                return [dict(item) for item in self._audit_cache[1]]

            if not self._audit_refresh_in_progress:
                self._audit_refresh_in_progress = True
                Thread(
                    target=self._refresh_audit_states,
                    name="audit-log-verifier",
                    daemon=True,
                ).start()

            if self._audit_cache is not None:
                return [dict(item) for item in self._audit_cache[1]]

        return [
            {
                "service": service,
                "valid": None,
                "detail": "audit verification in progress",
            }
            for service in ("edge-gateway", "data-diode", "fog-receiver")
        ]

    def _refresh_audit_states(self) -> None:
        states = []
        try:
            for service in ("edge-gateway", "data-diode", "fog-receiver"):
                path = self.audit_log_directory / service / f"{service}-audit.jsonl"
                if not path.exists():
                    path = self.audit_log_directory / f"{service}-audit.jsonl"
                valid, detail = verify_audit_log(path)
                states.append({"service": service, "valid": valid, "detail": detail})
        except Exception as exc:
            states = [
                {
                    "service": "audit-verifier",
                    "valid": False,
                    "detail": f"audit verification failed: {exc}",
                }
            ]
        finally:
            with self._audit_cache_lock:
                self._audit_cache = (monotonic(), states)
                self._audit_refresh_in_progress = False

    @staticmethod
    def _timestamp(value):
        try:
            stamp = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
            return stamp.replace(tzinfo=timezone.utc) if stamp is not None and stamp.tzinfo is None else stamp
        except (ValueError, TypeError, AttributeError):
            return None

    @staticmethod
    def _snapshot_health(snapshot: dict[str, object]) -> dict[str, object]:
        timestamp = MonitoringStore._timestamp(snapshot.get("timestamp"))
        if not timestamp:
            return {"status": "UNKNOWN", "last_seen": None}
        age = (datetime.now(timezone.utc) - timestamp).total_seconds()
        return {"status": "HEALTHY" if -5 <= age <= 20 else "STALE", "last_seen": timestamp}


def store_from_env() -> MonitoringStore:
    return MonitoringStore(
        os.environ["DATABASE_URL"],
        os.getenv("AUDIT_LOG_DIRECTORY", "/logs"),
        float(os.getenv("AUDIT_VERIFICATION_INTERVAL_SECONDS", "30")),
    )

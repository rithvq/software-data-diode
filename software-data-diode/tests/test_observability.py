from datetime import datetime, timezone
import json
import logging
from pathlib import Path

from fastapi.testclient import TestClient

from shared.models import ObservabilitySnapshot
from shared.observability.logging import JsonLogFormatter, log_context
from shared.observability.metrics import ServiceMetrics
from shared.persistence import InMemoryRepository
from tests.conftest import load_service_module


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_prometheus_registry_exposes_required_metrics() -> None:
    metrics = ServiceMetrics("test-service")
    metrics.received("edge-device-01", "HIGH")
    metrics.forwarded("edge-device-01", "HIGH")
    metrics.rejected("INVALID_SCHEMA", "edge-device-01")
    metrics.queue_size.labels("test-service").set(3)
    metrics.queue_wait.labels("test-service", "HIGH").observe(0.2)
    metrics.end_to_end_latency.labels("test-service", "HIGH").observe(0.5)
    metrics.signature_failures.labels("test-service").inc()
    metrics.replay_attempts.labels("test-service", "REPLAY_DETECTED").inc()
    metrics.filtered_bytes.labels("test-service", "edge-device-01").inc(42)
    metrics.transmitted_bytes.labels("test-service").inc(100)

    output, _ = metrics.render()
    text = output.decode("utf-8")

    for metric_name in (
        "messages_received_total",
        "messages_forwarded_total",
        "messages_rejected_total",
        "queue_size",
        "queue_wait_seconds",
        "end_to_end_latency_seconds",
        "signature_failures_total",
        "replay_attempts_total",
        "filtered_bytes_total",
        "transmitted_bytes_total",
    ):
        assert metric_name in text


def test_json_logs_include_trace_fields() -> None:
    record = logging.LogRecord(
        "service",
        logging.INFO,
        __file__,
        1,
        "Forwarded message",
        (),
        None,
    )
    for key, value in log_context(
        "message_forwarded",
        message_id="message-1",
        device_id="edge-device-01",
        correlation_id="message-1",
    ).items():
        setattr(record, key, value)

    document = json.loads(JsonLogFormatter("data-diode").format(record))

    assert document["service"] == "data-diode"
    assert document["level"] == "INFO"
    assert document["event"] == "message_forwarded"
    assert document["message_id"] == "message-1"
    assert document["device_id"] == "edge-device-01"
    assert document["correlation_id"] == "message-1"


def test_observability_snapshot_flows_into_fog_persistence() -> None:
    module = load_service_module("fog-receiver")
    module.repository = InMemoryRepository()
    module.OBSERVABILITY_TOKEN = "test-token"
    client = TestClient(module.app)
    snapshot = ObservabilitySnapshot(
        timestamp=datetime.now(timezone.utc),
        service="data-diode",
        metrics={"queue": {"queue_length": 4}},
    )

    response = client.post(
        "/receive-metrics",
        json=snapshot.model_dump(mode="json"),
        headers={"x-observability-token": "test-token"},
    )

    assert response.status_code == 200
    assert module.repository.observability_snapshots == [snapshot]


def test_dashboard_is_fog_only_and_observability_is_split_by_zone() -> None:
    import yaml

    compose = yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]

    assert services["dashboard"]["networks"] == [
        "fog-services-network",
        "fog-host-network",
    ]
    assert services["dashboard"]["environment"]["MONITORING_API_URL"].startswith(
        "http://monitoring-api:"
    )
    assert "edge-network" not in services["prometheus-fog"]["networks"]
    assert "fog-services-network" not in services["prometheus-edge"]["networks"]
    assert set(services["grafana"]["profiles"]) == {"full", "observability"}

    dashboard_source = (PROJECT_ROOT / "dashboard" / "app.py").read_text(encoding="utf-8")
    assert "edge-gateway:8000" not in dashboard_source
    assert "data-diode:8000" not in dashboard_source


def test_phase5_migration_and_grafana_dashboards_are_provisioned() -> None:
    migration = (
        PROJECT_ROOT / "database" / "migrations" / "002_phase5_observability.sql"
    ).read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS observability_snapshots" in migration
    dashboards = list((PROJECT_ROOT / "observability" / "grafana" / "dashboards").glob("*.json"))
    assert {path.stem for path in dashboards} == {
        "system-health",
        "throughput",
        "security",
        "scheduler",
        "workload",
    }
    for path in dashboards:
        assert json.loads(path.read_text(encoding="utf-8"))["panels"]


def test_monitoring_image_includes_audit_verifier_dependency() -> None:
    requirements = (
        PROJECT_ROOT / "monitoring-api" / "requirements.txt"
    ).read_text(encoding="utf-8")
    assert "cryptography" in requirements

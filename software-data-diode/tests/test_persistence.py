from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from shared.models import AlertRecord, AlertSeverity
from shared.persistence import InMemoryRepository
from tests.conftest import load_service_module


def test_event_processor_persists_accepted_telemetry(
    signed_envelope: object, fake_async_client: object
) -> None:
    module = load_service_module("event-processor")
    module.httpx.AsyncClient = fake_async_client
    module.repository = InMemoryRepository()
    module.EVENT_PROCESSOR_ALLOWED_CIDR = "0.0.0.0/0"
    client = TestClient(module.app)

    response = client.post("/events", json=signed_envelope.model_dump(mode="json"))

    assert response.status_code == 200
    assert len(module.repository.telemetry) == 1
    assert module.repository.telemetry[0].envelope.message_id == signed_envelope.message_id


def test_alert_engine_stores_complete_alert() -> None:
    module = load_service_module("alert-engine")
    module.repository = InMemoryRepository()
    client = TestClient(module.app)
    alert = AlertRecord(
        timestamp=datetime.now(timezone.utc),
        source_devices=["edge-device-03", "edge-device-04"],
        alert_type="POTENTIAL_SECURITY_INCIDENT",
        severity=AlertSeverity.CRITICAL,
        evidence=[{"metric": "failed_logins", "value": 8}],
        description="Correlated incident",
    )

    response = client.post("/alerts", json=alert.model_dump(mode="json"))

    assert response.status_code == 200
    assert module.repository.alerts == [alert]


def test_postgres_migration_contains_all_phase4_tables() -> None:
    schema = (
        Path(__file__).resolve().parents[1]
        / "database"
        / "migrations"
        / "001_phase4_schema.sql"
    ).read_text(encoding="utf-8")
    for table in (
        "accepted_telemetry",
        "rejected_messages",
        "security_events",
        "anomalies",
        "alerts",
        "experiment_metadata",
        "performance_metrics",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in schema

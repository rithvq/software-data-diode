import asyncio
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
import importlib
import importlib.util
from pathlib import Path
import sys
from unittest.mock import AsyncMock, Mock

from fastapi.testclient import TestClient
import httpx
import pytest

from shared.models import CongestionState, PriorityLevel, TelemetryType
from shared.traffic import AdaptiveScheduler, BoundedMessageQueue, SchedulerWeights
from shared.traffic.priority import PriorityRuleConfig, classify_priority
from tests.conftest import load_service_module, make_signed_envelope
from tests.test_monitoring_store import load_store_module


@pytest.mark.parametrize("kind", list(TelemetryType))
@pytest.mark.parametrize("priority", list(PriorityLevel))
def test_all_device_types_generate_valid_telemetry(monkeypatch, kind, priority):
    monkeypatch.setenv("DEVICE_TYPE", kind.value)
    module = load_service_module("edge-device")
    message = module.generate_telemetry(priority)
    assert message.telemetry_type == kind
    assert message.timestamp.tzinfo is not None
    assert message.measurements
    if priority == PriorityLevel.CRITICAL:
        assert classify_priority(message, PriorityRuleConfig()) == PriorityLevel.CRITICAL


@pytest.mark.parametrize("variable,value", [("TELEMETRY_INTERVAL_SECONDS", "0"), ("BURST_SIZE", "0"),
                                             ("LOW_TRAFFIC_PERCENT", "nan"), ("TRAFFIC_PROFILE", "typo")])
def test_device_invalid_settings_fail_fast(monkeypatch, variable, value):
    monkeypatch.setenv(variable, value)
    with pytest.raises(ValueError):
        load_service_module("edge-device")


def test_device_handles_transport_failure():
    module = load_service_module("edge-device")
    client = Mock(post=AsyncMock(side_effect=httpx.ConnectError("offline")))
    asyncio.run(module._send_one(client, module.generate_telemetry()))
    client.post.assert_awaited_once()


@pytest.mark.parametrize("profile", ["normal", "burst", "overload", "critical_burst"])
def test_device_traffic_loops_continue_and_cancel(monkeypatch, profile):
    module = load_service_module("edge-device")
    module.TRAFFIC_PROFILE = profile
    module.CRITICAL_BURST_EVERY_N_MESSAGES = 1
    module.BURST_SIZE = 2
    sent = []
    sleeps = []

    async def send(client, message):
        sent.append(message)

    async def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) >= 2:
            raise asyncio.CancelledError()

    monkeypatch.setattr(module, "_send_one", send)
    monkeypatch.setattr(module.asyncio, "sleep", sleep)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(module.send_forever())
    assert len(sent) >= 2


def test_adaptive_transport_preserves_signed_device_order(private_key):
    queue = BoundedMessageQueue(10, preserve_device_order=True)
    messages = [make_signed_envelope(private_key, device_id="a", sequence_number=1),
                make_signed_envelope(private_key, device_id="a", sequence_number=2, priority=PriorityLevel.CRITICAL),
                make_signed_envelope(private_key, device_id="b", sequence_number=1, priority=PriorityLevel.HIGH)]
    for message in messages:
        queue.push(message, 100, now=1)
    scheduler = AdaptiveScheduler(SchedulerWeights())
    popped = [queue.pop_adaptive(scheduler, 1, CongestionState.NORMAL).envelope for _ in messages]
    assert popped[0].device_id == "b"
    assert [item.sequence_number for item in popped if item.device_id == "a"] == [1, 2]


def test_monitoring_store_stale_devices_and_active_alerts(monkeypatch):
    module = load_store_module()
    store = module.MonitoringStore("unused")
    old = datetime.now(timezone.utc) - timedelta(seconds=60)
    monkeypatch.setattr(store, "_connect", lambda: nullcontext(object()))
    monkeypatch.setattr(store, "_latest_observability", lambda _: {"edge-gateway": {
        "timestamp": old, "metrics": {"devices": [{"device_id": "a", "health": "ACTIVE", "last_seen": old.isoformat(), "received_count": 10}]}}})
    monkeypatch.setattr(store, "_counts", lambda _: dict(accepted=9, rejected=1, recent_accepted=3, recent_bytes=100, critical_alerts=1))
    monkeypatch.setattr(store, "_latency", lambda _: {"average": 0.2, "p95": 0.7})
    monkeypatch.setattr(store, "_priority_throughput", lambda _: {})
    monkeypatch.setattr(store, "_security", lambda _: {"rate_limit_violations": 0, "malformed_messages": 0})
    monkeypatch.setattr(store, "_rows", lambda _, query: [{"alert_id": "older-active"}] if "WHERE acknowledged_at IS NULL" in query else [])
    monkeypatch.setattr(store, "_audit_states", lambda: [])
    snapshot = store.snapshot()
    assert snapshot["overview"]["active_edge_nodes"] == 0
    assert snapshot["architecture"]["edge_devices"][0]["health"] == "STALE"
    assert snapshot["overview"]["p95_latency"] == 0.7
    assert snapshot["analytics"]["active_alerts"] == [{"alert_id": "older-active"}]


def monitoring_module(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://unused")
    path = Path(__file__).resolve().parents[1] / "monitoring-api/app"
    spec = importlib.util.spec_from_file_location("audit_monitoring", path / "__init__.py", submodule_search_locations=[str(path)])
    package = importlib.util.module_from_spec(spec)
    sys.modules["audit_monitoring"] = package
    spec.loader.exec_module(package)
    return importlib.import_module("audit_monitoring.main")


def test_monitoring_api_handles_database_outages(monkeypatch):
    module = monitoring_module(monkeypatch)
    monkeypatch.setattr(module, "store", Mock(healthcheck=Mock(return_value=False), snapshot=Mock(side_effect=RuntimeError("offline"))))
    client = TestClient(module.app)
    assert client.get("/health").status_code == 200
    assert client.get("/metrics").status_code == 200
    assert client.get("/ready").status_code == 503
    assert client.get("/api/snapshot").status_code == 503


def test_monitoring_api_reports_actual_fog_health(monkeypatch):
    module = monitoring_module(monkeypatch)
    monkeypatch.setattr(module, "store", Mock(healthcheck=Mock(return_value=True), snapshot=Mock(return_value={"architecture": {}})))
    real_client = httpx.AsyncClient

    def handler(request):
        return httpx.Response(503 if request.url.host == "dashboard" else 200)

    monkeypatch.setattr(module.httpx, "AsyncClient", lambda **kwargs: real_client(transport=httpx.MockTransport(handler)))
    client = TestClient(module.app)
    assert client.get("/ready").status_code == 200
    response = client.get("/api/snapshot")
    assert response.status_code == 200
    services = {item["service"]: item["status"] for item in response.json()["architecture"]["fog_services"]}
    assert services["dashboard"] == "UNAVAILABLE"
    assert services["fog-receiver"] == "HEALTHY"


def test_fog_health_remains_responsive_during_rejection_persistence(monkeypatch, tmp_path):
    from threading import Event
    from shared.security import AuditLog
    module = load_service_module("fog-receiver")
    module.audit_log = AuditLog(tmp_path / "fog.jsonl", "fog-receiver")
    entered, release = Event(), Event()

    def save(*args):
        entered.set()
        release.wait(2)

    module.repository = Mock(save_rejection=save)

    async def verify():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=module.app), base_url="http://test") as client:
            rejection = asyncio.create_task(client.post("/receive", content="{}"))
            try:
                for _ in range(100):
                    if entered.is_set():
                        break
                    await asyncio.sleep(0.005)
                assert entered.is_set() and not rejection.done()
                health = await asyncio.wait_for(client.get("/health"), 0.5)
                assert health.status_code == 200
            finally:
                release.set()
                response = await rejection
            assert response.status_code == 422
    asyncio.run(verify())

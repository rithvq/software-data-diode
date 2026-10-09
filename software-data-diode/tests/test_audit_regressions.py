import asyncio
from datetime import datetime, timedelta, timezone
import json
from unittest.mock import AsyncMock, Mock

from fastapi import HTTPException, FastAPI
from fastapi.testclient import TestClient
import httpx
import pytest

from shared.analytics import AnomalyDetector, DetectionConfig
from shared.http import BodyLimitMiddleware, peer_allowed, strict_json
from shared.models import EdgeTelemetryMessage, FogEvent, PriorityLevel, SecureTelemetryEnvelope
from shared.persistence import InMemoryRepository
from shared.security import AuditLog, TokenBucketRateLimiter, verify_audit_log
from shared.traffic import BoundedMessageQueue, EdgeFilter, EdgeFilterConfig, TrafficMetrics
from tests.conftest import load_service_module, make_signed_envelope
from tests.test_monitoring_store import load_store_module


def transport(monkeypatch, module, statuses):
    calls = []

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, url, json):
            calls.append(json)
            code = statuses.pop(0)
            return httpx.Response(code, request=httpx.Request("POST", url))

    monkeypatch.setattr(module.httpx, "AsyncClient", Client)
    return calls


def test_diode_retries_identical_envelope_after_transient_failure(monkeypatch, tmp_path, signed_envelope):
    module = load_service_module("data-diode")
    module.audit_log = AuditLog(tmp_path / "audit.jsonl", "data-diode")
    module.queue_manager = BoundedMessageQueue(1)
    module.MAX_QUEUE_SIZE = 1
    calls = transport(monkeypatch, module, [503, 200])
    client = TestClient(module.app)
    assert client.post("/ingest", json=signed_envelope.model_dump(mode="json")).status_code == 200
    assert not asyncio.run(module.process_next_message())
    assert module._pending_message is not None
    assert module._observability_snapshot().metrics["queue"]["queue_length"] == 1
    assert client.post("/ingest", json=signed_envelope.model_dump(mode="json")).status_code == 503
    assert asyncio.run(module.process_next_message())
    assert calls[0] == calls[1]
    assert module._pending_message is None
    assert module.traffic_metrics.snapshot()["by_priority"][PriorityLevel.LOW]["dropped_count"] == 1


def test_diode_discards_permanent_rejection_once(monkeypatch, tmp_path, signed_envelope):
    module = load_service_module("data-diode")
    module.audit_log = AuditLog(tmp_path / "audit.jsonl", "data-diode")
    transport(monkeypatch, module, [422])
    TestClient(module.app).post("/ingest", json=signed_envelope.model_dump(mode="json"))
    assert not asyncio.run(module.process_next_message())
    assert module._pending_message is None
    assert module.traffic_metrics.snapshot()["by_priority"][PriorityLevel.LOW]["dropped_count"] == 1


def test_fog_failed_handoff_does_not_consume_replay_state(monkeypatch, tmp_path, private_key):
    module = load_service_module("fog-receiver")
    module.audit_log = AuditLog(tmp_path / "fog.jsonl", "fog-receiver")
    module._public_key = private_key.public_key()
    module.EVENT_PROCESSOR_URL = "http://event-processor:8000/events"
    calls = transport(monkeypatch, module, [503, 200])
    envelope = make_signed_envelope(private_key)
    client = TestClient(module.app)
    data = envelope.model_dump(mode="json")
    assert client.post("/receive", json=data).status_code == 502
    assert client.post("/receive", json=data).status_code == 200
    duplicate = client.post("/receive", json=data)
    assert duplicate.status_code == 409
    assert duplicate.headers["X-Previously-Accepted"] == "true"
    assert len(calls) == 2


def test_analytics_retry_is_idempotent(monkeypatch, private_key):
    module = load_service_module("fog-analytics")
    module.repository = InMemoryRepository()
    from shared.analytics.detection import ThresholdRule
    module.detector = AnomalyDetector(DetectionConfig(thresholds=(ThresholdRule("temperature", maximum=35),)))
    sender = AsyncMock(side_effect=[HTTPException(502), None])
    monkeypatch.setattr(module, "_send_alert", sender)
    event = FogEvent(received_at=datetime.now(timezone.utc), envelope=make_signed_envelope(private_key, temperature=45))
    client = TestClient(module.app)
    body = event.model_dump(mode="json")
    assert client.post("/analyze", json=body).status_code == 502
    assert client.post("/analyze", json=body).status_code == 200
    assert client.post("/analyze", json=body).status_code == 200
    assert len(module.repository.anomalies) == 1
    assert sender.call_args_list[0].args[0].alert_id == sender.call_args_list[1].args[0].alert_id
    assert len(module.detector._history[(event.envelope.device_id, "temperature")]) == 1


@pytest.mark.parametrize("value", ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'])
def test_ambiguous_json_is_rejected(value):
    with pytest.raises(ValueError):
        strict_json(value)


def test_request_boundary_limits_and_strict_parsing():
    app = FastAPI()
    app.add_middleware(BodyLimitMiddleware, paths=["/events"], limit=32)

    @app.post("/events")
    async def receive(body: dict):
        return body

    client = TestClient(app)
    assert client.post("/events", json={"ok": True}).status_code == 200
    assert client.post("/events", content=b"x" * 33).status_code == 413
    assert client.post("/events", content='{"x":NaN}').status_code == 422
    assert client.get("/openapi.json").status_code == 200


def test_peer_allowlist_fails_closed(monkeypatch):
    async def check():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "getaddrinfo", AsyncMock(side_effect=OSError("unavailable")))
        assert not await peer_allowed("172.20.0.2", "edge-gateway")
    asyncio.run(check())


@pytest.mark.parametrize("rate,burst", [(0, 1), (-1, 1), (float("nan"), 1), (float("inf"), 1), (1, 0)])
def test_rate_limiter_invalid_config(rate, burst):
    with pytest.raises(ValueError):
        TokenBucketRateLimiter(rate, burst)


def test_nonfinite_envelope_cost_is_invalid(signed_envelope):
    data = signed_envelope.model_dump()
    data["estimated_transmission_cost"] = float("inf")
    with pytest.raises(ValueError):
        SecureTelemetryEnvelope.model_validate(data)


def test_bounded_latency_history_and_weighted_mean():
    metrics = TrafficMetrics()
    for _ in range(3000):
        metrics.record_delivered(PriorityLevel.LOW, 1, 1, 0)
    metrics.record_delivered(PriorityLevel.CRITICAL, 1, 10, 0)
    snapshot = metrics.snapshot()
    assert snapshot["latency_sample_count"] == 2001
    assert snapshot["average_latency"] == pytest.approx(2010 / 2001)
    assert snapshot["latency_p95"] == 1
    assert snapshot["by_priority"][PriorityLevel.LOW]["delivered_count"] == 3000


@pytest.mark.parametrize("changed", [{"cpu_usage": 50}, {"memory_usage": 70}, {"measurements": {"cpu": 0}}, {"attributes": {"alarm": True}}])
def test_filter_preserves_changed_non_environmental_measurements(changed):
    filter_ = EdgeFilter(EdgeFilterConfig(enable_aggregation=False))
    first = EdgeTelemetryMessage(device_id="test", timestamp=datetime.now(timezone.utc), temperature=25, humidity=50, status="normal")
    assert filter_.evaluate(first, PriorityLevel.LOW).action == "forward"
    assert filter_.evaluate(first.model_copy(update=changed), PriorityLevel.LOW).action == "forward"


def test_audit_scalar_reports_broken_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('[]\n', encoding="utf-8")
    valid, reason = verify_audit_log(path)
    assert not valid
    assert "1" in reason


def test_key_setup_preserves_identity_and_repairs_missing_public_key(tmp_path):
    from scripts.generate_keys import main
    main(tmp_path)
    private = (tmp_path / "edge_private_key.pem").read_bytes()
    public = (tmp_path / "edge_public_key.pem").read_bytes()
    main(tmp_path)
    assert (tmp_path / "edge_private_key.pem").read_bytes() == private
    (tmp_path / "edge_public_key.pem").unlink()
    main(tmp_path)
    assert (tmp_path / "edge_private_key.pem").read_bytes() == private
    assert (tmp_path / "edge_public_key.pem").read_bytes() == public


def test_key_setup_does_not_replace_orphan_public_key(tmp_path):
    from scripts.generate_keys import main
    main(tmp_path)
    (tmp_path / "edge_private_key.pem").chmod(0o600)
    (tmp_path / "edge_private_key.pem").unlink()
    with pytest.raises(ValueError, match="rotation"):
        main(tmp_path)


@pytest.mark.parametrize("key,value", [("MAX_QUEUE_SIZE", "NaN"), ("MAX_MESSAGES_PER_SECOND", "inf"), ("LOW_TRAFFIC_PERCENT", "nan")])
def test_environment_rejects_nonfinite_config(key, value):
    from scripts.validate_config import parse_env, validate_environment, PROJECT_ROOT
    values = parse_env(PROJECT_ROOT / ".env.example")
    values[key] = value
    with pytest.raises(ValueError):
        validate_environment(values, allow_placeholders=True)


def test_statistics_reject_nonfinite_and_use_conservative_t():
    from experiments.analysis.analyze import _number, _t_critical_95
    assert _number("nan") is None
    assert _number("inf") is None
    assert _t_critical_95(21) >= 2.080
    assert _t_critical_95(31) >= 2.040


@pytest.mark.parametrize("config", [{"moving_average_window": 0}, {"zscore_minimum_samples": 50}, {"zscore_threshold": float("nan")}])
def test_detector_rejects_unusable_configuration(config):
    with pytest.raises(ValueError):
        DetectionConfig(thresholds=(), **config)


@pytest.mark.parametrize("seconds,status", [(0, "HEALTHY"), (60, "STALE"), (-60, "STALE")])
def test_snapshot_health_checks_freshness(seconds, status):
    module = load_store_module()
    stamp = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    assert module.MonitoringStore._snapshot_health({"timestamp": stamp.isoformat()})["status"] == status
    assert module.MonitoringStore._snapshot_health({"timestamp": "invalid"})["status"] == "UNKNOWN"


def test_experiment_refuses_to_overwrite_results(tmp_path):
    from experiments.runners.run_phase7 import run_benchmarks
    marker = tmp_path / "raw_trials.csv"
    marker.write_text("original", encoding="utf-8")
    with pytest.raises(ValueError, match="not empty"):
        run_benchmarks({}, tmp_path, config_path=tmp_path / "config.json")
    assert marker.read_text() == "original"


def test_gateway_retries_same_signed_identity(monkeypatch, tmp_path, signed_envelope):
    from shared.edge import DeviceRegistry
    module = load_service_module("edge-gateway")
    module.audit_log = AuditLog(tmp_path / "gateway.jsonl", "edge-gateway")
    module.device_registry = DeviceRegistry()
    module._pending_envelope = signed_envelope
    calls = transport(monkeypatch, module, [503, 200])
    assert not asyncio.run(module.process_information_message())
    assert module._pending_envelope == signed_envelope
    assert asyncio.run(module.process_information_message())
    assert module._pending_envelope is None
    assert calls[0] == calls[1]


def test_diode_worker_survives_unexpected_iteration_error(monkeypatch):
    module = load_service_module("data-diode")
    process = AsyncMock(side_effect=[RuntimeError("temporary failure"), False])
    sleeper = AsyncMock(side_effect=[None, asyncio.CancelledError()])
    monkeypatch.setattr(module, "process_next_message", process)
    monkeypatch.setattr(module, "egress_rate_limiter", Mock(allow=lambda: True))
    monkeypatch.setattr(module.asyncio, "sleep", sleeper)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(module._egress_loop())
    assert process.await_count == 2


def test_diode_readiness_detects_stopped_worker():
    module = load_service_module("data-diode")
    module._egress_task = Mock(done=lambda: True)
    assert TestClient(module.app).get("/ready").status_code == 503


def test_runtime_state_migration_preserves_files_and_never_rolls_back(tmp_path):
    from shared.security.runtime_state import initialize
    source = tmp_path / "edge-gateway-sequences.json"
    source.write_text('{"a":12}', encoding="utf-8")
    initialize(tmp_path)
    target = tmp_path / "edge-gateway/edge-gateway-sequences.json"
    assert target.read_bytes() == source.read_bytes()
    target.write_text('{"a":15}', encoding="utf-8")
    initialize(tmp_path)
    assert target.read_text() == '{"a":15}'
    assert source.exists()


def test_compose_service_writers_have_disjoint_volume_subpaths():
    import yaml
    from tests.conftest import PROJECT_ROOT
    services = yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text())["services"]
    for name in ("edge-gateway", "data-diode", "fog-receiver"):
        mount = next(item for item in services[name]["volumes"] if isinstance(item, dict) and item["target"] == "/logs")
        assert mount["volume"]["subpath"] == name
        assert services[name]["depends_on"]["runtime-state-init"]["condition"] == "service_completed_successfully"
    assert services["runtime-state-init"]["network_mode"] == "none"

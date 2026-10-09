from datetime import datetime, timedelta, timezone
import asyncio
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from shared.models import EdgeTelemetryMessage, PriorityLevel, SecureTelemetryEnvelope
from shared.security import ReplayDetector, verify_envelope_signature
from shared.security.audit import AuditLog, verify_audit_log
from shared.traffic.information import (
    InformationEngine, InformationPolicyConfig, LocalStateEstimator,
)
from tests.conftest import load_service_module


EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)


def message(t=0, device="edge-01", **values):
    return EdgeTelemetryMessage(device_id=device, timestamp=EPOCH + timedelta(seconds=t),
                                temperature=values.pop("temperature", 25), humidity=50,
                                status=values.pop("status", "normal"), **values)


def submit(engine, t, identifier, **values):
    priority = values.pop("priority", PriorityLevel.LOW)
    return engine.submit(message(t, **values), priority, t, EPOCH + timedelta(seconds=t), identifier)


@pytest.mark.parametrize("kind,field,base,spike", [
    ("environmental", "temperature", 25, 83), ("system", "cpu_usage", 30, 95),
    ("network", "packets_per_second", 1000, 10000),
    ("security", "failed_logins", 0, 10), ("industrial", "vibration_mm_s", 1, 10),
])
def test_type_specific_novelty_uses_last_dispatched_state(kind, field, base, spike):
    engine = InformationEngine(InformationPolicyConfig())
    def values(value):
        return {"telemetry_type": kind, **({field: value} if field in {"temperature", "cpu_usage"} else {"measurements": {field: value}})}
    submit(engine, 0, "initial", **values(base))
    engine.pop(0)
    assert engine.novelty(message(1, **values(base))) == 0
    assert engine.novelty(message(1, **values(spike))) == 1
    submit(engine, 1, "queued-spike", **values(spike))
    assert engine.novelty(message(2, **values(base))) == 0


def test_predictor_anticipates_overflow_without_receiver_input():
    config = InformationPolicyConfig(max_queue_size=20, messages_per_second=1)
    local = LocalStateEstimator(config)
    for _ in range(10):
        local.record(0, "arrival", 1000, "LOW")
    snapshot = local.snapshot(1, 2)
    assert snapshot["queue_utilization"] == 0.1
    assert snapshot["congestion_state"] == "CRITICAL"
    assert snapshot["predicted_queue_length"] > 20


def test_all_terms_and_weights_are_explained_and_config_validated():
    engine = InformationEngine(InformationPolicyConfig())
    decision = submit(engine, 0, "one")
    assert len(decision["components"]) == 8
    assert decision["utility_score"] == pytest.approx(sum(decision["weighted_components"].values()))
    with pytest.raises(ValidationError):
        InformationPolicyConfig(link_bytes_per_second=0)
    with pytest.raises(ValidationError):
        InformationPolicyConfig(weights={"novelty": float("nan")})


def test_pending_queue_bytes_are_not_counted_as_savings():
    engine = InformationEngine(InformationPolicyConfig(reduction_enabled=False))
    submit(engine, 0, "one")
    submit(engine, 0, "two")
    before = engine.snapshot(0)
    assert before["generated_bytes"] == before["pending_generated_bytes"]
    engine.pop(0)
    after = engine.snapshot(0)
    assert after["generated_bytes"] == after["dispatched_bytes"] + after["pending_generated_bytes"]


def test_mixed_timezone_input_and_older_samples_do_not_invert_aggregation_windows():
    engine = congested_engine()
    older = message(2).model_copy(update={"timestamp": (EPOCH + timedelta(seconds=2)).replace(tzinfo=None)})
    engine.submit(older, PriorityLevel.LOW, 2, EPOCH + timedelta(seconds=2), "old")
    submit(engine, 3, "new")
    aggregate = next(item for item in engine.queue if item.message.aggregation is not None)
    assert aggregate.message.aggregation.window_start <= aggregate.message.aggregation.window_end
    decision = engine.submit(message(1), PriorityLevel.LOW, 4, EPOCH + timedelta(seconds=4), "late")
    assert decision["action"] != "AGGREGATE"


def congested_engine(**overrides):
    config = InformationPolicyConfig(**{
        "prediction_enabled": False, "max_queue_size": 10,
        "elevated_threshold": .05, "congested_threshold": .1, "critical_threshold": .9,
        **overrides,
    })
    engine = InformationEngine(config)
    submit(engine, 0, "baseline")
    engine.pop(0)
    submit(engine, 1, "event", device="security", event_type="INTRUSION_DETECTED")
    return engine


def test_aggregation_contains_signed_summary_provenance_and_extrema():
    engine = congested_engine()
    assert submit(engine, 2, "a", temperature=25.1)["action"] == "DELAY"
    decision = submit(engine, 3, "b", temperature=25.2)
    assert decision["action"] == "AGGREGATE"
    aggregated = next(item for item in engine.queue if item.message_id == "b")
    assert aggregated.message.aggregation.sample_count == 2
    assert aggregated.message.temperature == pytest.approx(25.15)
    assert aggregated.message.aggregation.minimum_temperature == 25.1
    assert aggregated.message.aggregation.maximum_temperature == 25.2
    assert aggregated.message.aggregation.source_message_ids == ["a", "b"]
    assert aggregated.enqueued_at == 2


def test_supersession_sampling_expiry_and_event_preservation():
    engine = congested_engine()
    submit(engine, 2, "old", temperature=26)
    submit(engine, 3, "new", temperature=27)
    assert any(d["action"] == "SUPERSEDE" and d["message_id"] == "old" for d in engine.decisions)
    assert any(item.message_id == "event" for item in engine.queue)
    critical = congested_engine(critical_threshold=.2)
    submit(critical, 2, "routine")
    submit(critical, 3, "kept")
    assert submit(critical, 4, "sampled")["action"] == "SAMPLE"
    expiry = InformationEngine(InformationPolicyConfig(freshness_seconds=2))
    submit(expiry, 0, "baseline")
    expiry.pop(0)
    submit(expiry, 1, "stale")
    assert expiry.pop(4) is None
    assert expiry.decisions[-1]["action"] == "DROP"


def test_old_low_priority_event_is_served_during_critical_storm():
    engine = InformationEngine(InformationPolicyConfig(starvation_seconds=2, reduction_enabled=False))
    submit(engine, 0, "low")
    submit(engine, 1, "critical", priority=PriorityLevel.CRITICAL, event_type="intrusion")
    assert engine.pop(2).message_id == "low"


def test_queue_and_histories_stay_bounded_under_flood():
    engine = InformationEngine(InformationPolicyConfig(max_queue_size=8, max_streams=4))
    for index in range(1000):
        submit(engine, index / 100, str(index), device=f"device-{index % 5}")
        if index % 50 == 0:
            engine.pop(index / 100)
        assert len(engine.queue) <= 8
    assert len(engine.decisions) <= 100
    assert len(engine.last_dispatched) <= 4
    assert len(engine.local.buckets) <= 12


def test_link_capacity_and_density_are_explicit_local_controls():
    slow = InformationEngine(InformationPolicyConfig(link_bytes_per_second=100))
    fast = InformationEngine(InformationPolicyConfig(link_bytes_per_second=10000))
    for engine in (slow, fast):
        submit(engine, 0, "one")
        submit(engine, 0, "two")
        engine.pop(0)
    assert slow.next_dispatch_at > fast.next_dispatch_at
    assert slow.pop(1) is None
    assert fast.pop(1) is not None


def test_policy_audit_details_are_hash_chained(tmp_path):
    path = tmp_path / "decisions.jsonl"
    audit = AuditLog(path, "gateway")
    for i in range(5):
        audit.append("POLICY", "SEND", details={"score": i, "padding": "x" * 9000})
    assert verify_audit_log(path)[0]
    records = path.read_text().splitlines()
    tampered = json.loads(records[1])
    tampered["details"]["score"] = 999
    records[1] = json.dumps(tampered)
    path.write_text("\n".join(records) + "\n")
    valid, reason = verify_audit_log(path)
    assert not valid and "line 2" in reason


def test_live_gateway_signs_in_dispatch_order_and_preserves_source_time(monkeypatch, tmp_path, private_key, fake_async_client):
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "gateway.jsonl"))
    monkeypatch.setenv("INFORMATION_POLICY_ENABLED", "true")
    module = load_service_module("edge-gateway")
    module._private_key = private_key
    module.httpx.AsyncClient = fake_async_client
    client = TestClient(module.app)
    now = datetime.now(timezone.utc)
    low = message().model_copy(update={"timestamp": now - timedelta(seconds=1)})
    critical = low.model_copy(update={"timestamp": now, "event_type": "intrusion"})
    for item in (low, critical):
        assert client.post("/telemetry", json=item.model_dump(mode="json")).json()["status"] == "queued"
    asyncio.run(module.process_information_message())
    module.information_engine.next_dispatch_at = 0
    asyncio.run(module.process_information_message())
    envelopes = [SecureTelemetryEnvelope.model_validate(row["json"]) for row in fake_async_client.posted_requests]
    assert [e.priority for e in envelopes] == [PriorityLevel.CRITICAL, PriorityLevel.LOW]
    assert envelopes[0].sequence_number < envelopes[1].sequence_number
    detector = ReplayDetector(600, 300)
    for envelope in envelopes:
        assert verify_envelope_signature(envelope, private_key.public_key())
        assert detector.check_and_record(envelope) is None
        assert "source_timestamp" in envelope.payload.attributes
    assert all(row["url"] == module.DATA_DIODE_URL for row in fake_async_client.posted_requests)


def test_diagnostics_do_not_change_policy_decisions():
    engines = [InformationEngine(InformationPolicyConfig()) for _ in range(2)]
    for i in range(30):
        for engine in engines:
            submit(engine, i * .1, str(i), device=f"device-{i % 5}")
        engines[1].snapshot(i * .1 + .01)
        engines[1].snapshot(i * .1 + .02)
    assert list(engines[0].decisions) == list(engines[1].decisions)


def test_oversize_and_invalid_capacity_are_explicitly_rejected():
    engine = InformationEngine(InformationPolicyConfig(max_message_bytes=1000))
    decision = submit(engine, 0, "oversize", attributes={"text": "x" * 2000})
    assert decision["action"] == "DROP"
    assert "size bound" in decision["reason"]
    assert not engine.queue
    with pytest.raises(ValidationError):
        engine.configure_local_link(-1)


def test_signed_aggregate_is_verified_by_fog_and_tampering_rejected(monkeypatch, tmp_path, private_key):
    from uuid import uuid4
    engine = congested_engine()
    submit(engine, 2, str(uuid4()), temperature=25.1)
    submit(engine, 3, str(uuid4()), temperature=25.2)
    candidate = next(item for item in engine.queue if item.message.aggregation is not None)
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "gateway.jsonl"))
    gateway = load_service_module("edge-gateway")
    gateway._private_key = private_key
    envelope = gateway._build_signed_envelope(candidate.message, candidate.priority, candidate.size_bytes, message_id=candidate.message_id, include_source_timestamp=True)
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "fog.jsonl"))
    receiver = load_service_module("fog-receiver")
    receiver._public_key = private_key.public_key()
    receiver.EVENT_PROCESSOR_URL = ""
    client = TestClient(receiver.app)
    document = envelope.model_dump(mode="json")
    assert client.post("/receive", json=document).status_code == 200
    document["payload"]["aggregation"]["sample_count"] += 1
    response = client.post("/receive", json=document)
    assert response.status_code == 400
    assert response.json()["detail"]["reason"] == "HASH_MISMATCH"


def test_research_mode_keeps_transport_fifo(monkeypatch, tmp_path):
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "diode.jsonl"))
    monkeypatch.setenv("INFORMATION_POLICY_ENABLED", "true")
    monkeypatch.setenv("SCHEDULER_MODE", "adaptive")
    module = load_service_module("data-diode")
    assert module.SCHEDULER_MODE == "fifo"


def test_experiment_trace_and_decisions_reproduce_with_capacity_change():
    from experiments.runners.information_benchmark import generate_trace, simulate
    workload = {"id": "step", "load": 1.5, "capacity_multiplier": .25}
    trace = generate_trace(workload, duration=10, capacity=4, seed=123)
    assert trace == generate_trace(workload, duration=10, capacity=4, seed=123)
    first, second = [], []
    config = InformationPolicyConfig(max_queue_size=10, link_bytes_per_second=4096)
    left = simulate(trace, config, workload, 10, first.append)
    right = simulate(trace, config, workload, 10, second.append)
    assert left == right
    assert first == second
    assert left[0]["represented_samples"] <= len(trace)
    assert all(row["queue_size"] <= 10 for row in left[1])


def test_report_does_not_claim_confidence_from_one_priority_observation():
    from experiments.analysis.information_report import summary
    assert summary([1.0])["ci95_low"] is None
    repeated = summary([1, 2, 3, 4, 5])
    assert repeated["n"] == 5
    assert repeated["mean"] == 3
    assert repeated["ci95_low"] < 3 < repeated["ci95_high"]


def test_fifo_baseline_does_not_evict_already_queued_messages():
    engine = InformationEngine(InformationPolicyConfig(strategy="fifo", reduction_enabled=False, max_queue_size=1))
    submit(engine, 0, "first")
    decision = submit(engine, 1, "critical", event_type="intrusion", priority=PriorityLevel.CRITICAL)
    assert decision["action"] == "DROP"
    assert engine.pop(1).message_id == "first"


def test_monotonic_envelope_times_with_coarse_clock(monkeypatch, tmp_path, private_key):
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "gateway.jsonl"))
    module = load_service_module("edge-gateway")
    module._private_key = private_key
    class CoarseClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return EPOCH
    monkeypatch.setattr(module, "datetime", CoarseClock)
    first = module._build_signed_envelope(message(), PriorityLevel.LOW, 1000)
    second = module._build_signed_envelope(message(), PriorityLevel.LOW, 1000)
    assert second.created_at > first.created_at


def test_critical_candidate_progresses_when_novel_low_states_fill_queue():
    engine = InformationEngine(InformationPolicyConfig(max_queue_size=2))
    submit(engine, 0, "first", device="device-1")
    submit(engine, 0, "second", device="device-2")
    decision = submit(engine, .1, "critical", event_type="intrusion", priority=PriorityLevel.CRITICAL)
    assert decision["action"] == "DELAY"
    assert len(engine.queue) == 2
    assert engine.pop(.1).message_id == "critical"


def test_transport_failure_does_not_change_policy_state(monkeypatch, tmp_path, private_key):
    from types import SimpleNamespace
    from uuid import NAMESPACE_URL, uuid5
    import httpx
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "gateway.jsonl"))
    module = load_service_module("edge-gateway")
    module._private_key = private_key
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: 1.0))
    observed = []
    for failed in (False, True):
        class LocalTransport:
            def __init__(self, **kwargs):
                pass
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            async def post(self, url, **kwargs):
                assert url == module.DATA_DIODE_URL
                if failed:
                    raise httpx.ReadTimeout("simulated local handoff failure")
                return SimpleNamespace(raise_for_status=lambda: None)
        monkeypatch.setattr(module.httpx, "AsyncClient", LocalTransport)
        engine = InformationEngine(InformationPolicyConfig())
        for index in range(3):
            submit(engine, 0, str(uuid5(NAMESPACE_URL, str(index))), device=f"device-{index}")
        module.information_engine = engine
        asyncio.run(module.process_information_message())
        observed.append((list(engine.decisions), engine.snapshot(1), [item.message_id for item in engine.queue]))
    assert observed[0] == observed[1]

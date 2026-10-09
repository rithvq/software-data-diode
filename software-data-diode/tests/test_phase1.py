import asyncio
from datetime import datetime
import json
from pathlib import Path
import random

import httpx
import pytest
import yaml

from phase1.app import create_app
from phase1.components import default_components
from phase1.device import generate
from phase1.interfaces import PolicyDecision
from phase1.models import Telemetry
from phase1.pipeline import IdentityConflictError, Pipeline, PolicyRejectedError, QueueFullError


REAL_ASYNC_CLIENT = httpx.AsyncClient


async def local_peer(_):
    return {"127.0.0.1"}


def message(sequence=1):
    return generate(sequence, random.Random(sequence))


def client(app, address="127.0.0.1"):
    return REAL_ASYNC_CLIENT(
        transport=httpx.ASGITransport(app=app, client=(address, 12345)),
        base_url="http://test", trust_env=False,
    )


def test_phase1_forward_pipeline_and_instrumentation(tmp_path):
    async def run():
        apps = [create_app(role, resolver=local_peer, log_directory=tmp_path)
                for role in ("edge-gateway", "unidirectional-gateway", "fog-receiver")]
        payload = message().model_dump(mode="json")
        async with client(apps[0]) as edge, client(apps[1]) as diode, client(apps[2]) as fog:
            assert (await edge.post("/telemetry", json=payload)).status_code == 202

            async def to_diode(body):
                (await diode.post("/ingest", content=body)).raise_for_status()

            async def to_fog(body):
                (await fog.post("/receive", content=body)).raise_for_status()

            assert await apps[0].state.pipeline.transmit_next(to_diode)
            assert await apps[1].state.pipeline.transmit_next(to_fog)
            assert (await fog.get("/messages")).json() == [payload]
        for app in apps[:2]:
            record = app.state.pipeline.records[-1]
            assert record["event"] == "transmitted"
            assert record["message_id"] == payload["message_id"]
            assert record["queue_length"] == 0
            assert record["message_size_bytes"] == len(Pipeline.body(Telemetry.model_validate(payload)))
            stamps = [datetime.fromisoformat(record[name]) for name in
                      ("arrival_timestamp", "queue_entry_timestamp", "transmission_timestamp")]
            assert stamps == sorted(stamps)
        assert len(list(tmp_path.glob("*.jsonl"))) == 3
    asyncio.run(run())


def test_phase1_retry_after_lost_ack_is_idempotent_and_bounded():
    async def run():
        pipeline = Pipeline("test", capacity=1)
        first = message()
        pipeline.admit(first)
        fog = create_app("fog-receiver", resolver=local_peer)
        async with client(fog) as receiver:
            attempts = 0

            async def sender(body):
                nonlocal attempts
                (await receiver.post("/receive", content=body)).raise_for_status()
                attempts += 1
                if attempts == 1:
                    raise ConnectionError("acknowledgement lost")

            with pytest.raises(ConnectionError):
                await pipeline.transmit_next(sender)
            assert pipeline.queue_length == 1
            with pytest.raises(QueueFullError):
                pipeline.admit(message(2))
            assert not pipeline.admit(first)
            assert await pipeline.transmit_next(sender)
            assert len((await receiver.get("/messages")).json()) == 1
            assert pipeline.queue_length == 0
            assert pipeline.records[-1]["attempt"] == 2
            assert pipeline.failures == 1
            assert not pipeline.admit(first)
    asyncio.run(run())


def test_phase1_scheduler_is_replaceable():
    class StackScheduler:
        def __init__(self):
            self.items = []

        def enqueue(self, item):
            self.items.append(item)

        def select(self, state):
            return self.items.pop() if self.items else None

        def __len__(self):
            return len(self.items)

    async def run(scheduler, expected):
        components = default_components()
        if scheduler is not None:
            components.scheduler = scheduler
        pipeline = Pipeline("test", components=components)
        for sequence in range(1, 4):
            pipeline.admit(message(sequence))
        sent = []

        async def sender(body):
            sent.append(json.loads(body)["sequence_number"])

        while await pipeline.transmit_next(sender):
            pass
        assert sent == expected

    asyncio.run(run(None, [1, 2, 3]))
    asyncio.run(run(StackScheduler(), [3, 2, 1]))


def test_phase1_interfaces_participate_in_admission():
    calls = []

    class Analyzer:
        def analyze(self, message):
            calls.append("analyzer")
            return {"utility": 1.0}

    class Predictor:
        def predict(self, state):
            calls.append("predictor")
            assert state.arrivals == 1
            return "TEST"

    class Policy:
        def decide(self, message, information, state, prediction):
            calls.append("policy")
            assert information == {"utility": 1.0} and prediction == "TEST"
            return PolicyDecision(False, "test rejection")

    components = default_components()
    components.analyzer, components.predictor, components.policy = Analyzer(), Predictor(), Policy()
    pipeline = Pipeline("test", components=components)
    with pytest.raises(PolicyRejectedError):
        pipeline.admit(message())
    assert pipeline.queue_length == 0
    assert calls == ["analyzer", "predictor", "policy"]


@pytest.mark.parametrize("role,path", [
    ("edge-gateway", "/telemetry"), ("unidirectional-gateway", "/ingest"),
    ("fog-receiver", "/receive"),
])
def test_phase1_ingress_validation(role, path):
    async def run():
        app = create_app(role, resolver=local_peer, capacity=1, max_body_bytes=1024)
        async with client(app) as api:
            assert (await api.post(path, json={})).status_code == 422
            invalid = message().model_dump(mode="json")
            invalid["timestamp"] = "2026-01-01T00:00:00"
            assert (await api.post(path, json=invalid)).status_code == 422
            assert (await api.post(path, content=b"x" * 1025)).status_code == 413
            valid = message().model_dump(mode="json")
            assert (await api.post(path, json=valid)).status_code == 202
            assert (await api.post(path, json=valid)).json()["status"] == "duplicate"
            valid["sequence_number"] = 2
            assert (await api.post(path, json=valid)).status_code == 409
            if role != "fog-receiver":
                response = await api.post(path, json=message(2).model_dump(mode="json"))
                assert response.status_code == 503
                assert response.headers["Retry-After"] == "1"
        async with client(app, "192.0.2.1") as forbidden:
            response = await forbidden.post(path, json=valid, headers={"X-Forwarded-For": "127.0.0.1"})
            assert response.status_code == 403
            assert (await forbidden.get("/messages")).status_code == 403
    asyncio.run(run())


def test_phase1_concurrent_arrivals_remain_traceable():
    async def run():
        app = create_app("edge-gateway", resolver=local_peer, capacity=100)
        payloads = [message(seq).model_dump(mode="json") for seq in range(1, 101)]
        async with client(app) as api:
            responses = await asyncio.gather(*(api.post("/telemetry", json=p) for p in payloads))
        assert all(r.status_code == 202 for r in responses)
        pipeline = app.state.pipeline
        assert pipeline.queue_length == 100
        received = []

        async def sender(body):
            received.append(json.loads(body))

        while await pipeline.transmit_next(sender):
            pass
        assert {p["message_id"] for p in received} == {p["message_id"] for p in payloads}
        assert len(received) == 100
        assert {p["sequence_number"] for p in received} == set(range(1, 101))
        assert pipeline.queue_length == 0
    asyncio.run(run())


def test_phase1_background_worker_wakes_and_retries():
    async def run():
        pipeline = Pipeline("test")
        delivered = asyncio.Event()
        attempts = 0

        async def sender(body):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise ConnectionError("temporary failure")
            delivered.set()

        task = asyncio.create_task(pipeline.run(sender, retry_seconds=.001))
        await asyncio.sleep(0)
        pipeline.admit(message())
        await asyncio.wait_for(delivered.wait(), 2)
        assert pipeline.transmitted == 1 and attempts == 2
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(run())


def test_phase1_identity_conflict_and_bounded_history():
    async def run():
        pipeline = Pipeline("test", history_size=2)
        first = message()
        pipeline.admit(first)
        with pytest.raises(IdentityConflictError):
            pipeline.admit(first.model_copy(update={"sequence_number": 2}))

        async def sender(body):
            pass

        for sequence in range(2, 6):
            await pipeline.transmit_next(sender)
            pipeline.admit(message(sequence))
        await pipeline.transmit_next(sender)
        assert len(pipeline.completed_ids) == len(pipeline.records) == 2
        assert not pipeline.accepted_ids
    asyncio.run(run())


def test_phase1_compose_network_contract():
    root = Path(__file__).resolve().parents[1]
    config = yaml.safe_load((root / "docker-compose.phase1.yml").read_text())
    expected = {
        "edge-device": {"edge-network"},
        "edge-gateway": {"edge-network", "gateway-network"},
        "unidirectional-gateway": {"gateway-network", "fog-network"},
        "fog-receiver": {"fog-network"},
    }
    assert set(config["services"]) == set(expected)
    assert set(config["networks"]) == {"edge-network", "gateway-network", "fog-network"}
    assert all(n["internal"] for n in config["networks"].values())
    for service, networks in expected.items():
        spec = config["services"][service]
        assert set(spec["networks"]) == networks
        assert "ports" not in spec and "network_mode" not in spec
        assert spec["cap_drop"] == ["ALL"]

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import random
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx
import pytest
from pydantic import ValidationError
import yaml

from phase2.app import create_app
from phase2.device import DeviceState, generate_source
from phase2.keys import initialize
from phase2.models import SecureEnvelope, SourceMessage
from phase2.pipeline import PermanentDeliveryError
from phase2.security import Rejected, canonical, freshness, parse_json, sign, verify
from shared.security.audit import verify_audit_log


REAL_CLIENT = httpx.AsyncClient


async def peer(_):
    return {"127.0.0.1"}


def source(sequence=1, **updates):
    return generate_source(sequence, random.Random(101)).model_copy(update=updates)


def client(app, address="127.0.0.1"):
    return REAL_CLIENT(transport=httpx.ASGITransport(app=app, client=(address, 1234)),
                       base_url="http://local", trust_env=False)


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def factory(tmp_path, key):
    apps = []

    def build(role="fog-receiver", **options):
        path = options.pop("path", tmp_path / f"{role}-{len(apps)}")
        app = create_app(role, path, key.public_key(), resolver=peer,
                         private_key=key if role == "edge-gateway" else None, **options)
        apps.append(app)
        return app

    yield build
    for app in apps:
        app.state.security.close()


def test_phase2_canonical_signing_and_all_metadata_protected(key):
    envelope = sign(source(), key)
    document = envelope.model_dump(mode="json")
    reordered = dict(reversed(list(document.items())))
    assert canonical(document) == canonical(reordered)
    verify(SecureEnvelope.model_validate(reordered), key.public_key())
    for field, value in {"event_class": "OTHER", "supersession_key": "different",
                         "aggregation_allowed": False, "sampling_allowed": False,
                         "message_id": str(uuid4()), "sequence_number": 99}.items():
        modified = SecureEnvelope.model_validate({**document, field: value})
        with pytest.raises(Rejected, match="INVALID_SIGNATURE"):
            verify(modified, key.public_key())
    with pytest.raises(Rejected, match="INVALID_SIGNATURE"):
        verify(envelope, Ed25519PrivateKey.generate().public_key())


@pytest.mark.parametrize("body", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'])
def test_phase2_rejects_ambiguous_json(body):
    with pytest.raises(ValueError):
        parse_json(body)


@pytest.mark.parametrize("updates", [
    {"message_type": "security"}, {"priority": "CRITICAL", "base_priority": "CRITICAL"},
    {"must_preserve": True}, {"sampling_allowed": "false"}, {"sequence_number": True},
    {"sequence_number": 9223372036854775808},
    {"created_at": "2026-01-01T00:00:00"},
])
def test_phase2_rejects_unsafe_semantics(updates):
    with pytest.raises(ValidationError):
        SourceMessage.model_validate({**source().model_dump(mode="json"), **updates})


def test_phase2_required_event_semantics(key):
    message = source(message_type="security", event_class="SECURITY_INCIDENT", priority="CRITICAL",
                     base_priority="CRITICAL", must_preserve=True, aggregation_allowed=False,
                     sampling_allowed=False, supersession_key=None)
    envelope = sign(message, key)
    verify(envelope, key.public_key())
    assert envelope.must_preserve


def test_phase2_secure_pipeline(factory, key):
    async def run():
        edge, diode, fog = [factory(role) for role in
                            ("edge-gateway", "unidirectional-gateway", "fog-receiver")]
        original = source()
        async with client(edge) as e, client(diode) as d, client(fog) as f:
            assert (await e.post("/telemetry", json=original.model_dump(mode="json"))).status_code == 202

            async def to_diode(body):
                (await d.post("/ingest", content=body)).raise_for_status()

            async def to_fog(body):
                (await f.post("/receive", content=body)).raise_for_status()

            await edge.state.pipeline.transmit_next(to_diode)
            await diode.state.pipeline.transmit_next(to_fog)
            received = (await f.get("/messages")).json()
            assert len(received) == 1
            envelope = SecureEnvelope.model_validate(received[0])
            verify(envelope, key.public_key())
            assert envelope.message_id == original.message_id and envelope.payload == original.payload
            assert envelope.created_at == original.created_at
        for app in [edge, diode, fog]:
            assert verify_audit_log(app.state.audit.path)[0]
            assert app.state.security.counters()["accepted_messages"] == 1
        assert edge.state.pipeline.records[-1]["transmission_timestamp"]
    asyncio.run(run())


@pytest.mark.parametrize("scenario,expected", [
    ("tamper", "HASH_MISMATCH"), ("signature", "INVALID_SIGNATURE"),
    ("stale", "EXPIRED_MESSAGE"), ("future", "EXPIRED_MESSAGE"),
    ("size", "PAYLOAD_SIZE_MISMATCH"), ("oversized", "PAYLOAD_TOO_LARGE"),
    ("schema", "INVALID_SCHEMA"), ("unknown", "UNKNOWN_DEVICE"),
])
def test_phase2_attack_validation(factory, key, scenario, expected):
    async def run():
        app = factory()
        original = source()
        if scenario in {"stale", "future"}:
            stamp = datetime.now(timezone.utc) + timedelta(seconds=-300 if scenario == "stale" else 300)
            original = source(timestamp=stamp, created_at=stamp)
        document = sign(original, key).model_dump(mode="json")
        if scenario == "tamper":
            document["payload"]["temperature"] = 99.99
        elif scenario == "signature":
            document["signature"] = "x" * 88
        elif scenario == "size":
            document["payload_size"] += 1
        elif scenario == "schema":
            del document["sequence_number"]
        elif scenario == "unknown":
            document["device_id"] = "untrusted"
        async with client(app) as api:
            response = await api.post("/receive", content=b"x" * 8193) if scenario == "oversized" else await api.post("/receive", json=document)
        assert response.status_code >= 400
        assert response.json()["reason"] == expected
        assert app.state.security.counters()[expected] == 1
        assert not app.state.security.recent()
        assert verify_audit_log(app.state.audit.path)[0]
    asyncio.run(run())


def test_phase2_replay_duplicate_conflict_and_restart(factory, key, tmp_path):
    async def run():
        path = tmp_path / "persistent"
        app = factory(path=path)
        envelope = sign(source(10), key)
        async with client(app) as api:
            assert (await api.post("/receive", json=envelope.model_dump(mode="json"))).status_code == 202
            duplicate = await api.post("/receive", json=envelope.model_dump(mode="json"))
            assert duplicate.status_code == 200 and duplicate.json()["reason"] == "DUPLICATE_MESSAGE"
        app.state.security.close()
        restarted = factory(path=path)
        async with client(restarted) as api:
            replay = await api.post("/receive", json=sign(source(9), key).model_dump(mode="json"))
            assert replay.json()["reason"] == "REPLAY_DETECTED"
            conflict = sign(source(11, message_id=envelope.message_id), key)
            assert (await api.post("/receive", json=conflict.model_dump(mode="json"))).status_code == 409
            assert len((await api.get("/messages")).json()) == 1
            assert (await api.post("/receive", json=sign(source(11), key).model_dump(mode="json"))).status_code == 202
    asyncio.run(run())


def test_phase2_rate_and_payload_limits_do_not_poison_sequence(factory, key):
    async def run():
        limited = factory(rate=.001, burst=1)
        envelope = sign(source(), key).model_dump(mode="json")
        async with client(limited) as api:
            assert (await api.post("/receive", json=envelope)).status_code == 202
            response = await api.post("/receive", json=envelope)
            assert response.status_code == 429 and response.headers["retry-after"] == "1"
        small = factory(payload_limit=4)
        async with client(small) as api:
            assert (await api.post("/receive", json=envelope)).json()["reason"] == "PAYLOAD_TOO_LARGE"
            assert not small.state.security.counters().get("accepted_messages")
    asyncio.run(run())


def test_phase2_pending_recovery_bounded_queue_and_retry(factory, key, tmp_path):
    async def run():
        path = tmp_path / "recover"
        edge = factory("edge-gateway", path=path, capacity=1)
        first = source()
        second = source(2)
        async with client(edge) as api:
            assert (await api.post("/telemetry", json=first.model_dump(mode="json"))).status_code == 202
            assert (await api.post("/telemetry", json=second.model_dump(mode="json"))).json()["reason"] == "QUEUE_FULL"
        edge.state.security.close()
        restarted = factory("edge-gateway", path=path, capacity=1)
        assert restarted.state.pipeline.queue_length == 1
        fog = factory()
        async with client(fog) as api:
            attempts = 0

            async def unreliable(body):
                nonlocal attempts
                (await api.post("/receive", content=body)).raise_for_status()
                attempts += 1
                if attempts == 1:
                    raise ConnectionError("ack lost")

            with pytest.raises(ConnectionError):
                await restarted.state.pipeline.transmit_next(unreliable)
            await restarted.state.pipeline.transmit_next(unreliable)
            assert len((await api.get("/messages")).json()) == 1
            assert not restarted.state.security.pending()
        async with client(restarted) as api:
            assert (await api.post("/telemetry", json=second.model_dump(mode="json"))).status_code == 202
    asyncio.run(run())


def test_phase2_terminal_rejection_does_not_block_fifo(factory):
    async def run():
        app = factory("edge-gateway")
        async with client(app) as api:
            await api.post("/telemetry", json=source().model_dump(mode="json"))

        async def expired(body):
            raise PermanentDeliveryError("EXPIRED_MESSAGE")

        await app.state.pipeline.transmit_next(expired)
        assert app.state.pipeline.queue_length == 0
        assert app.state.pipeline.transmitted == 0
        assert app.state.security.counters()["terminal_delivery_rejections"] == 1
    asyncio.run(run())


def test_phase2_source_spoofing_rejected(factory, key):
    async def run():
        app = factory()
        async with client(app, "192.0.2.1") as api:
            response = await api.post("/receive", json=sign(source(), key).model_dump(mode="json"),
                                      headers={"X-Forwarded-For": "127.0.0.1"})
            assert response.status_code == 403
            assert (await api.get("/messages")).status_code == 403
    asyncio.run(run())


def test_phase2_audit_tampering_fails_closed(factory, tmp_path):
    app = factory(path=tmp_path / "audit")
    app.state.audit.append("test", "ACCEPTED")
    app.state.audit.append("test", "ACCEPTED")
    path = app.state.audit.path
    lines = path.read_text().splitlines()
    first = json.loads(lines[0])
    first["result"] = "MODIFIED"
    path.write_text(json.dumps(first) + "\n" + lines[1] + "\n")
    valid, reason = verify_audit_log(path)
    assert not valid and "line 1" in reason
    with pytest.raises(ValueError, match="broken audit chain"):
        factory(path=tmp_path / "audit")


def test_phase2_device_sequence_survives_restart(tmp_path):
    path = tmp_path / "device.db"
    state = DeviceState(path)
    first = state.next(random.Random(1))
    state.db.close()
    state = DeviceState(path)
    assert state.next(random.Random(2)) == first
    state.complete()
    assert state.next(random.Random(3)).sequence_number == 2
    state.db.close()


def test_phase2_key_initialization_is_non_destructive(tmp_path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    initialize(private, public)
    digest = hashlib.sha256(private.read_bytes()).hexdigest()
    initialize(private, public)
    assert hashlib.sha256(private.read_bytes()).hexdigest() == digest
    other_private, other_public = tmp_path / "other-private.pem", tmp_path / "other-public.pem"
    initialize(other_private, other_public)
    with pytest.raises(ValueError, match="does not match"):
        initialize(private, other_public)


def test_phase2_private_key_and_network_contract():
    root = Path(__file__).resolve().parents[1]
    config = yaml.safe_load((root / "docker-compose.phase2.yml").read_text())
    services = config["services"]
    for role in ("unidirectional-gateway", "fog-receiver", "edge-device"):
        assert not any("edge-private" in mount for mount in services[role]["volumes"])
    assert "edge-private:/private:ro" in services["edge-gateway"]["volumes"]
    assert "verification-public:/public:ro" in services["fog-receiver"]["volumes"]
    assert services["fog-receiver"]["networks"] == ["fog-network"]
    assert services["key-init"]["network_mode"] == "none"
    assert services["key-init"]["profiles"] == ["setup"]
    assert all("ports" not in spec for spec in services.values())

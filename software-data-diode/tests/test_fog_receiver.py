from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from shared.security import ReplayDetector
from tests.conftest import load_service_module, make_signed_envelope


def configured_fog_client(private_key: object) -> tuple[object, TestClient]:
    module = load_service_module("fog-receiver")
    module._public_key = private_key.public_key()
    module.replay_detector = ReplayDetector(600, 300)
    module.EVENT_PROCESSOR_URL = ""
    return module, TestClient(module.app)


def test_valid_signed_message_is_accepted(private_key: object) -> None:
    _, client = configured_fog_client(private_key)
    envelope = make_signed_envelope(private_key)

    response = client.post("/receive", json=envelope.model_dump(mode="json"))

    assert response.status_code == 200
    assert response.json()["status"] == "accepted"


def test_payload_tampering_is_rejected(private_key: object) -> None:
    _, client = configured_fog_client(private_key)
    envelope = make_signed_envelope(private_key)
    tampered = envelope.model_copy(
        update={"payload": envelope.payload.model_copy(update={"temperature": 999.0})}
    )

    response = client.post("/receive", json=tampered.model_dump(mode="json"))

    assert response.status_code == 400
    assert response.json()["detail"]["reason"] == "HASH_MISMATCH"


def test_invalid_signature_is_rejected(private_key: object) -> None:
    _, client = configured_fog_client(private_key)
    envelope = make_signed_envelope(private_key)
    tampered = envelope.model_copy(update={"signature": "invalid-signature"})

    response = client.post("/receive", json=tampered.model_dump(mode="json"))

    assert response.status_code == 400
    assert response.json()["detail"]["reason"] == "INVALID_SIGNATURE"


def test_modified_hash_is_rejected(private_key: object) -> None:
    _, client = configured_fog_client(private_key)
    envelope = make_signed_envelope(private_key, payload_hash="0" * 64)

    response = client.post("/receive", json=envelope.model_dump(mode="json"))

    assert response.status_code == 400
    assert response.json()["detail"]["reason"] == "HASH_MISMATCH"


def test_replayed_sequence_is_rejected(private_key: object) -> None:
    _, client = configured_fog_client(private_key)
    first = make_signed_envelope(
        private_key,
        sequence_number=2,
        created_at=datetime.now(timezone.utc),
    )
    replay = make_signed_envelope(
        private_key,
        message_id=str(uuid4()),
        sequence_number=1,
        created_at=datetime.now(timezone.utc),
    )

    assert client.post("/receive", json=first.model_dump(mode="json")).status_code == 200
    response = client.post("/receive", json=replay.model_dump(mode="json"))

    assert response.status_code == 409
    assert response.json()["detail"]["reason"] == "REPLAY_DETECTED"


def test_duplicate_uuid_is_rejected(private_key: object) -> None:
    _, client = configured_fog_client(private_key)
    envelope = make_signed_envelope(private_key)

    assert client.post("/receive", json=envelope.model_dump(mode="json")).status_code == 200
    response = client.post("/receive", json=envelope.model_dump(mode="json"))

    assert response.status_code == 409
    assert response.json()["detail"]["reason"] == "DUPLICATE_MESSAGE"


def test_expired_timestamp_is_rejected(private_key: object, expired_time: object) -> None:
    _, client = configured_fog_client(private_key)
    envelope = make_signed_envelope(private_key, created_at=expired_time)

    response = client.post("/receive", json=envelope.model_dump(mode="json"))

    assert response.status_code == 409
    assert response.json()["detail"]["reason"] == "EXPIRED_MESSAGE"


def test_malformed_json_is_rejected(private_key: object) -> None:
    _, client = configured_fog_client(private_key)

    response = client.post(
        "/receive",
        content="{bad json",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["reason"] == "INVALID_SCHEMA"

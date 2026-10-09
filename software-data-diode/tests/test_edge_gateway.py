from fastapi.testclient import TestClient

from tests.conftest import load_service_module


def test_valid_raw_telemetry_is_signed_and_forwarded(
    raw_edge_payload: dict[str, object],
    private_key: object,
    fake_async_client: object,
) -> None:
    module = load_service_module("edge-gateway")
    module.httpx.AsyncClient = fake_async_client
    module.DATA_DIODE_URL = "http://data-diode:8000/ingest"
    module._private_key = private_key
    client = TestClient(module.app)

    response = client.post("/telemetry", json=raw_edge_payload)

    assert response.status_code == 200
    assert response.json()["status"] == "forwarded"
    assert len(fake_async_client.posted_requests) == 1
    forwarded = fake_async_client.posted_requests[0]["json"]
    assert fake_async_client.posted_requests[0]["url"] == module.DATA_DIODE_URL
    assert forwarded["message_id"] == response.json()["message_id"]
    assert forwarded["signature"] != "unsigned"
    assert forwarded["payload_hash"]


def test_invalid_raw_telemetry_is_rejected(raw_edge_payload: dict[str, object]) -> None:
    module = load_service_module("edge-gateway")
    client = TestClient(module.app)
    invalid_payload = dict(raw_edge_payload)
    invalid_payload["humidity"] = 125.0

    response = client.post("/telemetry", json=invalid_payload)

    assert response.status_code == 422
    assert response.json()["reason"] == "INVALID_SCHEMA"

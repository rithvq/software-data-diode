import asyncio

from fastapi.testclient import TestClient

from shared.security import TokenBucketRateLimiter
from shared.traffic import BoundedMessageQueue, CongestionMonitor, TrafficMetrics
from tests.conftest import load_service_module


def test_valid_signed_envelope_is_received_and_forwarded(
    signed_envelope: object,
    fake_async_client: object,
) -> None:
    module = load_service_module("data-diode")
    module.httpx.AsyncClient = fake_async_client
    module.FOG_RECEIVER_URL = "http://fog-receiver:8000/receive"
    module.ingress_rate_limiter = TokenBucketRateLimiter(100, 100)
    module.queue_manager = BoundedMessageQueue(100)
    module.congestion_monitor = CongestionMonitor()
    module.traffic_metrics = TrafficMetrics()
    module.SCHEDULER_MODE = "fifo"
    client = TestClient(module.app)

    response = client.post("/ingest", json=signed_envelope.model_dump(mode="json"))
    processed = asyncio.run(module.process_next_message())

    assert response.status_code == 200
    assert response.json()["status"] == "queued"
    assert processed is True
    assert len(fake_async_client.posted_requests) == 1
    assert fake_async_client.posted_requests[0]["url"] == module.FOG_RECEIVER_URL


def test_oversized_payload_is_rejected(signed_envelope: object) -> None:
    module = load_service_module("data-diode")
    module.MAX_PAYLOAD_BYTES = 10
    module.ingress_rate_limiter = TokenBucketRateLimiter(100, 100)
    module.queue_manager = BoundedMessageQueue(100)
    client = TestClient(module.app)

    response = client.post("/ingest", json=signed_envelope.model_dump(mode="json"))

    assert response.status_code == 413
    assert response.json()["detail"]["reason"] == "PAYLOAD_TOO_LARGE"


def test_malformed_json_is_rejected() -> None:
    module = load_service_module("data-diode")
    module.ingress_rate_limiter = TokenBucketRateLimiter(100, 100)
    module.queue_manager = BoundedMessageQueue(100)
    client = TestClient(module.app)

    response = client.post(
        "/ingest",
        content="{bad json",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["reason"] == "INVALID_SCHEMA"


def test_excessive_request_rate_is_rejected(
    signed_envelope: object,
    fake_async_client: object,
) -> None:
    module = load_service_module("data-diode")
    module.httpx.AsyncClient = fake_async_client
    module.ingress_rate_limiter = TokenBucketRateLimiter(0.01, 1)
    module.queue_manager = BoundedMessageQueue(100)
    client = TestClient(module.app)

    first = client.post("/ingest", json=signed_envelope.model_dump(mode="json"))
    second = client.post("/ingest", json=signed_envelope.model_dump(mode="json"))

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["detail"]["reason"] == "RATE_LIMIT_EXCEEDED"

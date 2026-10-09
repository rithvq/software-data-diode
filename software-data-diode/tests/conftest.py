from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_REAL_ASYNC_CLIENT = httpx.AsyncClient
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(autouse=True)
def isolated_http_client():
    # Older service tests replace a shared module attribute directly.
    httpx.AsyncClient = _REAL_ASYNC_CLIENT
    yield
    httpx.AsyncClient = _REAL_ASYNC_CLIENT

from shared.models import PriorityLevel, SecureTelemetryEnvelope, TelemetryPayload, TelemetryType
from shared.security import compute_payload_hash, sign_envelope


def load_service_module(service_dir: str) -> Any:
    module_name = f"{service_dir.replace('-', '_')}_main"
    module_path = PROJECT_ROOT / service_dir / "app" / "main.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def raw_edge_payload() -> dict[str, object]:
    return {
        "device_id": "edge-device-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "temperature": 28.5,
        "humidity": 62.3,
        "status": "normal",
    }


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def make_signed_envelope(
    private_key: Ed25519PrivateKey,
    *,
    message_id: str | None = None,
    device_id: str = "edge-device-001",
    created_at: datetime | None = None,
    sequence_number: int = 1,
    temperature: float = 28.5,
    humidity: float = 62.3,
    status: str = "normal",
    event_type: str = "telemetry",
    priority: PriorityLevel = PriorityLevel.LOW,
    estimated_transmission_cost: float = 1.0,
    payload_hash: str | None = None,
    telemetry_type: TelemetryType = TelemetryType.ENVIRONMENTAL,
    cpu_usage: float | None = None,
    memory_usage: float | None = None,
    measurements: dict[str, float] | None = None,
) -> SecureTelemetryEnvelope:
    payload = TelemetryPayload(
        temperature=temperature,
        humidity=humidity,
        status=status,
        event_type=event_type,
        telemetry_type=telemetry_type,
        cpu_usage=cpu_usage,
        memory_usage=memory_usage,
        measurements=measurements or {},
    )
    envelope = SecureTelemetryEnvelope(
        message_id=message_id or uuid4(),
        device_id=device_id,
        created_at=created_at or datetime.now(timezone.utc),
        sequence_number=sequence_number,
        priority=priority,
        payload=payload,
        payload_hash=payload_hash or compute_payload_hash(payload),
        signature="unsigned",
        estimated_transmission_cost=estimated_transmission_cost,
        schema_version="1.0",
    )
    signature = sign_envelope(envelope, private_key)
    return envelope.model_copy(update={"signature": signature})


@pytest.fixture
def signed_envelope(private_key: Ed25519PrivateKey) -> SecureTelemetryEnvelope:
    return make_signed_envelope(private_key)


class FakeSuccessResponse:
    def raise_for_status(self) -> None:
        return None


class FakeAsyncClient:
    posted_requests: list[dict[str, object]] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.args = args
        self.kwargs = kwargs

    async def __aenter__(self) -> "FakeAsyncClient":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def post(self, url: str, json: dict[str, object]) -> FakeSuccessResponse:
        self.posted_requests.append({"url": url, "json": json})
        return FakeSuccessResponse()


@pytest.fixture
def fake_async_client() -> type[FakeAsyncClient]:
    FakeAsyncClient.posted_requests = []
    return FakeAsyncClient


@pytest.fixture
def expired_time() -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=1000)

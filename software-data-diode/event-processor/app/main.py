from datetime import datetime, timezone
import asyncio
from ipaddress import ip_address, ip_network
import logging
import os
import time

import httpx
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import Response

from shared.models import FogEvent, SecureTelemetryEnvelope
from shared.http import BodyLimitMiddleware
from shared.observability import ServiceMetrics, configure_json_logging, log_context
from shared.persistence import repository_from_env

configure_json_logging("event-processor")
logger = logging.getLogger("event-processor")

ANALYTICS_URL = os.getenv("ANALYTICS_URL", "http://fog-analytics:8000/analyze")
EVENT_PROCESSOR_ALLOWED_CIDR = os.getenv("EVENT_PROCESSOR_ALLOWED_CIDR", "0.0.0.0/0")
FORWARD_TIMEOUT_SECONDS = float(os.getenv("FORWARD_TIMEOUT_SECONDS", "5"))

app = FastAPI(title="Fog Event Processor", version="0.4.0")
app.add_middleware(BodyLimitMiddleware, paths=["/events"], limit=65536)
repository = repository_from_env()
prometheus_metrics = ServiceMetrics("event-processor")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "event-processor"}


@app.get("/ready")
async def ready() -> dict[str, str]:
    if not await asyncio.to_thread(repository.healthcheck):
        raise HTTPException(status_code=503, detail="database unavailable")
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(ANALYTICS_URL.rsplit("/", 1)[0] + "/ready")
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="analytics unavailable") from exc
    return {"status": "ready", "service": "event-processor"}


@app.get("/metrics")
async def prometheus() -> Response:
    body, content_type = prometheus_metrics.render()
    return Response(content=body, media_type=content_type)


@app.post("/events")
async def process_envelope(
    envelope: SecureTelemetryEnvelope, request: Request
) -> dict[str, str]:
    client_host = request.client.host if request.client else ""
    if not _client_allowed(client_host, EVENT_PROCESSOR_ALLOWED_CIDR):
        prometheus_metrics.rejected("UNAUTHORIZED_SOURCE")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="unauthorized source")

    started_at = time.monotonic()
    prometheus_metrics.received(envelope.device_id, envelope.priority)
    event = FogEvent(received_at=datetime.now(timezone.utc), envelope=envelope)
    try:
        await asyncio.to_thread(repository.save_telemetry, event)
    except Exception as exc:
        logger.exception("[EVENT PROCESSOR] Database persistence failed")
        raise HTTPException(status_code=503, detail="database unavailable") from exc

    try:
        async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT_SECONDS) as client:
            response = await client.post(ANALYTICS_URL, json=event.model_dump(mode="json"))
            response.raise_for_status()
    except httpx.HTTPError as exc:
        prometheus_metrics.rejected("FORWARD_FAILED", envelope.device_id)
        logger.error("[EVENT PROCESSOR] Analytics forwarding failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="analytics unavailable"
        ) from exc

    duration = time.monotonic() - started_at
    prometheus_metrics.forwarded(envelope.device_id, envelope.priority)
    prometheus_metrics.end_to_end_latency.labels(
        "event-processor", str(envelope.priority)
    ).observe(duration)
    try:
        await asyncio.to_thread(repository.save_performance_metric,
            "event-processor",
            "processing_latency_seconds",
            duration,
            {"device_id": envelope.device_id},
        )
    except Exception as exc:
        logger.error("[EVENT PROCESSOR] Could not persist performance metric: %s", exc)
    logger.info(
        "[EVENT PROCESSOR] Persisted and forwarded message_id=%s device=%s",
        envelope.message_id,
        envelope.device_id,
        extra=log_context(
            "event_persisted",
            message_id=envelope.message_id,
            device_id=envelope.device_id,
            correlation_id=envelope.message_id,
            processing_latency_seconds=duration,
        ),
    )
    return {"status": "processed", "event_id": str(event.event_id)}


def _client_allowed(client_host: str, allowed_cidr: str) -> bool:
    if allowed_cidr in {"*", "0.0.0.0/0", "::/0"}:
        return True
    try:
        return ip_address(client_host) in ip_network(allowed_cidr, strict=False)
    except ValueError:
        return False

import asyncio
import logging
import os

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import Response

from shared.observability import ServiceMetrics, configure_json_logging

from .store import store_from_env

configure_json_logging("monitoring-api")
logger = logging.getLogger("monitoring-api")

FOG_HEALTH_SERVICES = {
    "fog-receiver": os.getenv("FOG_RECEIVER_HEALTH_URL", "http://fog-receiver:8000/health"),
    "event-processor": os.getenv("EVENT_PROCESSOR_HEALTH_URL", "http://event-processor:8000/health"),
    "fog-analytics": os.getenv("FOG_ANALYTICS_HEALTH_URL", "http://fog-analytics:8000/health"),
    "alert-engine": os.getenv("ALERT_ENGINE_HEALTH_URL", "http://alert-engine:8000/health"),
    "dashboard": os.getenv("DASHBOARD_HEALTH_URL", "http://dashboard:8501/_stcore/health"),
}

app = FastAPI(title="Fog Monitoring API", version="0.5.0")
store = store_from_env()
prometheus_metrics = ServiceMetrics("monitoring-api")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "monitoring-api"}


@app.get("/ready")
async def ready() -> dict[str, str]:
    if not await asyncio.to_thread(store.healthcheck):
        raise HTTPException(status_code=503, detail="database unavailable")
    return {"status": "ready", "service": "monitoring-api"}


@app.get("/metrics")
async def prometheus() -> Response:
    body, content_type = prometheus_metrics.render()
    return Response(content=body, media_type=content_type)


@app.get("/api/snapshot")
async def snapshot() -> dict[str, object]:
    try:
        document = await asyncio.to_thread(store.snapshot)
    except Exception as exc:
        logger.exception("Monitoring snapshot query failed")
        raise HTTPException(status_code=503, detail="monitoring data unavailable") from exc
    fog_services = await _fog_health()
    fog_services.extend(
        [
            {"service": "postgres", "status": "HEALTHY"},
        ]
    )
    document["architecture"]["fog_services"] = fog_services
    return document


async def _fog_health() -> list[dict[str, str]]:
    async def check(service: str, url: str) -> dict[str, str]:
        try:
            async with httpx.AsyncClient(timeout=1.5) as client:
                response = await client.get(url)
                response.raise_for_status()
            return {"service": service, "status": "HEALTHY"}
        except httpx.HTTPError:
            return {"service": service, "status": "UNAVAILABLE"}

    return await asyncio.gather(
        *(check(service, url) for service, url in FOG_HEALTH_SERVICES.items())
    )

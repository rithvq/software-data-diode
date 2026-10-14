import logging
import asyncio
import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response

from shared.models import AlertRecord
from shared.http import BodyLimitMiddleware
from shared.observability import ServiceMetrics, configure_json_logging, log_context
from shared.persistence import repository_from_env
from shared.models.fog import CoverageAlertDelivery as AlertDelivery

configure_json_logging("alert-engine")
logger = logging.getLogger("alert-engine")

app = FastAPI(title="Fog Alert Engine", version="0.4.0")
app.add_middleware(BodyLimitMiddleware, paths=["/alerts"], limit=65536)
app.add_middleware(BodyLimitMiddleware, paths=["/coverage-alerts"], limit=4096)
repository = repository_from_env()
prometheus_metrics = ServiceMetrics("alert-engine")
COVERAGE_ALERTS_ENABLED = os.getenv("COVERAGE_ALERTS_ENABLED","false").lower() == "true"


@app.post("/coverage-alerts")
async def deliver_coverage_alert(delivery: AlertDelivery):
    if not COVERAGE_ALERTS_ENABLED:
        raise HTTPException(status_code=404,detail="coverage alerts disabled in baseline")
    try:
        result = await asyncio.to_thread(repository.deliver_coverage_alert,delivery)
    except Exception as exc:
        logger.exception("coverage alert database transaction failed")
        raise HTTPException(status_code=503,detail="durable alert repository unavailable") from exc
    return {"status":result,"alert_id":str(delivery.alert_id)}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "alert-engine"}


@app.get("/ready")
async def ready() -> dict[str, str]:
    if not await asyncio.to_thread(repository.healthcheck):
        raise HTTPException(status_code=503, detail="database unavailable")
    return {"status": "ready", "service": "alert-engine"}


@app.get("/metrics")
async def prometheus() -> Response:
    body, content_type = prometheus_metrics.render()
    return Response(content=body, media_type=content_type)


@app.post("/alerts")
async def create_alert(alert: AlertRecord) -> dict[str, str]:
    prometheus_metrics.received(",".join(alert.source_devices), alert.severity)
    try:
        await asyncio.to_thread(repository.save_alert, alert)
    except Exception as exc:
        logger.exception("[ALERT ENGINE] Database persistence failed")
        raise HTTPException(status_code=503, detail="database unavailable") from exc
    evidence_message_id = next(
        (
            item.get("message_id")
            for item in alert.evidence
            if item.get("message_id") is not None
        ),
        alert.alert_id,
    )
    logger.warning(
        "[ALERT ENGINE] severity=%s type=%s devices=%s alert_id=%s",
        alert.severity,
        alert.alert_type,
        ",".join(alert.source_devices),
        alert.alert_id,
        extra=log_context(
            "alert_stored",
            message_id=alert.alert_id,
            device_id=alert.source_devices[0],
            correlation_id=evidence_message_id,
            severity=alert.severity,
            alert_type=alert.alert_type,
        ),
    )
    return {"status": "stored", "alert_id": str(alert.alert_id)}

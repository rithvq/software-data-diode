from datetime import datetime, timezone
import asyncio
from collections import OrderedDict
import logging
import os
import time

import httpx
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import Response

from shared.analytics import AnomalyDetector, CorrelationEngine, DetectionConfig
from shared.models import AlertRecord, AlertSeverity, FogEvent
from shared.http import BodyLimitMiddleware
from shared.observability import ServiceMetrics, configure_json_logging, log_context
from shared.persistence import repository_from_env

configure_json_logging("fog-analytics")
logger = logging.getLogger("fog-analytics")

ANOMALY_RULES_PATH = os.getenv("ANOMALY_RULES_PATH", "config/anomaly_rules.json")
CORRELATION_RULES_PATH = os.getenv(
    "CORRELATION_RULES_PATH", "config/correlation_rules.json"
)
ALERT_ENGINE_URL = os.getenv("ALERT_ENGINE_URL", "http://alert-engine:8000/alerts")
FORWARD_TIMEOUT_SECONDS = float(os.getenv("FORWARD_TIMEOUT_SECONDS", "5"))

app = FastAPI(title="Fog Analytics Engine", version="0.4.0")
app.add_middleware(BodyLimitMiddleware, paths=["/analyze"], limit=65536)
repository = repository_from_env()
detector = AnomalyDetector(DetectionConfig.from_file(ANOMALY_RULES_PATH))
correlator = CorrelationEngine.from_file(CORRELATION_RULES_PATH)
prometheus_metrics = ServiceMetrics("fog-analytics")
_analysis_lock = asyncio.Lock()
_analyses = OrderedDict()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "fog-analytics"}


@app.get("/ready")
async def ready() -> dict[str, str]:
    if not await asyncio.to_thread(repository.healthcheck):
        raise HTTPException(status_code=503, detail="database unavailable")
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(ALERT_ENGINE_URL.rsplit("/", 1)[0] + "/ready")
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="alert engine unavailable") from exc
    return {"status": "ready", "service": "fog-analytics"}


@app.get("/metrics")
async def prometheus() -> Response:
    body, content_type = prometheus_metrics.render()
    return Response(content=body, media_type=content_type)


@app.post("/analyze")
async def analyze(event: FogEvent) -> dict[str, int | str]:
    async with _analysis_lock:
        return await _analyze_once(event)


async def _analyze_once(event):
    started_at = time.monotonic()
    prometheus_metrics.received(event.envelope.device_id, event.envelope.priority)
    identifier = str(event.envelope.message_id)
    cached = _analyses.get(identifier)
    if cached and cached["signature"] != event.envelope.signature:
        raise HTTPException(409, detail="conflicting message identity")
    if cached and cached["complete"]:
        return cached["result"]
    if cached is None:
        if len(_analyses) >= 1000:
            victim = next((key for key, value in _analyses.items() if value["complete"]), None)
            if victim is None:
                raise HTTPException(503, detail="pending analysis capacity exhausted")
            del _analyses[victim]
        anomalies = detector.detect(event)
        security_events, correlation_alerts = correlator.process(event)
        alerts = [_alert_from_anomaly(anomaly) for anomaly in anomalies] + correlation_alerts
        cached = {"signature": event.envelope.signature, "complete": False,
                  "anomalies": anomalies, "security_events": security_events, "alerts": alerts}
        _analyses[identifier] = cached
    anomalies, security_events, alerts = cached["anomalies"], cached["security_events"], cached["alerts"]

    try:
        for anomaly in anomalies:
            await asyncio.to_thread(repository.save_anomaly, anomaly)
        for security_event in security_events:
            await asyncio.to_thread(repository.save_security_event, security_event)
    except Exception as exc:
        logger.exception("[FOG ANALYTICS] Database persistence failed")
        raise HTTPException(status_code=503, detail="database unavailable") from exc
    for alert in alerts:
        await _send_alert(alert)

    duration = time.monotonic() - started_at
    try:
        await asyncio.to_thread(repository.save_performance_metric,
            "fog-analytics",
            "analysis_latency_seconds",
            duration,
            {"device_id": event.envelope.device_id},
        )
    except Exception as exc:
        logger.error("[FOG ANALYTICS] Could not persist performance metric: %s", exc)
    prometheus_metrics.forwarded(event.envelope.device_id, event.envelope.priority)
    prometheus_metrics.end_to_end_latency.labels(
        "fog-analytics", str(event.envelope.priority)
    ).observe(duration)
    logger.info(
        "[FOG ANALYTICS] message_id=%s anomalies=%s correlations=%s alerts=%s",
        event.envelope.message_id,
        len(anomalies),
        len(security_events),
        len(alerts),
        extra=log_context(
            "telemetry_analyzed",
            message_id=event.envelope.message_id,
            device_id=event.envelope.device_id,
            correlation_id=event.envelope.message_id,
            anomaly_count=len(anomalies),
            correlation_count=len(security_events),
            alert_count=len(alerts),
        ),
    )
    cached["complete"] = True
    cached["result"] = {
        "status": "analyzed",
        "anomalies": len(anomalies),
        "correlations": len(security_events),
        "alerts": len(alerts),
    }
    return cached["result"]


async def _send_alert(alert: AlertRecord) -> None:
    try:
        async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT_SECONDS) as client:
            response = await client.post(ALERT_ENGINE_URL, json=alert.model_dump(mode="json"))
            response.raise_for_status()
    except httpx.HTTPError as exc:
        prometheus_metrics.rejected("FORWARD_FAILED", alert.source_devices[0])
        logger.error("[FOG ANALYTICS] Alert forwarding failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="alert engine unavailable"
        ) from exc


def _alert_from_anomaly(anomaly) -> AlertRecord:
    return AlertRecord(
        timestamp=datetime.now(timezone.utc),
        source_devices=[anomaly.device_id],
        alert_type=f"ANOMALY_{anomaly.detector.upper()}",
        severity=anomaly.severity,
        evidence=[
            {
                "anomaly_id": str(anomaly.anomaly_id),
                "message_id": str(anomaly.message_id),
                "metric": anomaly.metric,
                "observed_value": anomaly.observed_value,
                "expected_value": anomaly.expected_value,
                "score": anomaly.score,
            }
        ],
        description=anomaly.explanation,
    )

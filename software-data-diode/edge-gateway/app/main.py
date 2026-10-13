import asyncio
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
import logging
import os
import re
import time
from uuid import uuid4

import httpx
from fastapi import FastAPI, Header, HTTPException, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response

from shared.models import (
    CongestionState,
    EdgeTelemetryMessage,
    PriorityLevel,
    RejectionReason,
    SecureTelemetryEnvelope,
    TelemetryPayload,
    ObservabilitySnapshot,
)
from shared.edge import DeviceRegistry
from shared.http import BodyLimitMiddleware
from shared.traffic.information import InformationEngine, InformationPolicyConfig
from shared.observability import ServiceMetrics, configure_json_logging, log_context
from shared.security import (
    AuditLog,
    compute_payload_hash,
    load_private_key,
    sign_envelope,
    verify_audit_log,
)
from shared.traffic import (
    EdgeFilter,
    EdgeFilterConfig,
    TrafficMetrics,
    classify_priority,
    load_priority_config_from_env,
)

configure_json_logging("edge-gateway")
logger = logging.getLogger("edge-gateway")

DATA_DIODE_URL = os.getenv(
    "DATA_DIODE_URL",
    "http://data-diode:8000/ingest",
)
FORWARD_TIMEOUT_SECONDS = float(os.getenv("FORWARD_TIMEOUT_SECONDS", "5"))
EDGE_PRIVATE_KEY_PATH = os.getenv(
    "EDGE_PRIVATE_KEY_PATH",
    "/run/secrets/edge_private_key.pem",
)
EDGE_INPUT_FRESHNESS_SECONDS = float(os.getenv("EDGE_INPUT_FRESHNESS_SECONDS", "300"))
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "logs/edge-gateway-audit.jsonl")
EDGE_FILTER_CONGESTION_STATE = CongestionState(
    os.getenv("EDGE_FILTER_CONGESTION_STATE", "NORMAL").upper()
)
DEVICE_HEALTH_TIMEOUT_SECONDS = float(os.getenv("DEVICE_HEALTH_TIMEOUT_SECONDS", "30"))
GATEWAY_SEQUENCE_STATE_PATH = os.getenv("GATEWAY_SEQUENCE_STATE_PATH") or None
DATA_DIODE_METRICS_URL = os.getenv(
    "DATA_DIODE_METRICS_URL", "http://data-diode:8000/ingest-metrics"
)
OBSERVABILITY_TOKEN = os.getenv("OBSERVABILITY_TOKEN", "phase5-internal-observability")
OBSERVABILITY_INTERVAL_SECONDS = float(os.getenv("OBSERVABILITY_INTERVAL_SECONDS", "5"))
INFORMATION_POLICY_ENABLED = os.getenv("INFORMATION_POLICY_ENABLED", "false").lower() == "true"
_coverage_flag = os.getenv("RULE_COVERAGE_ENABLED", "false").lower()
if _coverage_flag not in {"true", "false"}:
    raise ValueError("RULE_COVERAGE_ENABLED must be true or false")
RULE_COVERAGE_ENABLED = _coverage_flag == "true"

audit_log = AuditLog(AUDIT_LOG_PATH, "edge-gateway")
device_registry = DeviceRegistry(
    DEVICE_HEALTH_TIMEOUT_SECONDS,
    sequence_state_path=GATEWAY_SEQUENCE_STATE_PATH,
)
priority_config = load_priority_config_from_env()
edge_filter = EdgeFilter(EdgeFilterConfig.from_env())
traffic_metrics = TrafficMetrics()
prometheus_metrics = ServiceMetrics("edge-gateway")
_private_key = None
_observability_task: asyncio.Task | None = None
_policy_task: asyncio.Task | None = None
_pending_envelope = None
_last_envelope_created_at: datetime | None = None
_coverage_ledger = None
_coverage_task: asyncio.Task | None = None
_coverage_admissions: set[asyncio.Task] = set()


def _audit_policy_decision(decision: dict) -> None:
    prometheus_metrics.policy_actions.labels("edge-gateway", decision["action"]).inc()
    prometheus_metrics.predicted_queue.labels("edge-gateway").set(decision["local_state"]["predicted_queue_length"])
    prometheus_metrics.queue_size.labels("edge-gateway").set(len(information_engine.queue))
    prometheus_metrics.information_utility.labels("edge-gateway", decision["priority"]).observe(decision["utility_score"])
    audit_log.append(
        event_type="INFORMATION_POLICY", result=decision["action"],
        reason=decision["reason"], message_id=decision["message_id"],
        device_id=decision["device_id"], details=decision,
    )
    if decision["action"] in {"DROP", "SAMPLE", "SUPERSEDE"}:
        device_registry.record_filtered(decision["device_id"], decision["action"])
        if decision["action"] == "DROP":
            prometheus_metrics.dropped_messages.labels("edge-gateway", decision["priority"]).inc()


information_engine = InformationEngine(
    InformationPolicyConfig.from_file(os.environ["INFORMATION_POLICY_CONFIG"])
    if os.getenv("INFORMATION_POLICY_CONFIG") else InformationPolicyConfig(),
    on_decision=_audit_policy_decision,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _observability_task, _policy_task, _coverage_ledger, _coverage_task
    _observability_task = _policy_task = _coverage_task = None
    if RULE_COVERAGE_ENABLED:
        from shared.coverage.contracts import load_contract
        from shared.coverage.ledger import ObservationLedger, PROJECT_NAME
        if os.getenv("COVERAGE_PROJECT_NAME") != PROJECT_NAME or not os.getenv("COVERAGE_LEDGER_PATH") or not os.getenv("COVERAGE_CONTRACT_PATH"):
            raise ValueError("coverage mode requires a separately provisioned research project, ledger and contract")
        _coverage_ledger = await asyncio.to_thread(
            ObservationLedger, os.environ["COVERAGE_LEDGER_PATH"],
            load_contract(os.environ["COVERAGE_CONTRACT_PATH"]), project_name=PROJECT_NAME,
        )
        _coverage_task = asyncio.create_task(_coverage_clock_loop())
    else:
        _observability_task = asyncio.create_task(_observability_loop())
    if INFORMATION_POLICY_ENABLED and not RULE_COVERAGE_ENABLED:
        _policy_task = asyncio.create_task(_information_loop())
    try:
        yield
    finally:
        if _observability_task is not None:
            _observability_task.cancel()
            with suppress(asyncio.CancelledError):
                await _observability_task
        if _policy_task is not None:
            _policy_task.cancel()
            with suppress(asyncio.CancelledError):
                await _policy_task
        if _coverage_task is not None:
            _coverage_task.cancel()
            with suppress(asyncio.CancelledError):
                await _coverage_task
        if _coverage_admissions:
            await asyncio.gather(*tuple(_coverage_admissions), return_exceptions=True)
        if _coverage_ledger is not None:
            await asyncio.to_thread(_coverage_ledger.close)
            _coverage_ledger = None


app = FastAPI(title="Edge Gateway", version="0.5.0", lifespan=lifespan)
app.add_middleware(BodyLimitMiddleware, paths=["/telemetry"], limit=int(os.getenv("MAX_PAYLOAD_BYTES", "8192")))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc) -> JSONResponse:
    prometheus_metrics.rejected(RejectionReason.INVALID_SCHEMA)
    return JSONResponse(
        status_code=422,
        content={"status": "rejected", "reason": RejectionReason.INVALID_SCHEMA},
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "edge-gateway"}


@app.get("/ready")
async def ready() -> dict[str, str]:
    if RULE_COVERAGE_ENABLED:
        try:
            if _coverage_ledger is None or (_coverage_task is not None and _coverage_task.done()):
                raise RuntimeError("ledger worker unavailable")
            state = await asyncio.to_thread(_coverage_ledger.status)
            if state["clock_halted"] or state["admission_blocked"]:
                raise RuntimeError("ledger clock requires recovery")
        except Exception as exc:
            raise HTTPException(status_code=503, detail="coverage ledger unavailable") from exc
        return {"status": "ready", "service": "edge-gateway", "mode": "ledger-only"}
    if INFORMATION_POLICY_ENABLED and _policy_task is not None and _policy_task.done():
        raise HTTPException(status_code=503, detail="policy worker stopped")
    try:
        _get_private_key()
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(DATA_DIODE_URL.rsplit("/", 1)[0] + "/ready")
            response.raise_for_status()
    except (OSError, ValueError, TypeError, httpx.HTTPError) as exc:
        logger.warning("[EDGE GATEWAY] Readiness check failed: %s", exc)
        raise HTTPException(status_code=503, detail="gateway dependency unavailable") from exc
    return {"status": "ready", "service": "edge-gateway"}


@app.get("/metrics")
async def prometheus() -> Response:
    valid, _ = await asyncio.to_thread(verify_audit_log, AUDIT_LOG_PATH)
    prometheus_metrics.audit_log_valid.labels("edge-gateway").set(1 if valid else 0)
    body, content_type = prometheus_metrics.render()
    return Response(content=body, media_type=content_type)


@app.get("/metrics/runtime")
async def metrics() -> dict[str, object]:
    return {
        "traffic": traffic_metrics.snapshot(),
        "devices": [item.model_dump(mode="json") for item in device_registry.snapshots()],
        "information_policy": information_engine.snapshot(time.monotonic()) if INFORMATION_POLICY_ENABLED else None,
        **({"coverage_ledger": await asyncio.to_thread(_coverage_ledger.status)
            if _coverage_ledger is not None else None} if RULE_COVERAGE_ENABLED else {}),
    }


@app.get("/devices")
async def devices() -> list[dict[str, object]]:
    return [item.model_dump(mode="json") for item in device_registry.snapshots()]


@app.get("/devices/{device_id}")
async def device_status(device_id: str) -> dict[str, object]:
    snapshot = device_registry.snapshot(device_id)
    if snapshot is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown device")
    return snapshot.model_dump(mode="json")


@app.post("/telemetry")
async def receive_telemetry(
    message: EdgeTelemetryMessage,
    coverage_epoch: str | None = Header(default=None, alias="X-Coverage-Epoch"),
    retry_sequence: str | None = Header(default=None, alias="X-Coverage-Retry-Sequence"),
) -> dict[str, object]:
    if RULE_COVERAGE_ENABLED:
        return await _receive_coverage(message, coverage_epoch, retry_sequence)
    if not _timestamp_fresh(message.timestamp, EDGE_INPUT_FRESHNESS_SECONDS):
        device_registry.record_rejected(message.device_id)
        prometheus_metrics.rejected(RejectionReason.EXPIRED_MESSAGE, message.device_id)
        audit_log.append(
            event_type="EDGE_TELEMETRY_REJECTED",
            result="REJECTED",
            reason=RejectionReason.EXPIRED_MESSAGE,
            device_id=message.device_id,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "status": "rejected",
                "reason": RejectionReason.EXPIRED_MESSAGE,
            },
        )

    priority = classify_priority(message, priority_config)
    prometheus_metrics.received(message.device_id, priority)
    device_registry.record_received(message.device_id, priority)
    if INFORMATION_POLICY_ENABLED:
        try:
            decision = information_engine.submit(
                message, priority, time.monotonic(), datetime.now(timezone.utc)
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        traffic_metrics.record_generated(len(message.model_dump_json().encode("utf-8")))
        return {
            "status": "filtered" if decision["action"] in {"DROP", "SAMPLE"} else "queued",
            "message_id": decision["message_id"], "priority": priority,
            "action": decision["action"], "reason": decision["reason"],
        }
    filter_decision = edge_filter.evaluate(message, priority, EDGE_FILTER_CONGESTION_STATE)
    traffic_metrics.record_generated(filter_decision.generated_bytes)

    if filter_decision.message is None:
        traffic_metrics.record_filtered(priority, filter_decision.filtered_bytes)
        prometheus_metrics.filtered_bytes.labels(
            "edge-gateway", message.device_id
        ).inc(filter_decision.filtered_bytes)
        device_registry.record_filtered(message.device_id, str(filter_decision.reason))
        audit_log.append(
            event_type="EDGE_TELEMETRY_FILTERED",
            result="FILTERED",
            reason=filter_decision.reason or "",
            device_id=message.device_id,
        )
        logger.info(
            "[EDGE GATEWAY] Filtered telemetry from %s priority=%s reason=%s",
            message.device_id,
            priority,
            filter_decision.reason,
            extra=log_context(
                "telemetry_filtered",
                device_id=message.device_id,
                correlation_id=message.device_id,
                priority=priority,
                reason=filter_decision.reason,
            ),
        )
        return {
            "status": "filtered",
            "reason": str(filter_decision.reason),
            "priority": priority,
        }

    outbound_message = filter_decision.message
    outbound_priority = PriorityLevel.LOW if filter_decision.action == "aggregate" else priority
    envelope = _build_signed_envelope(
        outbound_message,
        outbound_priority,
        max(filter_decision.generated_bytes, 1),
    )
    logger.info(
        "[EDGE GATEWAY] Received valid telemetry from %s",
        message.device_id,
    )
    logger.info(
        "[EDGE GATEWAY] Created signed envelope message_id=%s sequence=%s",
        envelope.message_id,
        envelope.sequence_number,
    )

    try:
        async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT_SECONDS) as client:
            response = await client.post(
                DATA_DIODE_URL,
                json=envelope.model_dump(mode="json"),
            )
            response.raise_for_status()
    except httpx.HTTPError as exc:
        device_registry.record_rejected(envelope.device_id)
        prometheus_metrics.rejected(RejectionReason.FORWARD_FAILED, envelope.device_id)
        logger.error(
            "[EDGE GATEWAY] Failed to forward message_id=%s to Data Diode: %s",
            envelope.message_id,
            exc,
            extra=log_context(
                "forward_failed",
                message_id=envelope.message_id,
                device_id=envelope.device_id,
                correlation_id=envelope.message_id,
            ),
        )
        audit_log.append(
            event_type="SIGNED_ENVELOPE_FORWARD",
            result="REJECTED",
            reason=RejectionReason.FORWARD_FAILED,
            message_id=envelope.message_id,
            device_id=envelope.device_id,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "status": "rejected",
                "reason": RejectionReason.FORWARD_FAILED,
            },
        ) from exc

    logger.info(
        "[EDGE GATEWAY] Forwarded message_id=%s to Data Diode",
        envelope.message_id,
    )
    audit_log.append(
        event_type="SIGNED_ENVELOPE_FORWARD",
        result="ACCEPTED",
        message_id=envelope.message_id,
        device_id=envelope.device_id,
    )
    device_registry.record_forwarded(envelope.device_id)
    prometheus_metrics.forwarded(envelope.device_id, envelope.priority)
    prometheus_metrics.transmitted_bytes.labels("edge-gateway").inc(
        envelope.estimated_transmission_cost
    )
    logger.info(
        "Envelope forwarded to software data diode",
        extra=log_context(
            "envelope_forwarded",
            message_id=envelope.message_id,
            device_id=envelope.device_id,
            correlation_id=envelope.message_id,
            priority=envelope.priority,
        ),
    )
    return {
        "status": "forwarded",
        "message_id": str(envelope.message_id),
        "sequence_number": str(envelope.sequence_number),
        "priority": envelope.priority,
    }


def _build_signed_envelope(
    message: EdgeTelemetryMessage,
    priority: PriorityLevel,
    estimated_transmission_cost: float,
    *,
    message_id=None,
    include_source_timestamp: bool = False,
) -> SecureTelemetryEnvelope:
    global _last_envelope_created_at
    created_at = datetime.now(timezone.utc)
    if _last_envelope_created_at is not None and created_at <= _last_envelope_created_at:
        created_at = _last_envelope_created_at + timedelta(microseconds=1)
    _last_envelope_created_at = created_at
    payload = TelemetryPayload(
        temperature=message.temperature,
        humidity=message.humidity,
        status=message.status,
        event_type=message.event_type,
        telemetry_type=message.telemetry_type,
        cpu_usage=message.cpu_usage,
        memory_usage=message.memory_usage,
        measurements=message.measurements,
        attributes={**message.attributes, "source_timestamp": message.timestamp.isoformat()}
        if include_source_timestamp else message.attributes,
        aggregation=message.aggregation,
    )
    unsigned = SecureTelemetryEnvelope(
        message_id=message_id or uuid4(),
        device_id=message.device_id,
        created_at=created_at,
        sequence_number=device_registry.next_sequence(message.device_id),
        priority=priority,
        payload=payload,
        payload_hash=compute_payload_hash(payload),
        signature="unsigned",
        estimated_transmission_cost=estimated_transmission_cost,
        schema_version="2.0" if include_source_timestamp else "1.0",
    )
    signature = sign_envelope(unsigned, _get_private_key())
    return unsigned.model_copy(update={"signature": signature})


def _get_private_key():
    global _private_key
    if _private_key is None:
        _private_key = load_private_key(EDGE_PRIVATE_KEY_PATH)
    return _private_key


def _timestamp_fresh(timestamp: datetime, freshness_seconds: float) -> bool:
    now = datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    age_seconds = (now - timestamp).total_seconds()
    return -30 <= age_seconds <= freshness_seconds


async def _observability_loop() -> None:
    while True:
        await asyncio.sleep(OBSERVABILITY_INTERVAL_SECONDS)
        snapshot = ObservabilitySnapshot(
            timestamp=datetime.now(timezone.utc),
            service="edge-gateway",
            metrics={
                "information_policy": information_engine.snapshot(time.monotonic()) if INFORMATION_POLICY_ENABLED else None,
                "traffic": traffic_metrics.snapshot(),
                "devices": [
                    item.model_dump(mode="json") for item in device_registry.snapshots()
                ],
            },
        )
        try:
            async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    DATA_DIODE_METRICS_URL,
                    json=snapshot.model_dump(mode="json"),
                    headers={"x-observability-token": OBSERVABILITY_TOKEN},
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning(
                "Unable to publish observability snapshot: %s",
                exc,
                extra=log_context("observability_publish_failed"),
            )


async def process_information_message() -> bool:
    global _pending_envelope
    if _pending_envelope is None:
        item = information_engine.pop(time.monotonic())
        if item is None:
            return False
        # Transport retries retain the signed identity and never change policy weights.
        _pending_envelope = _build_signed_envelope(
            item.message, item.priority, item.size_bytes,
            message_id=item.message_id, include_source_timestamp=True,
        )
    envelope = _pending_envelope
    try:
        async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT_SECONDS) as client:
            response = await client.post(DATA_DIODE_URL, json=envelope.model_dump(mode="json"))
            response.raise_for_status()
    except httpx.HTTPError as exc:
        device_registry.record_rejected(envelope.device_id)
        prometheus_metrics.rejected(RejectionReason.FORWARD_FAILED, envelope.device_id)
        audit_log.append(
            "LOCAL_HANDOFF", "FAILED", reason=str(exc),
            message_id=envelope.message_id, device_id=envelope.device_id,
        )
        if isinstance(exc, httpx.HTTPStatusError) and 400 <= exc.response.status_code < 500 and exc.response.status_code not in {408, 429}:
            _pending_envelope = None
        await asyncio.sleep(0.25)
        return False
    _pending_envelope = None
    device_registry.record_forwarded(envelope.device_id)
    prometheus_metrics.forwarded(envelope.device_id, envelope.priority)
    prometheus_metrics.transmitted_bytes.labels("edge-gateway").inc(len(envelope.model_dump_json().encode("utf-8")))
    audit_log.append("LOCAL_HANDOFF", "ACCEPTED", message_id=envelope.message_id, device_id=envelope.device_id)
    return True


async def _information_loop() -> None:
    while True:
        try:
            await process_information_message()
        except Exception:
            logger.exception("Information policy dispatch failed")
        await asyncio.sleep(0.01)


def _coverage_admission_done(task):
    _coverage_admissions.discard(task)
    if not task.cancelled():
        task.exception()


async def _receive_coverage(message, epoch, retry_sequence):
    from shared.coverage.ledger import LedgerRefused
    if _coverage_ledger is None:
        raise HTTPException(status_code=503, detail="coverage ledger not initialized")
    if len(_coverage_admissions) >= 8:
        raise HTTPException(status_code=429, detail="coverage admission workers busy")
    if isinstance(retry_sequence, str):
        if not re.fullmatch(r"[1-9][0-9]{0,18}", retry_sequence):
            raise HTTPException(status_code=422, detail="invalid local retry sequence")
        retry_sequence = int(retry_sequence)
    task = asyncio.create_task(asyncio.to_thread(
        _coverage_ledger.admit, message, expected_epoch=epoch, retry_sequence=retry_sequence,
        freshness_seconds=EDGE_INPUT_FRESHNESS_SECONDS,
    ))
    _coverage_admissions.add(task)
    task.add_done_callback(_coverage_admission_done)
    try:
        receipt = await asyncio.shield(task)
    except LedgerRefused as exc:
        raise HTTPException(status_code=exc.http_status,
                            detail={"status": "refused", "reason": exc.reason}) from exc
    except Exception as exc:
        logger.exception("Coverage admission failed; acceptance not acknowledged")
        raise HTTPException(status_code=503, detail="durable admission unavailable") from exc
    if not receipt.duplicate:
        priority = classify_priority(message, priority_config)
        device_registry.record_received(message.device_id, priority)
        prometheus_metrics.received(message.device_id, priority)
    return {"status": "accepted", "mode": "ledger-only", **receipt.model_dump(mode="json")}


async def _coverage_clock_loop():
    while True:
        try:
            await asyncio.to_thread(_coverage_ledger.tick)
        except Exception:
            logger.exception("Coverage closure failed; ledger requires recovery")
            return
        await asyncio.sleep(0.1)

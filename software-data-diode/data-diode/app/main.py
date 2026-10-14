import asyncio
from collections import defaultdict, deque
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
import logging
from ipaddress import ip_address, ip_network
import hmac
import os
import time

import httpx
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import Response
from pydantic import ValidationError

from shared.models import ObservabilitySnapshot, RejectionReason, SecureTelemetryEnvelope
from shared.coverage.transport_mode import research_udp_enabled
from shared.http import peer_allowed, read_bounded_body, strict_json
from shared.observability import ServiceMetrics, configure_json_logging, log_context
from shared.security import AuditLog, TokenBucketRateLimiter, verify_audit_log
from shared.traffic import (
    AdaptiveScheduler,
    BoundedMessageQueue,
    CongestionMonitor,
    TrafficMetrics,
    load_scheduler_weights_from_env,
)

configure_json_logging("data-diode")
logger = logging.getLogger("data-diode")

FOG_RECEIVER_URL = os.getenv(
    "FOG_RECEIVER_URL",
    "http://fog-receiver:8000/receive",
)
FORWARD_TIMEOUT_SECONDS = float(os.getenv("FORWARD_TIMEOUT_SECONDS", "5"))
DIODE_INGEST_ALLOWED_CIDR = os.getenv("DIODE_INGEST_ALLOWED_CIDR", "0.0.0.0/0")
DIODE_ALLOWED_HOSTS = os.getenv("DIODE_ALLOWED_HOSTS", "")
MAX_MESSAGES_PER_SECOND = float(os.getenv("MAX_MESSAGES_PER_SECOND", "10"))
BURST_LIMIT = int(os.getenv("BURST_LIMIT", "20"))
MAX_PAYLOAD_BYTES = int(os.getenv("MAX_PAYLOAD_BYTES", "8192"))
MAX_QUEUE_SIZE = int(os.getenv("MAX_QUEUE_SIZE", "100"))
SCHEDULER_MODE = os.getenv("SCHEDULER_MODE", "adaptive").lower()
if os.getenv("INFORMATION_POLICY_ENABLED", "false").lower() == "true":
    SCHEDULER_MODE = "fifo"
EGRESS_MESSAGES_PER_SECOND = float(os.getenv("EGRESS_MESSAGES_PER_SECOND", "10"))
EGRESS_BURST_LIMIT = int(os.getenv("EGRESS_BURST_LIMIT", "10"))
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "logs/data-diode-audit.jsonl")
FOG_METRICS_URL = os.getenv(
    "FOG_METRICS_URL", "http://fog-receiver:8000/receive-metrics"
)
OBSERVABILITY_TOKEN = os.getenv("OBSERVABILITY_TOKEN", "phase5-internal-observability")

audit_log = AuditLog(AUDIT_LOG_PATH, "data-diode")
ingress_rate_limiter = TokenBucketRateLimiter(MAX_MESSAGES_PER_SECOND, BURST_LIMIT)
egress_rate_limiter = TokenBucketRateLimiter(EGRESS_MESSAGES_PER_SECOND, EGRESS_BURST_LIMIT)
queue_manager = BoundedMessageQueue(MAX_QUEUE_SIZE, preserve_device_order=True)
scheduler = AdaptiveScheduler(load_scheduler_weights_from_env())
congestion_monitor = CongestionMonitor()
traffic_metrics = TrafficMetrics()
prometheus_metrics = ServiceMetrics("data-diode")
_egress_task: asyncio.Task | None = None
_pending_message = None
scheduler_scores: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=200))
rejection_counts: dict[str, int] = defaultdict(int)
_research_udp = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _egress_task, _research_udp
    udp = research_udp_enabled()
    if udp:
        from shared.coverage.transport import TransportConfig
        from shared.coverage.udp_runtime import PassiveDiode
        config = TransportConfig.load(os.environ["COVERAGE_TRANSPORT_CONFIG"])
        _research_udp = PassiveDiode(config, link_capacity=int(os.environ["COVERAGE_LINK_BYTES_PER_SECOND"]))
        await _research_udp.start(9001)
        _egress_task = None
    else:
        _egress_task = asyncio.create_task(_egress_loop())
    try:
        yield
    finally:
        if _research_udp is not None:
            await _research_udp.close()
            _research_udp = None
        if _egress_task is not None:
            _egress_task.cancel()
            with suppress(asyncio.CancelledError):
                await _egress_task


app = FastAPI(title="Software Data Diode", version="0.3.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "data-diode"}


@app.get("/ready")
async def ready() -> dict[str, str]:
    if research_udp_enabled():
        if _research_udp is None or not _research_udp.status()["live"]:
            raise HTTPException(status_code=503, detail="local UDP forwarder unavailable")
        return {"status": "ready", "service": "data-diode", "assurance": "LOCAL_ONLY_NOT_FOG_READINESS"}
    if _egress_task is not None and _egress_task.done():
        raise HTTPException(status_code=503, detail="egress worker stopped")
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(FOG_RECEIVER_URL.rsplit("/", 1)[0] + "/ready")
            response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("[DATA DIODE] Readiness check failed: %s", exc)
        raise HTTPException(status_code=503, detail="fog receiver unavailable") from exc
    return {"status": "ready", "service": "data-diode"}


@app.get("/metrics")
async def prometheus() -> Response:
    valid, _ = await asyncio.to_thread(verify_audit_log, AUDIT_LOG_PATH)
    prometheus_metrics.audit_log_valid.labels("data-diode").set(1 if valid else 0)
    body, content_type = prometheus_metrics.render()
    return Response(content=body, media_type=content_type)


@app.get("/metrics/runtime")
async def metrics() -> dict[str, object]:
    if research_udp_enabled():
        return _research_udp.status() if _research_udp else {"live": False}
    congestion_snapshot = congestion_monitor.snapshot(len(queue_manager), MAX_QUEUE_SIZE)
    traffic_metrics.update_queue_state(
        len(queue_manager),
        MAX_QUEUE_SIZE,
        congestion_snapshot["congestion_state"],
    )
    return {
        "scheduler_mode": SCHEDULER_MODE,
        "queue": congestion_snapshot,
        "traffic": traffic_metrics.snapshot(),
    }


@app.post("/ingest")
async def ingest_telemetry(request: Request) -> dict[str, str]:
    if research_udp_enabled():
        raise HTTPException(status_code=404, detail="HTTP forwarding disabled in research mode")
    client_host = request.client.host if request.client else ""
    if not _client_allowed(client_host, DIODE_INGEST_ALLOWED_CIDR) or not await peer_allowed(client_host, DIODE_ALLOWED_HOSTS):
        logger.warning("[DATA DIODE] Rejected request from unauthorized source=%s", client_host)
        _audit_rejection(RejectionReason.UNAUTHORIZED_SOURCE)
        _raise_rejection(status.HTTP_403_FORBIDDEN, RejectionReason.UNAUTHORIZED_SOURCE)

    if not ingress_rate_limiter.allow():
        logger.warning("[DATA DIODE] Rejected request because rate limit was exceeded")
        _audit_rejection(RejectionReason.RATE_LIMIT_EXCEEDED)
        _raise_rejection(status.HTTP_429_TOO_MANY_REQUESTS, RejectionReason.RATE_LIMIT_EXCEEDED)

    try:
        body = await read_bounded_body(request, MAX_PAYLOAD_BYTES)
    except HTTPException:
        _audit_rejection(RejectionReason.PAYLOAD_TOO_LARGE)
        raise
    body_size = len(body)
    if body_size > MAX_PAYLOAD_BYTES:
        logger.warning(
            "[DATA DIODE] Rejected oversized request size=%s max=%s",
            body_size,
            MAX_PAYLOAD_BYTES,
        )
        _audit_rejection(RejectionReason.PAYLOAD_TOO_LARGE)
        _raise_rejection(413, RejectionReason.PAYLOAD_TOO_LARGE)

    try:
        message = SecureTelemetryEnvelope.model_validate(strict_json(body))
    except (ValidationError, ValueError, RecursionError):
        logger.warning("[DATA DIODE] Rejected malformed or invalid envelope")
        _audit_rejection(RejectionReason.INVALID_SCHEMA)
        _raise_rejection(422, RejectionReason.INVALID_SCHEMA)

    prometheus_metrics.received(message.device_id, message.priority)

    congestion_monitor.record_incoming()
    push_result = queue_manager.push(message, body_size, reserved=int(_pending_message is not None))
    if push_result.accepted and push_result.dropped is not None:
        dropped = push_result.dropped
        traffic_metrics.record_dropped(dropped.envelope.priority)
        prometheus_metrics.dropped_messages.labels(
            "data-diode", str(dropped.envelope.priority)
        ).inc()
        audit_log.append(
            event_type="QUEUE_DROP",
            result="DROPPED",
            reason=push_result.reason,
            message_id=dropped.envelope.message_id,
            device_id=dropped.envelope.device_id,
        )
        logger.warning(
            "[DATA DIODE] Dropped message_id=%s priority=%s reason=%s",
            dropped.envelope.message_id,
            dropped.envelope.priority,
            push_result.reason,
            extra=log_context(
                "queue_drop",
                message_id=dropped.envelope.message_id,
                device_id=dropped.envelope.device_id,
                correlation_id=dropped.envelope.message_id,
                priority=dropped.envelope.priority,
                reason=push_result.reason,
            ),
        )

    if not push_result.accepted:
        _audit_rejection(RejectionReason.QUEUE_FULL, message)
        traffic_metrics.record_dropped(message.priority)
        prometheus_metrics.dropped_messages.labels("data-diode", str(message.priority)).inc()
        _raise_rejection(status.HTTP_503_SERVICE_UNAVAILABLE, RejectionReason.QUEUE_FULL)

    traffic_metrics.record_queued(message.priority)
    _update_queue_metrics()
    logger.info(
        "[DATA DIODE] Queued message_id=%s priority=%s queue_length=%s",
        message.message_id,
        message.priority,
        len(queue_manager),
    )
    audit_log.append(
        event_type="ENVELOPE_QUEUED",
        result="ACCEPTED",
        message_id=message.message_id,
        device_id=message.device_id,
    )
    return {
        "status": "queued",
        "message_id": str(message.message_id),
        "priority": message.priority,
        "queue_length": str(len(queue_manager)),
    }


@app.post("/ingest-metrics")
async def ingest_metrics(snapshot: ObservabilitySnapshot, request: Request) -> dict[str, str]:
    if research_udp_enabled():
        raise HTTPException(status_code=404, detail="cross-boundary HTTP observability disabled")
    if not await peer_allowed(request.client.host if request.client else "", DIODE_ALLOWED_HOSTS):
        raise HTTPException(status_code=403, detail="unauthorized source")
    supplied_token = request.headers.get("x-observability-token", "")
    if not hmac.compare_digest(supplied_token, OBSERVABILITY_TOKEN):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid token")

    snapshots = [snapshot, _observability_snapshot()]
    try:
        async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT_SECONDS) as client:
            for item in snapshots:
                response = await client.post(
                    FOG_METRICS_URL,
                    json=item.model_dump(mode="json"),
                    headers={"x-observability-token": OBSERVABILITY_TOKEN},
                )
                response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.error(
            "Observability snapshot forwarding failed: %s",
            exc,
            extra=log_context("observability_forward_failed"),
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="Fog metrics receiver unavailable"
        ) from exc
    return {"status": "forwarded", "service": snapshot.service}


async def process_next_message() -> bool:
    if research_udp_enabled():
        return False
    global _pending_message
    now = time.monotonic()
    congestion_state = congestion_monitor.state(len(queue_manager), MAX_QUEUE_SIZE)
    if _pending_message is not None:
        item = _pending_message
    elif SCHEDULER_MODE == "fifo":
        item = queue_manager.pop_fifo()
    else:
        item = queue_manager.pop_adaptive(scheduler, now, congestion_state)

    if item is None:
        _update_queue_metrics()
        return False
    _pending_message = item

    selected_score = scheduler.score(item, now, congestion_state)
    scheduler_scores[str(item.envelope.priority)].append(selected_score)
    prometheus_metrics.scheduler_score.labels(
        "data-diode", str(item.envelope.priority)
    ).observe(selected_score)

    logger.info(
        "[DATA DIODE] Scheduler selected message_id=%s priority=%s mode=%s",
        item.envelope.message_id,
        item.envelope.priority,
        SCHEDULER_MODE,
    )

    try:
        async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT_SECONDS) as client:
            response = await client.post(
                FOG_RECEIVER_URL,
                json=item.envelope.model_dump(mode="json"),
            )
            if not (getattr(response, "status_code", 200) == 409 and
                    response.headers.get("X-Previously-Accepted") == "true"):
                response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.error(
            "[DATA DIODE] Failed to forward message_id=%s to Fog Receiver: %s",
            item.envelope.message_id,
            exc,
        )
        response = exc.response if isinstance(exc, httpx.HTTPStatusError) else None
        transient = response is None or response.status_code in {408, 429} or response.status_code >= 500
        if transient:
            audit_log.append("ENVELOPE_FORWARD", "RETRY", reason=RejectionReason.FORWARD_FAILED,
                             message_id=item.envelope.message_id, device_id=item.envelope.device_id)
            _update_queue_metrics()
            return False
        _pending_message = None
        traffic_metrics.record_dropped(item.envelope.priority)
        prometheus_metrics.rejected(RejectionReason.FORWARD_FAILED, item.envelope.device_id)
        prometheus_metrics.dropped_messages.labels(
            "data-diode", str(item.envelope.priority)
        ).inc()
        audit_log.append(
            event_type="ENVELOPE_FORWARD",
            result="REJECTED",
            reason=RejectionReason.FORWARD_FAILED,
            message_id=item.envelope.message_id,
            device_id=item.envelope.device_id,
        )
        _update_queue_metrics()
        return False

    _pending_message = None
    queue_wait = max(now - item.enqueued_at, 0.0)
    created_at = item.envelope.created_at
    source_timestamp = item.envelope.payload.attributes.get("source_timestamp")
    if item.envelope.schema_version == "2.0" and isinstance(source_timestamp, str):
        try:
            created_at = datetime.fromisoformat(source_timestamp.replace("Z", "+00:00"))
        except ValueError:
            pass
        if item.envelope.payload.aggregation and item.envelope.payload.aggregation.window_start:
            created_at = item.envelope.payload.aggregation.window_start
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    end_to_end_latency = max(
        (datetime.now(timezone.utc) - created_at).total_seconds(), queue_wait
    )
    congestion_monitor.record_outgoing(end_to_end_latency)
    traffic_metrics.record_delivered(
        item.envelope.priority,
        item.size_bytes,
        end_to_end_latency,
        queue_wait,
    )
    prometheus_metrics.forwarded(item.envelope.device_id, item.envelope.priority)
    prometheus_metrics.queue_wait.labels(
        "data-diode", str(item.envelope.priority)
    ).observe(queue_wait)
    prometheus_metrics.end_to_end_latency.labels(
        "data-diode", str(item.envelope.priority)
    ).observe(end_to_end_latency)
    prometheus_metrics.transmitted_bytes.labels("data-diode").inc(item.size_bytes)
    audit_log.append(
        event_type="ENVELOPE_FORWARD",
        result="ACCEPTED",
        message_id=item.envelope.message_id,
        device_id=item.envelope.device_id,
    )
    _update_queue_metrics()
    logger.info(
        "[DATA DIODE] Forwarded message_id=%s priority=%s wait=%.3fs",
        item.envelope.message_id,
        item.envelope.priority,
        queue_wait,
        extra=log_context(
            "envelope_forwarded",
            message_id=item.envelope.message_id,
            device_id=item.envelope.device_id,
            correlation_id=item.envelope.message_id,
            priority=item.envelope.priority,
            queue_wait_seconds=queue_wait,
            scheduler_score=selected_score,
        ),
    )
    return True


async def _egress_loop() -> None:
    while True:
        try:
            if egress_rate_limiter.allow() and await process_next_message():
                continue
        except Exception:
            logger.exception("Egress iteration failed; retaining pending message")
        await asyncio.sleep(0.25)


def _client_allowed(client_host: str, allowed_cidr: str) -> bool:
    if allowed_cidr in {"*", "0.0.0.0/0", "::/0"}:
        return True
    try:
        return ip_address(client_host) in ip_network(allowed_cidr, strict=False)
    except ValueError:
        return False


def _audit_rejection(
    reason: RejectionReason,
    message: SecureTelemetryEnvelope | None = None,
) -> None:
    rejection_counts[str(reason)] += 1
    prometheus_metrics.rejected(reason, message.device_id if message else "")
    audit_log.append(
        event_type="ENVELOPE_INGEST",
        result="REJECTED",
        reason=reason,
        message_id=message.message_id if message else None,
        device_id=message.device_id if message else None,
    )


def _raise_rejection(http_status: int, reason: RejectionReason) -> None:
    raise HTTPException(
        status_code=http_status,
        detail={"status": "rejected", "reason": reason},
    )


def _update_queue_metrics() -> None:
    depth = len(queue_manager) + int(_pending_message is not None)
    congestion_state = congestion_monitor.state(depth, MAX_QUEUE_SIZE)
    traffic_metrics.update_queue_state(depth, MAX_QUEUE_SIZE, congestion_state)
    prometheus_metrics.queue_size.labels("data-diode").set(depth)


def _observability_snapshot() -> ObservabilitySnapshot:
    congestion = congestion_monitor.snapshot(len(queue_manager) + int(_pending_message is not None), MAX_QUEUE_SIZE)
    return ObservabilitySnapshot(
        timestamp=datetime.now(timezone.utc),
        service="data-diode",
        metrics={
            "scheduler_mode": SCHEDULER_MODE,
            "queue": congestion,
            "traffic": traffic_metrics.snapshot(),
            "scheduler_scores": {
                priority: list(scores) for priority, scores in scheduler_scores.items()
            },
            "security_rejections": dict(rejection_counts),
        },
    )

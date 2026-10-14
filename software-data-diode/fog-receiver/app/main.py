import asyncio
from contextlib import asynccontextmanager
import logging
from ipaddress import ip_address, ip_network
import hmac
import os
from collections import OrderedDict

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.responses import Response
from pydantic import ValidationError

from shared.models import ObservabilitySnapshot, RejectionReason, SecureTelemetryEnvelope
from shared.coverage.transport_mode import research_udp_enabled
from shared.http import peer_allowed, read_bounded_body, strict_json
from shared.observability import ServiceMetrics, configure_json_logging, log_context
from shared.persistence import repository_from_env
from shared.security import (
    AuditLog,
    ReplayDetector,
    compute_payload_hash,
    load_public_key,
    verify_envelope_signature,
    verify_audit_log,
    validate_reverse_path,
)

configure_json_logging("fog-receiver")
logger = logging.getLogger("fog-receiver")

FOG_RECEIVE_ALLOWED_CIDR = os.getenv("FOG_RECEIVE_ALLOWED_CIDR", "0.0.0.0/0")
FOG_ALLOWED_HOSTS = os.getenv("FOG_ALLOWED_HOSTS", "")
MAX_PAYLOAD_BYTES = int(os.getenv("MAX_PAYLOAD_BYTES", "8192"))
FOG_PUBLIC_KEY_PATH = os.getenv("FOG_PUBLIC_KEY_PATH", "/run/secrets/edge_public_key.pem")
FOG_FRESHNESS_WINDOW_SECONDS = float(os.getenv("FOG_FRESHNESS_WINDOW_SECONDS", "300"))
DUPLICATE_TTL_SECONDS = float(os.getenv("DUPLICATE_TTL_SECONDS", "600"))
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "logs/fog-receiver-audit.jsonl")
EVENT_PROCESSOR_URL = os.getenv("EVENT_PROCESSOR_URL", "")
FORWARD_TIMEOUT_SECONDS = float(os.getenv("FORWARD_TIMEOUT_SECONDS", "5"))
OBSERVABILITY_TOKEN = os.getenv("OBSERVABILITY_TOKEN", "phase5-internal-observability")
SECURITY_TEST_MODE = os.getenv("SECURITY_TEST_MODE", "false").lower() == "true"

_research_udp = None


@asynccontextmanager
async def lifespan(app):
    global _research_udp
    if research_udp_enabled():
        from shared.coverage.transport import load_framer
        from shared.coverage.fog_store import FogEvidenceStore
        from shared.persistence.repository import PostgresRepository
        from shared.coverage.udp_runtime import FogUDP
        framer = load_framer(os.environ["COVERAGE_TRUST_PATH"], _get_public_key(),
            os.environ["COVERAGE_CONTRACT_PATH"], os.environ["COVERAGE_TRANSPORT_CONFIG"])
        if not isinstance(repository, PostgresRepository):
            raise RuntimeError("N6 requires PostgreSQL configuration; no in-memory evidence fallback")
        monitor = None
        if os.getenv("COVERAGE_RULE_MONITOR_CONFIG"):
            from shared.coverage.monitoring import CoverageMonitor, MonitoringConfig
            monitor = CoverageMonitor(framer,MonitoringConfig.load(os.environ["COVERAGE_RULE_MONITOR_CONFIG"]))
        store = await asyncio.to_thread(FogEvidenceStore, os.environ["COVERAGE_REPLAY_PATH"], framer)
        _research_udp = FogUDP(framer, store, repository, EVENT_PROCESSOR_URL, monitor=monitor)
    try:
        if _research_udp is not None:
            await _research_udp.start()
        yield
    finally:
        if _research_udp is not None:
            await _research_udp.close()
            await asyncio.to_thread(_research_udp.store.close)
            _research_udp = None


app = FastAPI(title="Fog Receiver", version="0.4.0", lifespan=lifespan)
audit_log = AuditLog(AUDIT_LOG_PATH, "fog-receiver")
replay_detector = ReplayDetector(DUPLICATE_TTL_SECONDS, FOG_FRESHNESS_WINDOW_SECONDS)
_public_key = None
repository = repository_from_env()
prometheus_metrics = ServiceMetrics("fog-receiver")
_receive_lock = asyncio.Lock()
_completed = OrderedDict()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "fog-receiver"}


@app.get("/ready")
async def ready() -> dict[str, str]:
    if research_udp_enabled():
        local = await asyncio.to_thread(_research_udp.status) if _research_udp is not None else {}
        if not local.get("live") or not local.get("local_admission_available"):
            raise HTTPException(status_code=503, detail="local research intake unavailable")
        return {"status": "ready", "service": "fog-receiver", "assurance": "LOCAL_INTAKE_NOT_PIPELINE_DELIVERY"}
    try:
        _get_public_key()
        if not await asyncio.to_thread(repository.healthcheck):
            raise RuntimeError("database unavailable")
        if EVENT_PROCESSOR_URL:
            async with httpx.AsyncClient(timeout=2.0) as client:
                response = await client.get(EVENT_PROCESSOR_URL.rsplit("/", 1)[0] + "/ready")
                response.raise_for_status()
    except (OSError, ValueError, TypeError, RuntimeError, httpx.HTTPError) as exc:
        logger.warning("[FOG RECEIVER] Readiness check failed: %s", exc)
        raise HTTPException(status_code=503, detail="receiver dependency unavailable") from exc
    return {"status": "ready", "service": "fog-receiver"}


@app.get("/metrics")
async def prometheus() -> Response:
    valid, _ = await asyncio.to_thread(verify_audit_log, AUDIT_LOG_PATH)
    prometheus_metrics.audit_log_valid.labels("fog-receiver").set(1 if valid else 0)
    body, content_type = prometheus_metrics.render()
    return Response(content=body, media_type=content_type)


@app.post("/receive")
async def receive_telemetry(request: Request) -> dict[str, str]:
    if research_udp_enabled():
        raise HTTPException(status_code=404, detail="HTTP research intake disabled")
    client_host = request.client.host if request.client else ""
    if not _client_allowed(client_host, FOG_RECEIVE_ALLOWED_CIDR) or not await peer_allowed(client_host, FOG_ALLOWED_HOSTS):
        logger.warning("[FOG RECEIVER] Rejected request from unauthorized source=%s", client_host)
        await asyncio.to_thread(_audit_rejection, RejectionReason.UNAUTHORIZED_SOURCE)
        _raise_rejection(status.HTTP_403_FORBIDDEN, RejectionReason.UNAUTHORIZED_SOURCE)

    try:
        body = await read_bounded_body(request, MAX_PAYLOAD_BYTES)
    except HTTPException:
        await asyncio.to_thread(_audit_rejection, RejectionReason.PAYLOAD_TOO_LARGE)
        raise
    try:
        envelope = SecureTelemetryEnvelope.model_validate(strict_json(body))
    except (ValidationError, ValueError, RecursionError):
        logger.warning("[FOG RECEIVER] Rejected malformed or invalid envelope")
        await asyncio.to_thread(_audit_rejection, RejectionReason.INVALID_SCHEMA)
        _raise_rejection(422, RejectionReason.INVALID_SCHEMA)

    expected_hash = compute_payload_hash(envelope.payload)
    if envelope.payload_hash != expected_hash:
        logger.warning(
            "[FOG RECEIVER] Hash mismatch message_id=%s expected=%s received=%s",
            envelope.message_id,
            expected_hash,
            envelope.payload_hash,
        )
        await asyncio.to_thread(_audit_rejection, RejectionReason.HASH_MISMATCH, envelope)
        _raise_rejection(status.HTTP_400_BAD_REQUEST, RejectionReason.HASH_MISMATCH)

    if not verify_envelope_signature(envelope, _get_public_key()):
        logger.warning("[FOG RECEIVER] Invalid signature message_id=%s", envelope.message_id)
        await asyncio.to_thread(_audit_rejection, RejectionReason.INVALID_SIGNATURE, envelope)
        _raise_rejection(status.HTTP_400_BAD_REQUEST, RejectionReason.INVALID_SIGNATURE)

    # Serialize admission through completion: failed downstream processing must
    # not consume the sequence and turn a legitimate retry into a replay.
    async with _receive_lock:
        return await _accept_verified(envelope)


async def _accept_verified(envelope):
    replay_reason = replay_detector.check_and_record(envelope, record=False)
    if replay_reason is not None:
        logger.warning(
            "[FOG RECEIVER] Replay protection rejected message_id=%s reason=%s",
            envelope.message_id,
            replay_reason,
        )
        await asyncio.to_thread(_audit_rejection, replay_reason, envelope)
        if replay_reason == RejectionReason.DUPLICATE_MESSAGE and _completed.get(str(envelope.message_id)) == envelope.signature:
            raise HTTPException(409, detail={"status": "rejected", "reason": replay_reason},
                                headers={"X-Previously-Accepted": "true"})
        _raise_rejection(status.HTTP_409_CONFLICT, replay_reason)

    prometheus_metrics.received(envelope.device_id, envelope.priority)
    logger.info("[FOG RECEIVER] Successfully received telemetry")
    logger.info(
        "[FOG RECEIVER] message_id=%s device=%s sequence=%s temperature=%.2f "
        "humidity=%.2f status=%s created_at=%s",
        envelope.message_id,
        envelope.device_id,
        envelope.sequence_number,
        envelope.payload.temperature,
        envelope.payload.humidity,
        envelope.payload.status,
        envelope.created_at.isoformat(),
        extra=log_context(
            "envelope_verified",
            message_id=envelope.message_id,
            device_id=envelope.device_id,
            correlation_id=envelope.message_id,
            priority=envelope.priority,
        ),
    )
    audit_log.append(
        event_type="ENVELOPE_VERIFY",
        result="ACCEPTED",
        message_id=envelope.message_id,
        device_id=envelope.device_id,
    )
    if EVENT_PROCESSOR_URL:
        try:
            async with httpx.AsyncClient(timeout=FORWARD_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    EVENT_PROCESSOR_URL,
                    json=envelope.model_dump(mode="json"),
                )
                response.raise_for_status()
                prometheus_metrics.forwarded(envelope.device_id, envelope.priority)
        except httpx.HTTPError as exc:
            logger.error("[FOG RECEIVER] Event Processor unavailable: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={"status": "rejected", "reason": RejectionReason.FORWARD_FAILED},
            ) from exc
    replay_detector.record(envelope)
    _completed[str(envelope.message_id)] = envelope.signature
    while len(_completed) > 10000:
        _completed.popitem(last=False)
    return {
        "status": "accepted",
        "message_id": str(envelope.message_id),
        "sequence_number": str(envelope.sequence_number),
    }


@app.post("/receive-metrics")
async def receive_metrics(snapshot: ObservabilitySnapshot, request: Request) -> dict[str, str]:
    if research_udp_enabled():
        raise HTTPException(status_code=404, detail="unsigned cross-boundary state disabled")
    supplied_token = request.headers.get("x-observability-token", "")
    if not hmac.compare_digest(supplied_token, OBSERVABILITY_TOKEN):
        prometheus_metrics.rejected(RejectionReason.UNAUTHORIZED_SOURCE)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid token")
    try:
        await asyncio.to_thread(repository.save_observability_snapshot, snapshot)
    except Exception as exc:
        logger.exception("[FOG RECEIVER] Metrics persistence failed")
        raise HTTPException(status_code=503, detail="database unavailable") from exc
    return {"status": "stored", "service": snapshot.service}


@app.post("/security-test/reverse-path")
async def security_test_reverse_path() -> dict[str, object]:
    if not SECURITY_TEST_MODE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return await asyncio.to_thread(validate_reverse_path)


def _get_public_key():
    global _public_key
    if _public_key is None:
        _public_key = load_public_key(FOG_PUBLIC_KEY_PATH)
    return _public_key


@app.get("/research/status")
async def research_status():
    if _research_udp is None:
        raise HTTPException(status_code=404, detail="research mode not active")
    result = await asyncio.to_thread(_research_udp.status)
    try:
        result.update(await asyncio.to_thread(repository.coverage_status))
    except Exception:
        result["postgres_verification_status"] = "UNAVAILABLE_NOT_ACKNOWLEDGED"
    result["rule_evaluation"] = _coverage_rule_mode()
    return result


def _coverage_rule_mode():
    from shared.coverage.monitoring import CoverageMonitor
    return "RCCD_SCOPED_RULES_V1" if isinstance(getattr(_research_udp,"coverage_monitor",None),CoverageMonitor) else "NOT_IMPLEMENTED_N6"


@app.get("/research/evidence")
async def research_evidence(limit: int = Query(default=20, ge=1, le=100)):
    if _research_udp is None:
        raise HTTPException(status_code=404, detail="research mode not active")
    try:
        return {"evidence": await asyncio.to_thread(repository.coverage_evidence, limit),
                "rule_evaluation": _coverage_rule_mode()}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="durable evidence repository unavailable") from exc


@app.get("/research/rules")
async def research_rules(limit: int = Query(default=20,ge=1,le=100), history: bool = False):
    if _research_udp is None:
        raise HTTPException(status_code=404,detail="research mode not active")
    try:
        return {"mode":"RCCD_SCOPED_RULES_V1","decisions":await asyncio.to_thread(repository.coverage_rules,limit,history)}
    except Exception as exc:
        raise HTTPException(status_code=503,detail="durable rule repository unavailable") from exc


def _client_allowed(client_host: str, allowed_cidr: str) -> bool:
    if allowed_cidr in {"*", "0.0.0.0/0", "::/0"}:
        return True
    try:
        return ip_address(client_host) in ip_network(allowed_cidr, strict=False)
    except ValueError:
        return False


def _audit_rejection(
    reason: RejectionReason,
    envelope: SecureTelemetryEnvelope | None = None,
) -> None:
    prometheus_metrics.rejected(reason, envelope.device_id if envelope else "")
    if reason == RejectionReason.INVALID_SIGNATURE:
        prometheus_metrics.signature_failures.labels("fog-receiver").inc()
    if reason in {RejectionReason.REPLAY_DETECTED, RejectionReason.DUPLICATE_MESSAGE}:
        prometheus_metrics.replay_attempts.labels("fog-receiver", str(reason)).inc()
    audit_log.append(
        event_type="ENVELOPE_VERIFY",
        result="REJECTED",
        reason=reason,
        message_id=envelope.message_id if envelope else None,
        device_id=envelope.device_id if envelope else None,
    )
    try:
        repository.save_rejection(
            str(reason),
            envelope.message_id if envelope else None,
            envelope.device_id if envelope else None,
        )
    except Exception as exc:
        # Preserve the security decision and local audit evidence during a DB outage.
        logger.error("[FOG RECEIVER] Could not persist rejection metadata: %s", exc)


def _raise_rejection(http_status: int, reason: RejectionReason) -> None:
    raise HTTPException(
        status_code=http_status,
        detail={"status": "rejected", "reason": reason},
    )

import asyncio
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import httpx
from pydantic import ValidationError

from phase1.app import NEXT_HOP, ROUTES, UPSTREAM, resolve_peer
from phase1.pipeline import QueueFullError
from shared.security.audit import AuditLog, verify_audit_log
from shared.security.crypto import load_private_key, load_public_key
from shared.security.rate_limit import TokenBucketRateLimiter
from .models import SecureEnvelope, SourceMessage
from .pipeline import PermanentDeliveryError, SecurePipeline
from .security import Rejected, canonical, fingerprint, freshness, parse_json, sign, validate_payload, verify
from .state import SecurityState


def create_app(role, state_directory, public_key, *, private_key=None, resolver=resolve_peer,
               capacity=100, rate=20, burst=40, body_limit=8192, payload_limit=4096,
               freshness_seconds=120, future_skew=10, device_id="edge-device-01", transport=None):
    if role not in UPSTREAM or min(capacity, rate, burst, body_limit, payload_limit, freshness_seconds) <= 0:
        raise ValueError("invalid Phase 2 configuration")
    if future_skew < 0 or (role == "edge-gateway") != (private_key is not None):
        raise ValueError("only the Edge Gateway may hold a signing key; clock skew must be nonnegative")
    if private_key and private_key.public_key().public_bytes_raw() != public_key.public_bytes_raw():
        raise ValueError("signing and verification keys do not match")
    directory = Path(state_directory)
    directory.mkdir(parents=True, exist_ok=True)
    audit_path = directory / "audit.jsonl"
    valid, reason = verify_audit_log(audit_path)
    if not valid:
        raise ValueError(f"refusing to append to broken audit chain: {reason}")
    audit = AuditLog(audit_path, role)
    state = SecurityState(directory / "security.sqlite3")
    pipeline = SecurePipeline(role, state, audit, capacity=capacity, log_directory=directory)
    limiter = TokenBucketRateLimiter(rate, burst)

    @asynccontextmanager
    async def lifespan(app):
        task = None
        async with httpx.AsyncClient(timeout=3, transport=transport, trust_env=False) as client:
            async def sender(body):
                response = await client.post(NEXT_HOP[role], content=body,
                                             headers={"content-type": "application/json"})
                if 400 <= response.status_code < 500 and response.status_code not in {408, 429}:
                    raise PermanentDeliveryError(f"HTTP {response.status_code}: {response.text[:200]}")
                response.raise_for_status()
            if role in NEXT_HOP:
                task = asyncio.create_task(pipeline.run(sender))
            try:
                yield
            finally:
                if task:
                    task.cancel()
                    with suppress(asyncio.CancelledError):
                        await task
                state.close()

    app = FastAPI(title=f"Phase 2 {role}", lifespan=lifespan)
    app.state.pipeline, app.state.security, app.state.audit = pipeline, state, audit

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": role}

    @app.get("/metrics/runtime")
    async def metrics():
        return {**pipeline.snapshot(), "security": state.counters()}

    @app.get("/messages")
    async def messages(request: Request):
        if not request.client or request.client.host not in {"127.0.0.1", "::1"}:
            raise HTTPException(403, "container-local diagnostics only")
        return [json.loads(row["body"]) for row in reversed(state.recent())]

    @app.post(ROUTES[role])
    async def ingest(request: Request):
        arrival = datetime.now(timezone.utc)
        message = None
        try:
            # Bound work before DNS, parsing, cryptography, or untrusted audit details.
            if not limiter.allow():
                raise Rejected("RATE_LIMIT_EXCEEDED", 429)
            try:
                allowed = await resolver(UPSTREAM[role])
            except (OSError, TimeoutError):
                raise Rejected("UPSTREAM_IDENTITY_UNAVAILABLE", 503)
            if not request.client or request.client.host not in allowed:
                raise Rejected("UNAUTHORIZED_SOURCE", 403)
            body = bytearray()
            async for chunk in request.stream():
                if len(body) + len(chunk) > body_limit:
                    raise Rejected("PAYLOAD_TOO_LARGE", 413)
                body.extend(chunk)
            model = SourceMessage if role == "edge-gateway" else SecureEnvelope
            try:
                message = model.model_validate(parse_json(bytes(body)))
                canonical(message.model_dump(mode="json"))
            except (ValueError, ValidationError, RecursionError):
                raise Rejected("INVALID_SCHEMA", 422)
            if message.device_id != device_id:
                raise Rejected("UNKNOWN_DEVICE", 403)
            validate_payload(message, payload_limit)
            if role != "edge-gateway":
                verify(message, public_key, payload_limit)
            digest = fingerprint(message)
            previous = state.check(message, digest)
            if previous:
                # A lost HTTP acknowledgement must not deadlock the FIFO. Record the
                # duplicate but acknowledge the original admission without redelivery.
                if previous["status"] == "pending":
                    pipeline.admit(SecureEnvelope.model_validate_json(previous["body"]),
                                   datetime.fromisoformat(previous["arrival"]))
                audit.append("validation", "DUPLICATE_MESSAGE", message_id=message.message_id,
                             device_id=message.device_id)
                state.increment("DUPLICATE_MESSAGE")
                return JSONResponse({"status": "duplicate", "reason": "DUPLICATE_MESSAGE"}, status_code=200)
            freshness(message, freshness_seconds, future_skew)
            if role in NEXT_HOP and pipeline.queue_length >= capacity:
                raise Rejected("QUEUE_FULL", 503)
            envelope = sign(message, private_key) if role == "edge-gateway" else message
            audit.append("validation", "VALIDATED", message_id=message.message_id,
                         device_id=message.device_id, details={"sequence_number": message.sequence_number,
                                                             "payload_size": message.payload_size})
            state.accept(envelope, digest, canonical(envelope.model_dump(mode="json")).decode(), arrival,
                         receiver=role == "fog-receiver", retention=freshness_seconds + future_skew + 20)
            if role in NEXT_HOP:
                pipeline.admit(envelope, arrival)
            return JSONResponse({"status": "accepted", "message_id": str(message.message_id)}, status_code=202)
        except (Rejected, QueueFullError) as exc:
            reason, status = (exc.reason, exc.status) if isinstance(exc, Rejected) else ("QUEUE_FULL", 503)
            audit.append("validation", "REJECTED", reason,
                         message.message_id if message else None, message.device_id if message else None)
            state.increment(reason)
            return JSONResponse({"reason": reason}, status_code=status,
                                headers={"Retry-After": "1"} if status in {429, 503} else None)

    return app


def app_from_env():
    role = os.environ["PHASE2_ROLE"]
    return create_app(role, os.getenv("PHASE2_STATE_DIRECTORY", "/state"),
                      load_public_key("/public/edge_public.pem"),
                      private_key=load_private_key("/private/edge_private.pem") if role == "edge-gateway" else None,
                      capacity=int(os.getenv("PHASE2_QUEUE_CAPACITY", "100")),
                      rate=float(os.getenv("PHASE2_RATE", "20")), burst=int(os.getenv("PHASE2_BURST", "40")),
                      freshness_seconds=float(os.getenv("PHASE2_FRESHNESS_SECONDS", "120")))

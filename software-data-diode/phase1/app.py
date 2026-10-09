import asyncio
from collections import OrderedDict, deque
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import socket

from fastapi import FastAPI, HTTPException, Request
import httpx
from pydantic import ValidationError

from .models import Telemetry, TransferRecord
from .pipeline import IdentityConflictError, Pipeline, PolicyRejectedError, QueueFullError


UPSTREAM = {"edge-gateway": "edge-device", "unidirectional-gateway": "edge-gateway", "fog-receiver": "unidirectional-gateway"}
NEXT_HOP = {"edge-gateway": "http://unidirectional-gateway:8000/ingest", "unidirectional-gateway": "http://fog-receiver:8000/receive"}
ROUTES = {"edge-gateway": "/telemetry", "unidirectional-gateway": "/ingest", "fog-receiver": "/receive"}


async def resolve_peer(hostname: str) -> set[str]:
    loop = asyncio.get_running_loop()
    records = await asyncio.wait_for(loop.getaddrinfo(hostname, 8000, type=socket.SOCK_STREAM), timeout=2)
    return {record[4][0] for record in records}


def create_app(role: str, *, log_directory: Path | None = None,
               capacity: int = 100, max_body_bytes: int = 8192,
               resolver=resolve_peer, transport=None, components=None) -> FastAPI:
    if role not in UPSTREAM:
        raise ValueError("unknown Phase 1 service role")
    if max_body_bytes <= 0:
        raise ValueError("max_body_bytes must be positive")
    pipeline = Pipeline(role, capacity, components, log_directory)
    received = deque(maxlen=1000)
    receiver_ids = OrderedDict()
    receiver_count = 0
    logger = logging.getLogger(role)

    @asynccontextmanager
    async def lifespan(app):
        task = None
        async with httpx.AsyncClient(timeout=3, transport=transport, trust_env=False) as client:
            async def sender(body):
                response = await client.post(NEXT_HOP[role], content=body, headers={"content-type": "application/json"})
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

    app = FastAPI(title=f"Phase 1 {role}", lifespan=lifespan)
    app.state.pipeline = pipeline

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": role}

    @app.get("/metrics/runtime")
    async def metrics():
        return {**pipeline.snapshot(), "received_messages": receiver_count}

    @app.get("/messages")
    async def messages(request: Request):
        # Operator diagnostics stay container-local; peers receive no read API.
        if request.client is None or request.client.host not in {"127.0.0.1", "::1"}:
            raise HTTPException(403, "container-local diagnostics only")
        return list(received)

    @app.post(ROUTES[role], status_code=202)
    async def ingest(request: Request):
        nonlocal receiver_count
        arrival = datetime.now(timezone.utc)
        try:
            allowed = await resolver(UPSTREAM[role])
        except (OSError, TimeoutError):
            raise HTTPException(503, "upstream identity unavailable")
        if request.client is None or request.client.host not in allowed:
            raise HTTPException(403, "source is not the configured upstream service")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > max_body_bytes:
                raise HTTPException(413, "message exceeds body limit")
        try:
            message = Telemetry.model_validate_json(bytes(body))
        except ValidationError:
            raise HTTPException(422, "invalid telemetry schema")
        if role != "fog-receiver":
            try:
                admitted = pipeline.admit(message, arrival)
            except QueueFullError as exc:
                raise HTTPException(503, str(exc), headers={"Retry-After": "1"})
            except IdentityConflictError as exc:
                raise HTTPException(409, str(exc))
            except PolicyRejectedError as exc:
                raise HTTPException(403, str(exc))
            return {"status": "queued" if admitted else "duplicate", "message_id": str(message.message_id)}
        identifier, digest = str(message.message_id), Pipeline.digest(Pipeline.body(message))
        if identifier in receiver_ids:
            if receiver_ids[identifier] != digest:
                raise HTTPException(409, "message_id already belongs to different telemetry")
            return {"status": "duplicate", "message_id": identifier}
        record = TransferRecord(
            service=role, event="received", message_id=message.message_id,
            device_id=message.device_id, sequence_number=message.sequence_number,
            arrival_timestamp=arrival, queue_entry_timestamp=None, transmission_timestamp=None,
            message_size_bytes=len(Pipeline.body(message)), queue_length=0,
        ).model_dump(mode="json")
        document = message.model_dump(mode="json")
        if log_directory:
            with (log_directory / "fog-received.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"message": document, "instrumentation": record}, sort_keys=True) + "\n")
        received.append(document)
        pipeline.records.append(record)
        receiver_ids[identifier] = digest
        while len(receiver_ids) > 1000:
            receiver_ids.popitem(last=False)
        receiver_count += 1
        logger.info("Received message_id=%s device_id=%s sequence_number=%s", identifier, message.device_id, message.sequence_number)
        return {"status": "received", "message_id": identifier}

    return app


def app_from_env():
    return create_app(
        os.environ["PHASE1_ROLE"], log_directory=Path(os.getenv("PHASE1_LOG_DIRECTORY", "/logs")),
        capacity=int(os.getenv("PHASE1_QUEUE_CAPACITY", "100")),
        max_body_bytes=int(os.getenv("PHASE1_MAX_BODY_BYTES", "8192")),
    )

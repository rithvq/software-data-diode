"""Small HTTP boundary helpers shared by the service applications."""
import asyncio
import json
import socket

from fastapi import HTTPException
from starlette.responses import JSONResponse


class BodyLimitMiddleware:
    """Bound typed request bodies before FastAPI materializes or validates JSON."""

    def __init__(self, app, paths, limit=8192, timeout=10):
        self.app, self.paths, self.limit, self.timeout = app, set(paths), limit, timeout

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] not in self.paths or scope["method"] != "POST":
            return await self.app(scope, receive, send)
        chunks = bytearray()

        async def collect():
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return False
                body = message.get("body", b"")
                if len(chunks) + len(body) > self.limit:
                    raise HTTPException(413, detail="PAYLOAD_TOO_LARGE")
                chunks.extend(body)
                if not message.get("more_body", False):
                    return True

        try:
            if not await asyncio.wait_for(collect(), self.timeout):
                return
            strict_json(bytes(chunks))
        except (ValueError, RecursionError):
            return await JSONResponse({"detail": {"reason": "INVALID_SCHEMA"}}, 422)(scope, receive, send)
        except (HTTPException, TimeoutError) as exc:
            code = exc.status_code if isinstance(exc, HTTPException) else 408
            reason = "PAYLOAD_TOO_LARGE" if code == 413 else "REQUEST_TIMEOUT"
            return await JSONResponse({"detail": {"reason": reason}}, code)(scope, receive, send)

        delivered = False

        async def replay():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(chunks), "more_body": False}

        await self.app(scope, replay, send)


async def read_bounded_body(request, limit):
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > limit:
            raise HTTPException(413, detail={"status": "rejected", "reason": "PAYLOAD_TOO_LARGE"})
        body.extend(chunk)
    return bytes(body)


def strict_json(body):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError("nonfinite JSON value")

    return json.loads(body, object_pairs_hook=pairs, parse_constant=invalid)


async def peer_allowed(host, names):
    if not names:
        return True
    loop = asyncio.get_running_loop()
    for name in names.split(","):
        try:
            records = await asyncio.wait_for(loop.getaddrinfo(name.strip(), 8000, type=socket.SOCK_STREAM), 1)
        except (OSError, TimeoutError):
            continue
        if host in {record[4][0] for record in records}:
            return True
    return False

from __future__ import annotations

import socket
from typing import Callable


EDGE_SERVICE_HOSTS = (
    "edge-device-01",
    "edge-device-02",
    "edge-device-03",
    "edge-device-04",
    "edge-device-05",
    "edge-gateway",
)


def validate_reverse_path(
    timeout_seconds: float = 0.5,
    resolver: Callable[..., object] = socket.getaddrinfo,
    connector: Callable[..., object] = socket.create_connection,
) -> dict[str, object]:
    """Probe only fixed Edge targets and pass when every reverse path is blocked."""

    checks: list[dict[str, object]] = []
    for host in EDGE_SERVICE_HOSTS:
        try:
            resolver(host, 8000, type=socket.SOCK_STREAM)
        except OSError as exc:
            checks.append(
                {
                    "action": "resolve",
                    "target": host,
                    "blocked": True,
                    "detail": type(exc).__name__,
                }
            )
        else:
            checks.append(
                {
                    "action": "resolve",
                    "target": host,
                    "blocked": False,
                    "detail": "unexpectedly resolved",
                }
            )

    for host in EDGE_SERVICE_HOSTS:
        try:
            connection = connector((host, 8000), timeout=timeout_seconds)
        except OSError as exc:
            checks.append(
                {
                    "action": "connect",
                    "target": f"{host}:8000",
                    "blocked": True,
                    "detail": type(exc).__name__,
                }
            )
        else:
            close = getattr(connection, "close", None)
            if callable(close):
                close()
            checks.append(
                {
                    "action": "connect",
                    "target": f"{host}:8000",
                    "blocked": False,
                    "detail": "unexpectedly connected",
                }
            )

    return {
        "status": "blocked" if all(check["blocked"] for check in checks) else "failed",
        "all_blocked": all(check["blocked"] for check in checks),
        "checks": checks,
    }

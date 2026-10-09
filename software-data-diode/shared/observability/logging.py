from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import sys


STANDARD_FIELDS = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "taskName",
}


class JsonLogFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        document: dict[str, object] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": self.service,
            "level": record.levelname,
            "event": getattr(record, "event", "log"),
            "message": record.getMessage(),
            "message_id": getattr(record, "message_id", None),
            "device_id": getattr(record, "device_id", None),
            "correlation_id": getattr(record, "correlation_id", None),
        }
        for key, value in record.__dict__.items():
            if key not in STANDARD_FIELDS and key not in document and key != "event":
                document[key] = value
        if record.exc_info:
            document["exception"] = self.formatException(record.exc_info)
        return json.dumps(document, separators=(",", ":"), default=str)


def configure_json_logging(service: str, level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter(service))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        framework_logger = logging.getLogger(logger_name)
        framework_logger.handlers.clear()
        framework_logger.addHandler(handler)
        framework_logger.propagate = False


def log_context(
    event: str,
    *,
    message_id: object | None = None,
    device_id: str | None = None,
    correlation_id: object | None = None,
    **fields: object,
) -> dict[str, object]:
    return {
        "event": event,
        "message_id": str(message_id) if message_id is not None else None,
        "device_id": device_id,
        "correlation_id": str(correlation_id) if correlation_id is not None else None,
        **fields,
    }

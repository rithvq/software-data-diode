from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from threading import Lock
from uuid import UUID, uuid4


class AuditLog:
    """Append-only JSONL audit log with a verifiable SHA-256 hash chain."""

    def __init__(self, path: str | Path, service: str) -> None:
        self.path = Path(path)
        self.service = service
        self._lock = Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        event_type: str,
        result: str,
        reason: str = "",
        message_id: UUID | str | None = None,
        device_id: str | None = None,
        details: dict[str, object] | None = None,
    ) -> dict[str, object]:
        with self._lock:
            previous_hash = self._last_hash()
            record: dict[str, object] = {
                "event_id": str(uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "service": self.service,
                "event_type": event_type,
                "message_id": str(message_id) if message_id is not None else None,
                "device_id": device_id,
                "result": result,
                "reason": reason,
                "previous_log_hash": previous_hash,
                "current_log_hash": "",
            }
            if details is not None:
                record["details"] = details
            record["current_log_hash"] = _record_hash(record)
            with self.path.open("a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(record, sort_keys=True) + "\n")
            return record

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        # Only the last record is needed for append. Full verification remains
        # separate, so a growing audit trail does not make each decision O(n).
        last_line = b""
        with self.path.open("rb") as log_file:
            log_file.seek(0, 2)
            position = log_file.tell()
            suffix = b""
            while position > 0:
                length = min(position, 8192)
                position -= length
                log_file.seek(position)
                suffix = log_file.read(length) + suffix
                lines = suffix.splitlines()
                complete = lines if position == 0 else lines[1:]
                last_line = next((line for line in reversed(complete) if line.strip()), b"")
                if last_line:
                    break
        if not last_line:
            return "0" * 64
        try:
            return str(json.loads(last_line)["current_log_hash"])
        except (json.JSONDecodeError, KeyError):
            return "INVALID_PREVIOUS_LOG"


def _record_hash(record: dict[str, object]) -> str:
    hashable = dict(record)
    hashable["current_log_hash"] = ""
    canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def verify_audit_log(path: str | Path) -> tuple[bool, str]:
    log_path = Path(path)
    previous_hash = "0" * 64
    if not log_path.exists():
        return True, "audit log does not exist yet"

    with log_path.open("r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return False, f"line {line_number}: malformed JSON"

            if not isinstance(record, dict):
                return False, f"line {line_number}: audit record must be an object"

            if record.get("previous_log_hash") != previous_hash:
                return False, f"line {line_number}: previous_log_hash mismatch"

            expected_hash = _record_hash(record)
            if record.get("current_log_hash") != expected_hash:
                return False, f"line {line_number}: current_log_hash mismatch"

            previous_hash = expected_hash

    return True, "audit log hash chain is valid"

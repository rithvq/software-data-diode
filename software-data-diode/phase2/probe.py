"""Fixed-target, container-local Phase 2 validation. Never accepts external URLs."""

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import urllib.error
import urllib.request
from uuid import uuid4

from shared.security.audit import verify_audit_log
from shared.security.crypto import load_private_key, load_public_key
from .models import SecureEnvelope, SourceMessage
from .security import canonical, sign, verify


def audit_checks():
    path = Path("/state/audit.jsonl")
    # Snapshot an actively appended log, ending at the last complete record.
    data = path.read_bytes()
    data = data[:data.rfind(b"\n") + 1]
    with tempfile.TemporaryDirectory() as directory:
        copy = Path(directory) / "audit-copy.jsonl"
        copy.write_bytes(data)
        valid, reason = verify_audit_log(copy)
        results = [{"check": "Audit hash chain", "passed": valid and bool(data), "detail": reason}]
        lines = copy.read_text().splitlines()
        record = json.loads(lines[0])
        record["result"] = "MODIFIED"
        lines[0] = json.dumps(record)
        copy.write_text("\n".join(lines) + "\n")
        valid, reason = verify_audit_log(copy)
        results.append({"check": "Audit copy tampering", "passed": not valid and "line 1:" in reason, "detail": reason})
    return results


def public_checks():
    public = load_public_key("/public/edge_public.pem")
    with sqlite3.connect("file:/state/security.sqlite3?mode=ro", uri=True) as db:
        rows = db.execute("SELECT body FROM messages WHERE status='received' ORDER BY rowid DESC LIMIT 10").fetchall()
    for row in rows:
        verify(SecureEnvelope.model_validate_json(row[0]), public)
    return [{"check": "Fog validates received Ed25519 envelopes", "passed": len(rows) == 10, "detail": len(rows)},
            {"check": "Fog has no private signing key", "passed": not Path("/private/edge_private.pem").exists(),
             "detail": "private key path absent"}]


def attacks():
    private = load_private_key("/private/edge_private.pem")
    with sqlite3.connect("file:/state/security.sqlite3?mode=ro", uri=True) as db:
        row = db.execute("SELECT body FROM messages WHERE status='transmitted' ORDER BY rowid DESC LIMIT 1").fetchone()
    original = SecureEnvelope.model_validate_json(row[0])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    results = []

    def signed_variant(**updates):
        data = original.model_dump(mode="json", exclude={"payload_hash", "signature", "schema_version"})
        return sign(SourceMessage.model_validate({**data, **updates}), private).model_dump(mode="json")

    def request(body):
        req = urllib.request.Request("http://unidirectional-gateway:8000/ingest", data=body,
                                     headers={"content-type": "application/json"})
        try:
            with opener.open(req, timeout=3) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def attack(name, body, expected, expected_status):
        start = time.perf_counter()
        status, response = request(body)
        actual = response.get("reason", response.get("status"))
        results.append({"scenario": name, "attack_type": name, "expected_result": expected,
                        "actual_result": actual, "detected": actual == expected and status == expected_status,
                        "response_time": time.perf_counter() - start,
                        "timestamp": datetime.now(timezone.utc).isoformat(), "http_status": status})

    document = original.model_dump(mode="json")
    attack("exact retransmission", canonical(document), "DUPLICATE_MESSAGE", 200)
    attack("duplicate UUID conflict", canonical(signed_variant(sequence_number=original.sequence_number + 1000000)), "DUPLICATE_MESSAGE", 409)
    attack("replay sequence", canonical(signed_variant(message_id=str(uuid4()))), "REPLAY_DETECTED", 409)
    modified = {**document, "payload": {**document["payload"], "temperature": 999}}
    modified["payload_size"] = len(canonical(modified["payload"]))
    attack("payload tampering", canonical(modified), "HASH_MISMATCH", 400)
    attack("metadata tampering", canonical({**document, "event_class": "MODIFIED"}), "INVALID_SIGNATURE", 400)
    attack("signature corruption", canonical({**document, "signature": "A" * 88}), "INVALID_SIGNATURE", 400)
    for name, offset in [("stale timestamp", -300), ("future timestamp", 300)]:
        stamp = (datetime.now(timezone.utc) + timedelta(seconds=offset)).isoformat()
        attack(name, canonical(signed_variant(message_id=str(uuid4()), sequence_number=original.sequence_number + 1000000,
                                              timestamp=stamp, created_at=stamp)), "EXPIRED_MESSAGE", 400)
    attack("missing fields", b"{}", "INVALID_SCHEMA", 422)
    attack("oversized body", b"x" * 8193, "PAYLOAD_TOO_LARGE", 413)
    start = time.perf_counter()
    limited = sum(request(b"{}")[0] == 429 for _ in range(80))
    results.append({"scenario": "bounded local flood", "attack_type": "rate limiting", "expected_result": "RATE_LIMIT_EXCEEDED",
                    "actual_result": "RATE_LIMIT_EXCEEDED" if limited else "not observed", "detected": limited > 0,
                    "response_time": time.perf_counter() - start, "timestamp": datetime.now(timezone.utc).isoformat(),
                    "http_status": 429 if limited else 0})
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["audit", "public", "attacks"])
    mode = parser.parse_args().mode
    print(json.dumps({"audit": audit_checks, "public": public_checks, "attacks": attacks}[mode]()))

import json

from shared.security.audit import AuditLog, verify_audit_log


def test_audit_hash_chain_detects_tampering(tmp_path) -> None:
    log_path = tmp_path / "audit.jsonl"
    audit_log = AuditLog(log_path, "test-service")
    audit_log.append("FIRST_EVENT", "ACCEPTED", message_id="message-1", device_id="device-1")
    audit_log.append("SECOND_EVENT", "REJECTED", reason="INVALID_SIGNATURE")

    valid, _ = verify_audit_log(log_path)
    assert valid is True

    lines = log_path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["result"] = "REJECTED"
    lines[0] = json.dumps(tampered, sort_keys=True)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    valid, reason = verify_audit_log(log_path)
    assert valid is False
    assert "current_log_hash mismatch" in reason

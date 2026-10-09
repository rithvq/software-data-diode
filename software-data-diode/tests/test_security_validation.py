import csv
import socket
from pathlib import Path

import pytest
import yaml

from shared.security import AuditLog, validate_reverse_path
from tests.conftest import load_service_module


def test_security_client_restricts_targets_to_internal_services() -> None:
    module = load_service_module("security-test-client")

    assert module.validate_target_url("http://fog-receiver:8000/receive").startswith("http://")
    assert module.validate_target_url("http://data-diode:8000/ingest").startswith("http://")
    with pytest.raises(ValueError):
        module.validate_target_url("https://example.com/attack")
    with pytest.raises(ValueError):
        module.validate_target_url("http://127.0.0.1:8000/attack")


def test_security_csv_has_required_machine_readable_columns(tmp_path: Path) -> None:
    module = load_service_module("security-test-client")
    result = module.ScenarioResult(
        scenario="payload_tampering",
        attack_type="PAYLOAD_TAMPERING",
        expected_result="HASH_MISMATCH",
        actual_result="HASH_MISMATCH",
        detected=True,
        response_time=0.01,
        timestamp="2026-09-02T00:00:00+00:00",
    )
    report_path = tmp_path / "results.csv"

    module.write_csv_report(report_path, [result])

    with report_path.open(newline="", encoding="utf-8") as report_file:
        reader = csv.DictReader(report_file)
        rows = list(reader)
    assert tuple(reader.fieldnames or ()) == module.CSV_FIELDS
    assert rows[0]["detected"] == "true"


def test_controlled_audit_copy_reports_first_broken_location(tmp_path: Path) -> None:
    module = load_service_module("security-test-client")
    source = tmp_path / "source.jsonl"
    audit = AuditLog(source, "security-test")
    audit.append("FIRST", "ACCEPTED")
    audit.append("SECOND", "ACCEPTED")

    line, reason = module.tamper_audit_copy(source, tmp_path / "tampered.jsonl")

    assert line == 1
    assert reason == "line 1: current_log_hash mismatch"


def test_reverse_path_passes_only_when_resolution_and_connections_fail() -> None:
    def blocked(*args: object, **kwargs: object) -> object:
        raise socket.gaierror("blocked by isolated Docker network")

    result = validate_reverse_path(resolver=blocked, connector=blocked)

    assert result["all_blocked"] is True
    assert result["status"] == "blocked"
    assert len(result["checks"]) == 12


def test_security_compose_profile_does_not_weaken_default_memberships() -> None:
    root = Path(__file__).resolve().parents[1]
    compose = yaml.safe_load((root / "docker-compose.yml").read_text(encoding="utf-8"))
    override = yaml.safe_load(
        (root / "docker-compose.security.yml").read_text(encoding="utf-8")
    )
    client = compose["services"]["security-test-client"]

    assert client["profiles"] == ["security-test"]
    assert set(client["networks"]) == {"diode-network", "fog-ingress-network"}
    assert "edge-network" not in client["networks"]
    assert "fog-services-network" not in client["networks"]
    assert "SECURITY_TEST_MODE" not in compose["services"]["fog-receiver"]["environment"]
    assert override["services"]["fog-receiver"]["environment"]["SECURITY_TEST_MODE"] == "true"

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from scripts.validate_config import validate_environment
from tests.conftest import load_service_module


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
SERVICES = COMPOSE["services"]


def test_deployment_profiles_have_expected_membership() -> None:
    edge_devices = {f"edge-device-{number:02d}" for number in range(1, 6)}
    processing = {
        "edge-gateway",
        "data-diode",
        "fog-receiver",
        "event-processor",
        "fog-analytics",
        "alert-engine",
        "postgres",
        "database-migrator",
    }
    observability = {
        "monitoring-api",
        "dashboard",
        "prometheus-edge",
        "prometheus-fog",
        "grafana",
    }

    assert edge_devices | processing <= {
        name for name, service in SERVICES.items() if "core" in service.get("profiles", [])
    }
    assert edge_devices | processing | observability <= {
        name for name, service in SERVICES.items() if "full" in service.get("profiles", [])
    }
    security_members = {
        name
        for name, service in SERVICES.items()
        if "security-test" in service.get("profiles", [])
    }
    assert edge_devices | processing | {"security-test-client"} <= security_members
    assert not observability.intersection(security_members)


def test_python_services_use_non_root_read_only_containers() -> None:
    python_services = {
        "edge-device-01",
        "edge-device-02",
        "edge-device-03",
        "edge-device-04",
        "edge-device-05",
        "edge-gateway",
        "data-diode",
        "fog-receiver",
        "event-processor",
        "fog-analytics",
        "alert-engine",
        "monitoring-api",
        "dashboard",
        "security-test-client",
    }
    dockerfiles = {
        service["build"]["dockerfile"]
        for name, service in SERVICES.items()
        if name in python_services
    }

    for name in python_services:
        service = SERVICES[name]
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert service["pids_limit"] > 0
        assert float(service["cpus"]) > 0
        assert service["mem_limit"]

    for relative in dockerfiles:
        source = (PROJECT_ROOT / relative).read_text(encoding="utf-8")
        assert source.startswith("FROM python:3.11.11-slim-bookworm")
        assert "USER 10001:10001" in source
        assert "-c /tmp/constraints.txt" in source
        assert "\\\\\n" not in source


def test_expected_host_ports_are_published_and_networks_are_internal() -> None:
    assert SERVICES["edge-gateway"]["ports"] == ["127.0.0.1:${EDGE_GATEWAY_PORT:-8000}:8000"]
    assert SERVICES["dashboard"]["ports"] == ["127.0.0.1:${DASHBOARD_PORT:-8501}:8501"]
    assert SERVICES["prometheus-edge"]["ports"] == ["127.0.0.1:${PROMETHEUS_EDGE_PORT:-9091}:9090"]
    assert SERVICES["prometheus-fog"]["ports"] == ["127.0.0.1:${PROMETHEUS_FOG_PORT:-9090}:9090"]
    assert SERVICES["grafana"]["ports"] == ["127.0.0.1:${GRAFANA_PORT:-3000}:3000"]
    isolated = {
        "edge-network",
        "diode-network",
        "fog-ingress-network",
        "fog-services-network",
        "observability-control-network",
    }
    assert all(COMPOSE["networks"][name].get("internal") is True for name in isolated)
    assert COMPOSE["networks"]["edge-host-network"].get("internal") is not True
    assert COMPOSE["networks"]["fog-host-network"].get("internal") is not True
    assert "fog-host-network" not in SERVICES["edge-gateway"]["networks"]
    assert "edge-host-network" not in SERVICES["dashboard"]["networks"]


def test_fog_services_have_no_edge_network_membership() -> None:
    fog_services = {
        "fog-receiver",
        "event-processor",
        "fog-analytics",
        "alert-engine",
        "postgres",
        "monitoring-api",
        "dashboard",
    }
    for name in fog_services:
        assert "edge-network" not in SERVICES[name]["networks"]

    assert SERVICES["data-diode"]["networks"] == ["diode-network", "fog-ingress-network"]
    assert SERVICES["fog-receiver"]["networks"] == [
        "fog-ingress-network",
        "fog-services-network",
    ]


def test_readiness_checks_use_readiness_endpoints() -> None:
    ready_services = {
        "edge-gateway",
        "data-diode",
        "fog-receiver",
        "event-processor",
        "fog-analytics",
        "alert-engine",
        "monitoring-api",
    }
    for name in ready_services:
        assert "/ready" in " ".join(SERVICES[name]["healthcheck"]["test"])


def test_configuration_rejects_placeholders_and_bad_capacity() -> None:
    valid = {
        "POSTGRES_PASSWORD": "random-value",
        "OBSERVABILITY_TOKEN": "random-token",
        "GRAFANA_ADMIN_PASSWORD": "random-admin-value",
        "MAX_QUEUE_SIZE": "10",
        "LOW_TRAFFIC_PERCENT": "70",
        "MEDIUM_TRAFFIC_PERCENT": "20",
        "HIGH_TRAFFIC_PERCENT": "8",
        "CRITICAL_TRAFFIC_PERCENT": "2",
    }
    validate_environment(valid)

    with pytest.raises(ValueError, match="placeholder"):
        validate_environment({**valid, "POSTGRES_PASSWORD": "replace-password"})
    with pytest.raises(ValueError, match="greater than zero"):
        validate_environment({**valid, "MAX_QUEUE_SIZE": "0"})
    with pytest.raises(ValueError, match="total 100"):
        validate_environment({**valid, "LOW_TRAFFIC_PERCENT": "60"})


def test_runtime_material_is_not_tracked_by_default() -> None:
    ignores = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in ignores
    assert "secrets/*.pem" in ignores
    assert "logs/" in ignores
    assert "security-reports/" in ignores
    docker_ignores = (PROJECT_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in docker_ignores
    assert "secrets/*.pem" in docker_ignores


def test_audit_logs_use_non_root_compatible_named_volume() -> None:
    writers = ("edge-gateway", "data-diode", "fog-receiver")
    for name in writers:
        mount = next(item for item in SERVICES[name]["volumes"] if isinstance(item, dict) and item["target"] == "/logs")
        assert mount["source"] == "audit-logs"
        assert mount["volume"]["subpath"] == name
        dockerfile = PROJECT_ROOT / SERVICES[name]["build"]["dockerfile"]
        assert "chown app:app /logs" in dockerfile.read_text(encoding="utf-8")
    assert "audit-logs:/logs:ro" in SERVICES["monitoring-api"]["volumes"]
    assert "audit-logs" in COMPOSE["volumes"]


def test_database_outage_does_not_mask_security_rejection() -> None:
    class FailingRepository:
        def save_rejection(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError("database offline")

    module = load_service_module("fog-receiver")
    module.repository = FailingRepository()
    response = TestClient(module.app).post("/receive", content=b'{"not": "an envelope"}')

    assert response.status_code == 422
    assert response.json()["detail"]["reason"] == "INVALID_SCHEMA"

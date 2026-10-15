import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts.coverage_local import (
    DEVICES,
    ROOT,
    SERVICES,
    LocalProject,
    validate_model,
    write_new,
)
from scripts.verify_n7_rules import scope_fixture
from shared.coverage.capsules import EvidenceError
from shared.coverage.demo_faults import DemoForwardFaults
from shared.coverage.parts import verify_part
from shared.edge.demo import SCENARIOS, demo_project, payload, require_demo
from tests.test_coverage_transport import framer  # noqa: F401


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setenv("N11_DEMO_ENABLED", "true")
    monkeypatch.setenv("N11_PROJECT", "software-data-diode-coverage-n11-1a11c0de0001")


@pytest.mark.parametrize("name", ["software-data-diode", "other", "software-data-diode-n9-abcdef012345",
                                  "software-data-diode-coverage-n11-../../main"])
def test_refuse_non_demo_projects(name):
    with pytest.raises(ValueError):
        demo_project(name)


def test_opt_in_required(monkeypatch):
    monkeypatch.delenv("N11_DEMO_ENABLED", raising=False)
    with pytest.raises(ValueError, match="not enabled"):
        require_demo()


def test_faults_inactive_without_plan_and_do_not_modify_state(tmp_path, enabled):
    faults = DemoForwardFaults(tmp_path/"missing", clock=lambda: 100)
    assert faults.transform(b"RCR1raw") == b"RCR1raw"
    assert not faults.counts


def test_fixed_fault_schedule_preserves_state_and_other_classes(tmp_path, enabled):
    plan = tmp_path/"plan.json"
    plan.write_text(json.dumps({"start": 100, "run_id": "fixture"}))
    clock = [130]
    faults = DemoForwardFaults(plan, clock=lambda: clock[0])
    assert faults.transform(b"RCR1raw") is None
    assert faults.transform(b"RCS1state") == b"RCS1state"
    assert faults.transform(b'{"evidence":1}') == b'{"evidence":1}'
    clock[0] = 150
    assert faults.transform(b"RCR1raw") == b"RCR1raw"
    assert faults.transform(b'{"evidence":1}') is None
    clock[0] = 170
    assert faults.transform(b'{"evidence":1}') == b'{"evidence":1}'
    assert faults.counts == {"RAW_DROP": 1, "EVIDENCE_DROP": 1}


def test_tamper_hits_real_signature_and_preserves_wire_length(tmp_path, enabled, framer):  # noqa: F811
    scope, _, _, frames = scope_fixture(framer, 5, "edge-device-01", [40])
    plan = tmp_path/"plan.json"
    plan.write_text(json.dumps({"start": 100, "run_id": "fixture"}))
    faults = DemoForwardFaults(plan, clock=lambda: 160)
    changed = faults.transform(frames[0])
    assert len(changed) == len(frames[0]) <= 1200
    with pytest.raises(EvidenceError, match="INVALID_SIGNED_PART"):
        verify_part(changed, framer.keys)
    assert scope.verification.status == "VALID"


def test_fault_plan_bounded_and_events_bounded(tmp_path, enabled):
    plan = tmp_path/"plan.json"
    plan.write_text("x"*1025)
    faults = DemoForwardFaults(plan, clock=lambda: 130)
    with pytest.raises(ValueError, match="bound"):
        faults.transform(b"RCR1raw")
    plan.write_text(json.dumps({"start": 100, "run_id": "fixture"}))
    for _ in range(600):
        assert faults.transform(b"RCR1raw") is None
    assert len(faults.events) == 512 and faults.counts["RAW_DROP"] == 600


@pytest.mark.parametrize("stage", [*SCENARIOS, "recovery"])
def test_five_devices_use_registered_metrics(stage):
    messages = [payload(f"edge-device-{i:02}", stage, datetime.now(timezone.utc)) for i in range(1, 6)]
    assert len({m.device_id for m in messages}) == 5
    assert messages[1].cpu_usage is not None
    assert "packets_per_second" in messages[2].measurements
    assert "failed_logins" in messages[3].measurements
    assert "vibration_mm_s" in messages[4].measurements
    assert all(m.attributes["n11_scenario"] == stage for m in messages)
    if stage == "registered-match":
        assert messages[0].temperature == 40
        assert messages[1].cpu_usage == 30
        assert messages[2].measurements["packets_per_second"] == 1000
        assert messages[3].measurements["failed_logins"] == 0


def owned_container(project):
    return {"Config": {"Labels": {"org.rccd.n11": project}},
        "Mounts": [{"Type": "volume", "Name": project+"_ledger"}],
        "NetworkSettings": {"Networks": {project+"_edge-network": {}}},
        "HostConfig": {"PortBindings": {"8501/tcp": [{"HostIp": "127.0.0.1"}]}}}


@pytest.mark.parametrize("attack", ["foreign_label", "foreign_volume", "foreign_network", "public_port"])
def test_guard_refuses_unsafe_existing_deployment(attack):
    project = LocalProject("software-data-diode-coverage", docker="mock-docker")
    container = owned_container(project.project)
    if attack == "foreign_label":
        container["Config"]["Labels"] = {}
    elif attack == "foreign_volume":
        container["Mounts"][0]["Name"] = "main_database"
    elif attack == "foreign_network":
        container["NetworkSettings"]["Networks"] = {"main_edge": {}}
    else:
        container["HostConfig"]["PortBindings"]["8501/tcp"][0]["HostIp"] = "0.0.0.0"
    project.containers = Mock(return_value=[container])
    with pytest.raises(ValueError):
        project.guard()


def test_routine_stop_is_scoped_and_never_deletes_state(tmp_path):
    project = LocalProject("software-data-diode-coverage", docker="mock-docker")
    project.output = tmp_path
    (tmp_path/"settings.json").write_text("{}")
    project.containers = Mock(return_value=[owned_container(project.project)])
    project.call = Mock()
    project.stop()
    project.call.assert_called_once_with(["stop", "--timeout", "30"], timeout=180)
    assert "-p" in project.command and project.project in project.command


def test_shared_writable_state_refused_but_safe_stop_still_possible(tmp_path):
    project = LocalProject("software-data-diode-coverage", docker="mock-docker")
    containers = [owned_container(project.project), owned_container(project.project)]
    for c, service in zip(containers, ("edge-gateway", "fog-receiver")):
        c["Config"]["Labels"]["com.docker.compose.service"] = service
        c["Mounts"][0]["RW"] = True
    project.containers = Mock(return_value=containers)
    with pytest.raises(ValueError, match="shared writable"):
        project.guard()
    assert project.guard(check_isolation=False) == containers


def model_fixture():
    project = "software-data-diode-coverage"
    services = {s: {"networks": ["edge" if s in DEVICES or s == "edge-gateway" else "fog"]}
                for s in (*SERVICES, *DEVICES, "database-migrator", "validation-init")}
    return {"name": project, "services": services,
            "networks": {n: {"name": project+"_"+n, "internal": True} for n in ("edge", "fog")},
            "volumes": {"ledger": {"name": project+"_ledger"}}}


@pytest.mark.parametrize("attack", ["public_port", "host_namespace", "secret_bind", "private_ledger", "shared_network"])
def test_validate_resolved_model_before_start(attack):
    model = model_fixture()
    validate_model(model, model["name"])
    service = model["services"]["fog-receiver"]
    if attack == "public_port":
        service["ports"] = [{"target": 8000, "host_ip": "0.0.0.0"}]
    elif attack == "host_namespace":
        service["network_mode"] = "host"
    elif attack == "secret_bind":
        service["volumes"] = [{"type": "bind", "source": str(ROOT/"secrets/private.pem"), "read_only": True}]
    elif attack == "private_ledger":
        service["volumes"] = [{"type": "volume", "source": "ledger"}]
    else:
        service["networks"] = ["edge"]
    with pytest.raises(ValueError):
        validate_model(model, model["name"])


def test_new_evidence_never_overwrites(tmp_path):
    path = tmp_path/"result.json"
    write_new(path, {"value": 1})
    with pytest.raises(FileExistsError):
        write_new(path, {"value": 2})
    assert json.loads(path.read_bytes()) == {"value": 1}


def test_wrappers_resolve_actual_root_and_venv():
    root = Path(__file__).resolve().parents[1]
    for action in ("setup", "start", "status", "demo", "stop", "restart"):
        source = (root/"scripts"/("coverage-"+action+".ps1")).read_text()
        assert "Split-Path -Parent $PSScriptRoot" in source
        assert ".venv\\Scripts\\python.exe" in source
        assert "down" not in source and "Remove-Item" not in source

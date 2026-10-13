import json
import subprocess

import pytest

from scripts.capture_n0_baseline import (
    docker_summary,
    environment_summary,
    run_readonly,
    sanitize_container,
    source_fingerprints,
    test_summary as summarize_junit,
)


def test_fingerprints_exclude_private_and_generated_material(tmp_path):
    (tmp_path / "shared").mkdir()
    (tmp_path / "shared" / "module.py").write_text("value = 1\n")
    (tmp_path / ".env").write_text("POSTGRES_PASSWORD=do-not-export\n")
    (tmp_path / "private.pem").write_text("private-key-material")
    (tmp_path / ".dockerignore").write_text("secrets/\n")
    (tmp_path / "experiments" / "results").mkdir(parents=True)
    (tmp_path / "experiments" / "results" / "raw.json").write_text("{}")
    (tmp_path / "docs" / "novelty-roadmap" / "evidence").mkdir(parents=True)
    (tmp_path / "docs" / "novelty-roadmap" / "evidence" / "manifest.json").write_text("{}")
    result = source_fingerprints(tmp_path)
    assert [row["path"] for row in result["files"]] == [".dockerignore", "shared/module.py"]
    assert "do-not-export" not in json.dumps(result)


def test_fingerprints_are_stable_and_detect_source_changes(tmp_path):
    (tmp_path / "shared").mkdir()
    source = tmp_path / "shared" / "module.py"
    source.write_text("value = 1\n")
    first = source_fingerprints(tmp_path)
    assert source_fingerprints(tmp_path) == first
    source.write_text("value = 2\n")
    assert source_fingerprints(tmp_path)["aggregate_sha256"] != first["aggregate_sha256"]


def test_environment_exports_presence_without_secret_values_or_digests(tmp_path):
    (tmp_path / ".env").write_text(
        "POSTGRES_PASSWORD=private-password\nOBSERVABILITY_TOKEN=private-token\n"
        "GRAFANA_ADMIN_PASSWORD=another-private-password\nDATABASE_URL=private-url\n"
        "MAX_QUEUE_SIZE=250\n"
    )
    result = environment_summary(tmp_path)
    assert result["public_settings"] == {"MAX_QUEUE_SIZE": "250"}
    assert all(result["required_secret_present"].values())
    assert result["secret_values_and_digests_exported"] is False
    assert "private-" not in json.dumps(result)


def test_container_export_omits_credentials_and_health_command_output():
    result = sanitize_container({
        "Name": "/software-data-diode-postgres-1", "Image": "sha256:image",
        "Config": {"Env": ["PASSWORD=private-value"], "Labels": {
            "com.docker.compose.project": "software-data-diode", "com.docker.compose.service": "postgres"}},
        "State": {"Status": "exited", "Running": False, "ExitCode": 0,
                  "Health": {"Status": "healthy", "Log": [{"Output": "private-value"}]}},
        "NetworkSettings": {"Networks": {"fog-network": {"IPAddress": ""}}},
        "HostConfig": {"PortBindings": {}},
        "Mounts": [{"Type": "bind", "Source": "private-key-path"},
                   {"Type": "volume", "Name": "fog-data", "Destination": "/data", "RW": True}],
    })
    assert result["running"] is False
    assert result["configured_networks"] == ["fog-network"]
    assert len(result["named_volume_mounts"]) == 1
    assert "private-" not in json.dumps(result)


def test_readonly_command_errors_do_not_export_expanded_configuration(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], 1, "private-stdout", "private-stderr"))
    with pytest.raises(RuntimeError, match="exited with code 1") as exc:
        run_readonly(["docker", "compose", "config", "--quiet"], root=tmp_path)
    assert "private-" not in str(exc.value)


def test_docker_capture_has_no_service_mutations(monkeypatch, tmp_path):
    calls = []

    def fake_command(command, **kwargs):
        calls.append(command[1:])
        if command[1] == "version":
            return json.dumps({"Client": {"Version": "test"}, "Server": {"Version": "test"}})
        if command[1:3] == ["compose", "version"]:
            return "test\n"
        if command[1] == "ps":
            return ""
        if command[1:3] == ["network", "ls"]:
            return ""
        if command[1:3] == ["compose", "-p"]:
            assert command[-2:] == ["config", "--quiet"]
            return ""
        raise AssertionError(command)

    monkeypatch.setattr("scripts.capture_n0_baseline.run_readonly", fake_command)
    result = docker_summary(tmp_path, "docker")
    assert result["status"] == "available"
    assert result["running_project_container_count"] == 0
    assert {row[0] for row in calls} <= {"version", "compose", "ps", "network"}
    assert not any(set(row) & {"up", "down", "start", "stop", "restart", "run", "exec"} for row in calls)


def test_junit_summary_preserves_failed_and_skipped_evidence(tmp_path):
    report = tmp_path / "tests.xml"
    report.write_text('<testsuites><testsuite><testcase name="pass"/>'
                      '<testcase name="fail"><failure/></testcase>'
                      '<testcase name="skip"><skipped/></testcase>'
                      '</testsuite></testsuites>')
    result = summarize_junit(report)
    assert result["status"] == "not_passed"
    assert result["counts"] == {"tests": 3, "passed": 1, "failures": 1, "errors": 0, "skipped": 1}

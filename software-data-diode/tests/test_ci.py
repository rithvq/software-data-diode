from copy import deepcopy
import json
from pathlib import Path
import re
import sys

import pytest
import yaml

from scripts import ci_runtime


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = next(path for path in (ROOT.parent / ".github/workflows/ci.yml",
                                  ROOT / ".github/workflows/ci.yml") if path.is_file())
CI = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_workflow_runs_all_required_suites_and_never_deploys_to_the_user():
    assert set(CI["on"]) == {"push", "pull_request", "workflow_dispatch", "merge_group"}
    assert CI["permissions"] == {"contents": "read"}
    assert CI["concurrency"]["cancel-in-progress"] is True
    jobs = CI["jobs"]
    assert set(jobs["ci-passed"]["needs"]) == set(jobs) - {"ci-passed"}
    assert jobs["ci-passed"]["if"] == "${{ always() }}"
    assert jobs["ci-passed"]["name"] == "CI Passed"
    assert jobs["python-tests"]["strategy"]["fail-fast"] is False
    assert {entry["python"] for entry in jobs["python-tests"]["strategy"]["matrix"]["include"]} == {"3.11", "3.12"}
    assert any(entry["os"].startswith("windows") for entry in jobs["python-tests"]["strategy"]["matrix"]["include"])
    assert jobs["docker-baselines"]["strategy"]["matrix"]["phase"] == [1, 2]
    assert all("runner." not in str(value) for value in jobs["python-tests"]["env"].values())
    for job in jobs.values():
        assert "timeout-minutes" in job
        assert "self-hosted" not in job["runs-on"]
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"actions/[a-z-]+@[a-f0-9]{40}", step["uses"])
                if step["uses"].startswith("actions/checkout@"):
                    assert step["with"]["persist-credentials"] is False
                if step["uses"].startswith("actions/upload-artifact@"):
                    assert step["if"] == "${{ always() }}"
                    paths = step["with"]["path"].splitlines()
                    assert all("/secrets/" not in path and ".env" not in path for path in paths)
                    assert step["with"]["retention-days"] == 14
    commands = "\n".join(step.get("run", "") for job in jobs.values() for step in job["steps"])
    assert "actionlint" in commands and "sha256sum --ignore-missing --check" in commands
    assert "docker system prune" not in commands and "docker volume prune" not in commands
    assert "pytest -q --junitxml=" in commands
    assert "scripts/audit_runtime.py --outages" in commands
    assert "--profile security-test run --build --use-aliases --rm security-test-client" in commands


def test_one_off_security_client_preserves_the_alias_required_by_source_allowlists():
    step = next(step for step in CI["jobs"]["docker-security"]["steps"]
                if step.get("name") == "Run isolated attack simulator")
    command = next(line for line in step["run"].splitlines() if " run " in line)
    assert "--use-aliases" in command.split()
    assert command.split()[-1] == "security-test-client"
    assert "--service-ports" not in command and "--publish" not in command
    override = yaml.safe_load((ROOT / "docker-compose.security.yml").read_text())
    assert override["services"]["data-diode"]["environment"]["DIODE_ALLOWED_HOSTS"] == "edge-gateway,security-test-client"
    assert override["services"]["fog-receiver"]["environment"]["FOG_ALLOWED_HOSTS"] == "data-diode,security-test-client"
    base = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    assert base["services"]["data-diode"]["environment"]["DIODE_ALLOWED_HOSTS"] == "edge-gateway"
    assert base["services"]["fog-receiver"]["environment"]["FOG_ALLOWED_HOSTS"] == "data-diode"


@pytest.mark.parametrize("job_name", ["docker-baselines", "docker-system", "docker-security"])
def test_docker_diagnostics_cleanup_and_artifacts_always_run(job_name):
    steps = CI["jobs"][job_name]["steps"]
    diagnostics = next(i for i, step in enumerate(steps) if step.get("name") == "Collect diagnostics")
    cleanup = next(i for i, step in enumerate(steps) if "down --volumes --remove-orphans" in step.get("run", ""))
    upload = next(i for i, step in enumerate(steps) if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert diagnostics < cleanup < upload
    assert all(steps[index]["if"] == "${{ always() }}" for index in (diagnostics, cleanup, upload))


@pytest.mark.parametrize("result", ["success", "failure", "cancelled", "skipped"])
def test_final_gate_fails_closed_for_failed_cancelled_or_skipped_suites(tmp_path, monkeypatch, result):
    step = CI["jobs"]["ci-passed"]["steps"][0]
    source = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    results = {name: {"result": "success"} for name in CI["jobs"]["ci-passed"]["needs"]}
    results["docker-security"]["result"] = result
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("RESULTS", json.dumps(results))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    if result == "success":
        exec(compile(source, "ci-gate", "exec"), {})
    else:
        with pytest.raises(SystemExit, match="docker-security"):
            exec(compile(source, "ci-gate", "exec"), {})
    assert result in summary.read_text()


def hosted(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setenv("RUNNER_OS", "Linux")


@pytest.mark.parametrize("variable,value", [("GITHUB_ACTIONS", "false"),
                                           ("RUNNER_ENVIRONMENT", "self-hosted"),
                                           ("RUNNER_OS", "Windows")])
def test_bootstrap_refuses_local_or_self_hosted_runners(tmp_path, monkeypatch, variable, value):
    hosted(monkeypatch)
    monkeypatch.setenv(variable, value)
    with pytest.raises(RuntimeError, match="GitHub-hosted"):
        ci_runtime.prepare(tmp_path)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("relative", [".env", "secrets/edge_private_key.pem", "secrets/edge_public_key.pem"])
def test_bootstrap_preserves_existing_credentials(tmp_path, monkeypatch, relative):
    hosted(monkeypatch)
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"existing user material")
    monkeypatch.setattr(ci_runtime.subprocess, "run", lambda *a, **k: pytest.fail("must not run setup"))
    with pytest.raises(RuntimeError, match="clean checkout"):
        ci_runtime.prepare(tmp_path)
    assert path.read_bytes() == b"existing user material"


def test_bootstrap_only_adjusts_ephemeral_files_and_masks_generated_secrets(tmp_path, monkeypatch, capsys):
    hosted(monkeypatch)
    calls, permissions = [], []

    def command(args, **kwargs):
        calls.append(args)
        assert kwargs["check"]
        if args[0] == sys.executable:
            assert kwargs["cwd"] == tmp_path
            (tmp_path / ".env").write_text("POSTGRES_PASSWORD=ci-db\nOBSERVABILITY_TOKEN=ci-token\nGRAFANA_ADMIN_PASSWORD=ci-grafana\n")
            (tmp_path / "secrets").mkdir()
            (tmp_path / "secrets/edge_private_key.pem").write_text("test-only private file")
            (tmp_path / "secrets/edge_public_key.pem").write_text("test-only public file")
            (tmp_path / "security-reports").mkdir()

    monkeypatch.setattr(ci_runtime.subprocess, "run", command)
    monkeypatch.setattr(Path, "chmod", lambda path, mode: permissions.append((path, mode)))
    ci_runtime.prepare(tmp_path)
    assert calls[0] == [sys.executable, str(tmp_path / "scripts/setup.py")]
    assert calls[1] == ["sudo", "chown", "10001:10001", str(tmp_path / "secrets/edge_private_key.pem"),
                        str(tmp_path / "security-reports")]
    assert (tmp_path / "secrets/edge_private_key.pem", 0o400) in permissions
    assert capsys.readouterr().out.splitlines() == ["::add-mask::ci-db", "::add-mask::ci-token", "::add-mask::ci-grafana"]


def test_warmup_retries_transient_failures_and_times_out_visibly():
    now, calls = [0.0], [0]

    def predicate():
        calls[0] += 1
        if calls[0] == 1:
            raise OSError("startup")
        return calls[0] == 3

    ci_runtime.poll_until("test", predicate, 10, clock=lambda: now[0], sleep=lambda delay: now.__setitem__(0, now[0] + delay))
    assert calls[0] == 3
    with pytest.raises(TimeoutError, match="missing"):
        ci_runtime.poll_until("missing", lambda: False, 3, clock=lambda: now[0], sleep=lambda delay: now.__setitem__(0, now[0] + delay))


@pytest.mark.parametrize("timeout", [0, -1, 301, float("inf"), float("nan"), True])
def test_warmup_rejects_unbounded_or_invalid_timeouts(timeout):
    with pytest.raises(ValueError):
        ci_runtime.poll_until("test", lambda: True, timeout)


def test_readiness_requires_persistence_anomalies_all_devices_and_all_scrape_targets():
    ready = {"overview": {"active_edge_nodes": 5, "accepted_messages": 1},
             "analytics": {"latest_anomalies": [{}], "active_alerts": [{}]}}
    assert ci_runtime.telemetry_ready(ready)
    for section, key, value in [("overview", "active_edge_nodes", 4), ("overview", "accepted_messages", 0),
                                 ("analytics", "latest_anomalies", []), ("analytics", "active_alerts", [])]:
        document = deepcopy(ready)
        document[section][key] = value
        assert not ci_runtime.telemetry_ready(document)
    assert ci_runtime.targets_ready({"data": {"activeTargets": [{"health": "up"}]}})
    assert not ci_runtime.targets_ready({"data": {"activeTargets": []}})
    assert not ci_runtime.targets_ready({"data": {"activeTargets": [{"health": "up"}, {"health": "down"}]}})


def test_smoke_urls_are_loopback_only(monkeypatch):
    monkeypatch.setenv("EDGE_GATEWAY_PORT", "28000")
    assert ci_runtime.local_url("EDGE_GATEWAY_PORT", "8000", "/ready") == "http://127.0.0.1:28000/ready"
    monkeypatch.setenv("EDGE_GATEWAY_PORT", "99999")
    with pytest.raises(ValueError):
        ci_runtime.local_url("EDGE_GATEWAY_PORT", "8000", "/ready")


def test_full_stack_warmup_uses_registered_telemetry_and_fog_only_snapshot(monkeypatch):
    hosted(monkeypatch)
    urls, commands = [], []
    snapshot = {"overview": {"active_edge_nodes": 5, "accepted_messages": 1},
                "analytics": {"latest_anomalies": [{}], "active_alerts": [{}]}}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def open_url(request, **kwargs):
        urls.append(request)
        return Response()

    def snapshot_command(command, **kwargs):
        commands.append(command)
        assert kwargs["timeout"] == 15
        return json.dumps(snapshot)

    monkeypatch.setattr(ci_runtime, "urlopen", open_url)
    monkeypatch.setattr(ci_runtime, "get_json", lambda url: {"data": {"activeTargets": [{"health": "up"}]}})
    monkeypatch.setattr(ci_runtime, "docker_executable", lambda: "docker")
    monkeypatch.setattr(ci_runtime.subprocess, "check_output", snapshot_command)
    ci_runtime.wait(10)
    assert urls[0].endswith("/ready")
    message = json.loads(urls[1].data)
    assert message["device_id"] == "edge-device-01" and message["event_type"] == "attack"
    assert urls[1].full_url.startswith("http://127.0.0.1:")
    assert commands[0][:6] == ["docker", "compose", "-p", "software-data-diode-audit", "--profile", "full"]
    assert commands[0][6:11] == ["exec", "-T", "dashboard", "python", "-c"]
    assert "http://monitoring-api:8000/api/snapshot" in commands[0][-1]


def test_runtime_audit_writes_fresh_failure_evidence_if_stack_is_missing(tmp_path, monkeypatch):
    from scripts import audit_runtime

    report = tmp_path / "new-run/runtime.json"
    monkeypatch.setattr(sys, "argv", ["audit_runtime.py", "--output", str(report)])
    monkeypatch.setattr(audit_runtime, "docker_executable", lambda: "docker")

    def missing_stack(*args, **kwargs):
        raise RuntimeError("disposable stack unavailable")

    monkeypatch.setattr(audit_runtime.subprocess, "check_output", missing_stack)
    assert audit_runtime.main() == 1
    results = json.loads(report.read_text())
    assert results[0]["passed"] is False
    assert results[0]["evidence"] == "disposable stack unavailable"

"""CI-only bootstrap and bounded warm-up of the disposable full-stack audit."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.docker_support import docker_executable
from scripts.validate_config import parse_env, REQUIRED_SECRETS


def require_hosted_runner() -> None:
    if (os.getenv("GITHUB_ACTIONS") != "true"
            or os.getenv("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.getenv("RUNNER_OS") != "Linux"):
        raise RuntimeError("Docker CI preparation is restricted to GitHub-hosted Linux runners")


def prepare(root: Path = ROOT) -> None:
    require_hosted_runner()
    protected = [root / ".env", root / "secrets/edge_private_key.pem",
                 root / "secrets/edge_public_key.pem"]
    if any(path.exists() or path.is_symlink() for path in protected):
        raise RuntimeError("CI requires a clean checkout; refusing existing credentials or signing keys")
    subprocess.run([sys.executable, str(root / "scripts/setup.py")], cwd=root, check=True)
    for name in REQUIRED_SECRETS:
        value = parse_env(root / ".env")[name]
        if not value or "\n" in value or "\r" in value:
            raise RuntimeError("Invalid generated CI secret")
        print("::add-mask::" + value, flush=True)
    (root / ".env").chmod(0o600)
    (root / "secrets").chmod(0o755)
    private = root / "secrets/edge_private_key.pem"
    private.chmod(0o400)
    (root / "secrets/edge_public_key.pem").chmod(0o644)
    (root / "security-reports").chmod(0o755)
    # Bind mounts retain host ownership; grant only the container UID access.
    subprocess.run(["sudo", "chown", "10001:10001", str(private),
                    str(root / "security-reports")], check=True)


def poll_until(name, predicate, timeout, *, clock=time.monotonic, sleep=time.sleep):
    if type(timeout) not in (int, float) or not 0 < timeout <= 300:
        raise ValueError("CI polling timeout must be in (0, 300] seconds")
    deadline = clock() + timeout
    last = "condition not yet satisfied"
    while clock() < deadline:
        try:
            if predicate():
                return
            last = "condition not yet satisfied"
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
            last = type(exc).__name__
        sleep(min(2, max(0, deadline - clock())))
    raise TimeoutError(f"{name} did not become ready: {last}")


def local_url(setting, fallback, path):
    port = int(os.getenv(setting, fallback))
    if not 1 <= port <= 65535:
        raise ValueError("Invalid CI loopback port")
    return f"http://127.0.0.1:{port}{path}"


def get_json(url):
    with urlopen(url, timeout=5) as response:
        if response.status != 200:
            raise RuntimeError("CI endpoint is not ready")
        return json.load(response)


def telemetry_ready(snapshot):
    overview = snapshot["overview"]
    analytics = snapshot["analytics"]
    return (overview["active_edge_nodes"] == 5 and overview["accepted_messages"] > 0
            and bool(analytics["latest_anomalies"]) and bool(analytics["active_alerts"]))


def targets_ready(document):
    targets = document["data"]["activeTargets"]
    return bool(targets) and all(target["health"] == "up" for target in targets)


def wait(timeout):
    require_hosted_runner()
    gateway = local_url("EDGE_GATEWAY_PORT", "28000", "/ready")

    def gateway_ready():
        with urlopen(gateway, timeout=5) as response:
            return response.status == 200

    poll_until("Edge Gateway", gateway_ready, timeout)
    # A registered synthetic device stimulates analytics without adding a sixth node.
    message = {"device_id": "edge-device-01", "timestamp": datetime.now(timezone.utc).isoformat(),
               "telemetry_type": "environmental", "temperature": 45, "humidity": 50,
               "status": "critical", "event_type": "attack", "attributes": {"ci_smoke": True}}
    request = Request(local_url("EDGE_GATEWAY_PORT", "28000", "/telemetry"),
                      data=json.dumps(message).encode("utf-8"),
                      headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError("Synthetic CI telemetry was not accepted")

    compose = [docker_executable(), "compose", "-p", "software-data-diode-audit", "--profile", "full"]
    snapshot_code = ("import requests; r=requests.get('http://monitoring-api:8000/api/snapshot',"
                     "timeout=10); r.raise_for_status(); print(r.text)")

    def snapshot_ready():
        raw = subprocess.check_output(compose + ["exec", "-T", "dashboard", "python", "-c", snapshot_code],
                                      cwd=ROOT, text=True, timeout=15)
        return telemetry_ready(json.loads(raw))

    poll_until("five-device persistence and analytics", snapshot_ready, timeout)
    for setting, port in (("PROMETHEUS_EDGE_PORT", "29091"), ("PROMETHEUS_FOG_PORT", "29090")):
        target_url = local_url(setting, port, "/api/v1/targets")
        poll_until(setting + " scrape targets", lambda: targets_ready(get_json(target_url)), timeout)
    print("Full-stack telemetry, analytics and scrape targets are ready.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "wait"))
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare()
    else:
        wait(args.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

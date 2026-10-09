from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.request import urlopen


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from scripts.docker_support import docker_executable
PYTHON = PROJECT_ROOT / ".venv/Scripts/python.exe" if sys.platform == "win32" else PROJECT_ROOT / ".venv/bin/python"


def run(command: list[str]) -> None:
    print("+ " + " ".join(str(item) for item in command), flush=True)
    subprocess.run(command, cwd=PROJECT_ROOT, check=True)


def wait_for_url(name: str, url: str, timeout_seconds: float = 120) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(2)
    raise RuntimeError(f"{name} did not become ready within {timeout_seconds} seconds")


def wait_for_gateway(timeout_seconds: float = 120) -> None:
    wait_for_url("gateway", f"http://127.0.0.1:{os.environ['EDGE_GATEWAY_PORT']}/ready", timeout_seconds)


def wait_for_gateway_unready(timeout_seconds: float = 30) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with urlopen(f"http://127.0.0.1:{os.environ['EDGE_GATEWAY_PORT']}/ready", timeout=2) as response:
                if response.status != 200:
                    return
        except OSError:
            return
        time.sleep(1)
    raise RuntimeError("gateway remained ready after a required dependency stopped")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run all Phase 8 verification suites.")
    parser.add_argument(
        "--local-only",
        action="store_true",
        help="Run configuration and pytest checks without Docker integration/security tests.",
    )
    args = parser.parse_args()
    if not PYTHON.exists():
        raise SystemExit("Virtual environment missing. Create .venv and install requirements-dev.txt")

    run([str(PYTHON), "scripts/validate_config.py", "--example"])
    run([str(PYTHON), "-m", "pytest"])
    if args.local_only:
        print("Local unit and integration tests passed; Docker suites were explicitly skipped.")
        return 0

    docker = docker_executable()
    os.environ["PATH"] = str(Path(docker).parent) + os.pathsep + os.environ.get("PATH", "")
    for setting, port in (("EDGE_GATEWAY_PORT", "28000"), ("DASHBOARD_PORT", "28501"),
                          ("PROMETHEUS_FOG_PORT", "29090"), ("PROMETHEUS_EDGE_PORT", "29091"),
                          ("GRAFANA_PORT", "23000")):
        os.environ.setdefault(setting, port)
    if not (PROJECT_ROOT / ".env").exists():
        raise SystemExit("Missing .env. Run: python scripts/setup.py")
    run([str(PYTHON), "scripts/validate_config.py"])

    compose = [
        docker,
        "compose",
        "-p",
        "software-data-diode-verification",
        "--profile",
        "full",
    ]
    try:
        run(compose + ["config", "--quiet"])
        run(compose + ["up", "--build", "-d"])
        wait_for_gateway()
        wait_for_url("Streamlit dashboard", f"http://127.0.0.1:{os.environ['DASHBOARD_PORT']}/_stcore/health")
        wait_for_url("Fog Prometheus", f"http://127.0.0.1:{os.environ['PROMETHEUS_FOG_PORT']}/-/ready")
        wait_for_url("Edge Prometheus", f"http://127.0.0.1:{os.environ['PROMETHEUS_EDGE_PORT']}/-/ready")
        wait_for_url("Grafana", f"http://127.0.0.1:{os.environ['GRAFANA_PORT']}/api/health")
        run(compose + ["exec", "-T", "postgres", "pg_isready", "-U", "fog", "-d", "fog_data"])
        with urlopen(f"http://127.0.0.1:{os.environ['EDGE_GATEWAY_PORT']}/devices", timeout=5) as response:
            if response.status != 200:
                raise RuntimeError("gateway integration endpoint failed")

        print("Testing Fog Receiver outage and recovery", flush=True)
        run(compose + ["stop", "fog-receiver"])
        wait_for_gateway_unready()
        run(compose + ["start", "fog-receiver"])
        wait_for_gateway()

        print("Testing PostgreSQL outage and recovery", flush=True)
        run(compose + ["stop", "postgres"])
        wait_for_gateway_unready()
        run(compose + ["start", "postgres"])
        wait_for_gateway()

        print("Testing Data Diode and Edge Gateway restarts", flush=True)
        run(compose + ["restart", "data-diode"])
        wait_for_gateway()
        run(compose + ["restart", "edge-gateway"])
        wait_for_gateway()
    finally:
        subprocess.run(
            compose + ["down", "--volumes", "--remove-orphans"],
            cwd=PROJECT_ROOT,
            check=False,
        )

    if sys.platform == "win32":
        run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                "scripts/run_security_tests.ps1",
            ]
        )
    else:
        raise SystemExit("Run the security-test profile using the commands in docs/deployment.md")
    print("Unit, integration, and security suites passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

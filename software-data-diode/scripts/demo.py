from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from shared.models import PriorityLevel, SecureTelemetryEnvelope, TelemetryPayload
from shared.security import compute_payload_hash, load_private_key, sign_envelope
from scripts.docker_support import docker_executable


def gateway_url(path):
    return f"http://127.0.0.1:{os.getenv('EDGE_GATEWAY_PORT', '8000')}{path}"


PLAN = (
    "Normal telemetry",
    "HIGH alert",
    "CRITICAL security event",
    "Tampered message",
    "Replay attempt",
    "Traffic congestion",
    "Adaptive scheduler response",
    "Fog anomaly",
)


def edge_message(
    device_id: str,
    *,
    temperature: float,
    status: str,
    event_type: str,
    attributes: dict[str, object] | None = None,
    measurements: dict[str, float] | None = None,
) -> dict[str, object]:
    return {
        "device_id": device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "temperature": temperature,
        "humidity": 52.0,
        "status": status,
        "event_type": event_type,
        "attributes": attributes or {},
        "measurements": measurements or {},
    }


def post_gateway(message: dict[str, object]) -> dict[str, object]:
    request = Request(
        gateway_url("/telemetry"),
        data=json.dumps(message).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            return {"http_status": response.status, "body": json.loads(response.read())}
    except HTTPError as exc:
        return {"http_status": exc.code, "body": json.loads(exc.read())}
    except OSError as exc:
        return {"http_status": 0, "body": {"error": type(exc).__name__}}


def signed_envelope(device_id: str, sequence: int) -> SecureTelemetryEnvelope:
    payload = TelemetryPayload(
        temperature=26.0,
        humidity=50.0,
        status="demo",
        event_type="security_validation",
    )
    envelope = SecureTelemetryEnvelope(
        message_id=uuid4(),
        device_id=device_id,
        created_at=datetime.now(timezone.utc),
        sequence_number=sequence,
        priority=PriorityLevel.HIGH,
        payload=payload,
        payload_hash=compute_payload_hash(payload),
        signature="unsigned",
    )
    key = load_private_key(PROJECT_ROOT / "secrets/edge_private_key.pem")
    return envelope.model_copy(update={"signature": sign_envelope(envelope, key)})


def fog_post_from_diode(envelope: dict[str, object]) -> dict[str, object]:
    code = (
        "import json,sys,urllib.request,urllib.error; "
        "data=sys.stdin.buffer.read(); "
        "req=urllib.request.Request('http://fog-receiver:8000/receive',data=data,"
        "headers={'Content-Type':'application/json'},method='POST'); "
        "\ntry:\n r=urllib.request.urlopen(req,timeout=10); print(r.read().decode())"
        "\nexcept urllib.error.HTTPError as e:\n print(e.read().decode())"
    )
    completed = subprocess.run(
        [
            docker_executable(),
            "compose",
            "--profile",
            "full",
            "exec",
            "-T",
            "data-diode",
            "python",
            "-c",
            code,
        ],
        cwd=PROJECT_ROOT,
        input=json.dumps(envelope).encode("utf-8"),
        capture_output=True,
        check=True,
    )
    output = completed.stdout.decode("utf-8").strip().splitlines()
    return json.loads(output[-1]) if output else {"error": "empty response"}


def diode_runtime() -> dict[str, object]:
    code = "import json,urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/metrics/runtime').read().decode())"
    completed = subprocess.run(
        [docker_executable(), "compose", "--profile", "full", "exec", "-T", "data-diode", "python", "-c", code],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(completed.stdout.strip().splitlines()[-1])


def wait_ready(timeout: float = 120) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urlopen(gateway_url("/ready"), timeout=2) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(2)
    raise RuntimeError("full deployment did not become ready")


def gateway_is_ready() -> bool:
    try:
        with urlopen(gateway_url("/ready"), timeout=2) as response:
            return response.status == 200
    except OSError:
        return False


def require_docker_engine() -> None:
    completed = subprocess.run(
        [docker_executable(), "info", "--format", "{{.ServerVersion}}"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(
            "Docker Desktop Linux engine is not running. Open Docker Desktop, "
            "wait until it reports Engine running, then run this command again."
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the deterministic faculty demo sequence.")
    parser.add_argument("--start-stack", action="store_true", help="Build and start the full profile first.")
    parser.add_argument("--stop-after", action="store_true", help="Stop the full profile after the demo.")
    parser.add_argument("--dry-run", action="store_true", help="Print the sequence without Docker traffic.")
    args = parser.parse_args()
    for number, name in enumerate(PLAN, 1):
        print(f"{number}. {name}")
    if args.dry_run:
        return 0
    require_docker_engine()
    if not (PROJECT_ROOT / ".env").exists():
        raise SystemExit("Run python scripts/setup.py before the demo")

    compose = [docker_executable(), "compose", "--profile", "full"]
    if args.start_stack:
        subprocess.run(compose + ["up", "--build", "-d"], cwd=PROJECT_ROOT, check=True)
    elif not gateway_is_ready():
        print("Full deployment is not running; starting it now.", flush=True)
        subprocess.run(compose + ["up", "-d"], cwd=PROJECT_ROOT, check=True)
    wait_ready()
    results: list[dict[str, object]] = []
    try:
        results.append({"step": PLAN[0], "result": post_gateway(edge_message("demo-normal", temperature=25.0, status="normal", event_type="telemetry"))})
        results.append({"step": PLAN[1], "result": post_gateway(edge_message("demo-high", temperature=41.0, status="warning", event_type="telemetry"))})
        results.append({"step": PLAN[2], "result": post_gateway(edge_message("demo-critical", temperature=30.0, status="critical", event_type="attack", measurements={"failed_logins": 12.0}))})

        tampered = signed_envelope(f"demo-tamper-{uuid4().hex[:8]}", 1).model_dump(mode="json")
        tampered["payload"]["temperature"] = 999.0
        results.append({"step": PLAN[3], "result": fog_post_from_diode(tampered)})

        replay_device = f"demo-replay-{uuid4().hex[:8]}"
        first = signed_envelope(replay_device, 2)
        fog_post_from_diode(first.model_dump(mode="json"))
        replay = signed_envelope(replay_device, 1)
        results.append({"step": PLAN[4], "result": fog_post_from_diode(replay.model_dump(mode="json"))})

        flood = [
            edge_message(
                "demo-congestion",
                temperature=39.0,
                status="warning",
                event_type="telemetry",
                attributes={"demo_sequence": index},
            )
            for index in range(120)
        ]
        with ThreadPoolExecutor(max_workers=24) as executor:
            flood_results = list(executor.map(post_gateway, flood))
        results.append(
            {
                "step": PLAN[5],
                "result": {
                    "requests": len(flood_results),
                    "forwarded": sum(item["http_status"] == 200 for item in flood_results),
                    "backpressure": sum(item["http_status"] in {429, 502, 503} for item in flood_results),
                },
            }
        )
        results.append({"step": PLAN[6], "result": diode_runtime()})
        results.append(
            {
                "step": PLAN[7],
                "result": post_gateway(
                    edge_message(
                        "demo-anomaly",
                        temperature=45.0,
                        status="abnormal",
                        event_type="telemetry",
                        attributes={"demo_id": uuid4().hex},
                    )
                ),
            }
        )
        output = PROJECT_ROOT / "demo-results/latest.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {"timestamp": datetime.now(timezone.utc).isoformat(), "steps": results},
                indent=2,
                default=str,
            )
            + "\n",
            encoding="utf-8",
        )
        for number, item in enumerate(results, 1):
            print(f"[{number}] {item['step']}: {json.dumps(item['result'], default=str)[:500]}")
        print(f"Demo evidence: {output}")
    finally:
        if args.stop_after:
            subprocess.run(compose + ["down", "--remove-orphans"], cwd=PROJECT_ROOT, check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

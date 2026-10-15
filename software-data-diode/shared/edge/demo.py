"""Bounded N11 fixtures and forward faults; never a production policy input."""
import argparse
import asyncio
import json
import os
import re
import time
from datetime import datetime, timezone

import httpx

from shared.edge.coverage_client import research_headers
from shared.models import EdgeTelemetryMessage

SCENARIOS = ("normal-reduction", "registered-match", "cross-device-incident",
             "raw-loss", "evidence-loss", "tampering")
TYPES = ("environmental", "system", "network", "security", "industrial")


def demo_project(project):
    if project != "software-data-diode-coverage" and not re.fullmatch(
            r"software-data-diode-coverage-n11-[a-f0-9]{12}", project):
        raise ValueError("N11 requires an isolated coverage project")
    return project


def require_demo():
    if os.getenv("N11_DEMO_ENABLED") != "true":
        raise ValueError("N11 demo is not enabled")
    return demo_project(os.environ["N11_PROJECT"])


def payload(device, stage, timestamp):
    number = int(device[-2:])
    if device != f"edge-device-{number:02}" or not 1 <= number <= 5:
        raise ValueError("unregistered demo device")
    if stage not in (*SCENARIOS, "recovery"):
        raise ValueError("unknown demo scenario")
    hot = (stage in {"cross-device-incident", "raw-loss", "recovery"}
           or (stage == "registered-match" and number == 1))
    values = {"temperature": 40 if hot and number == 1 else 25,
              "humidity": 50, "cpu_usage": 95 if hot else 30,
              "measurements": {"packets_per_second": 9000 if hot else 1000,
                               "failed_logins": 6 if hot else 0,
                               "vibration_mm_s": 9 if hot else 2},
              "status": "normal", "event_type": ("environmental_telemetry", "resource", "network", "security", "industrial_process")[number-1],
              "attributes": {"synthetic_demo": True, "n11_scenario": stage}}
    return EdgeTelemetryMessage(device_id=device, telemetry_type=TYPES[number-1],
                                timestamp=timestamp, **values)


async def send_device(start, stages):
    require_demo()
    device = os.environ["DEVICE_ID"]
    if not start % 10 == 0 or not time.time()+1 < start < time.time()+120:
        raise ValueError("demo start must be a near-future aligned UTC boundary")
    rows = []
    async with httpx.AsyncClient(timeout=4) as client:
        for offset, stage in enumerate(stages):
            # Stay well clear of admission-window boundaries; no receiver feedback.
            due = start+offset*10+2
            await asyncio.sleep(max(0, due-time.time()))
            if time.time() > due+2:
                raise RuntimeError("missed deterministic admission slot")
            for sample in range(5):
                message = payload(device, stage, datetime.now(timezone.utc))
                response = await client.post("http://edge-gateway:8000/telemetry",
                    json=message.model_dump(mode="json"), headers=research_headers(device))
                response.raise_for_status()
                receipt = response.json()
                if receipt.get("window_index") != (start//10+offset):
                    raise RuntimeError("admission landed in a different window")
                rows.append({"scenario": stage, "sample": sample, "receipt": receipt,
                             "original": message.model_dump(mode="json")})
                await asyncio.sleep(.12)
    print(json.dumps({"device_id": device, "observations": rows}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", required=True, type=int)
    parser.add_argument("--recovery", action="store_true")
    args = parser.parse_args()
    asyncio.run(send_device(args.start, ("recovery",) if args.recovery else SCENARIOS))

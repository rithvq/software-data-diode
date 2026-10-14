import asyncio
from datetime import datetime, timezone
import logging
import math
import os
import random

import httpx

from shared.models import EdgeTelemetryMessage, PriorityLevel, TelemetryType
from shared.observability import configure_json_logging, log_context

configure_json_logging(os.getenv("DEVICE_ID", "edge-device"))
logger = logging.getLogger("edge-device")

DEVICE_ID = os.getenv("DEVICE_ID", "edge-device-001")
DEVICE_TYPE = TelemetryType(os.getenv("DEVICE_TYPE", "environmental").lower())
EDGE_GATEWAY_URL = os.getenv(
    "EDGE_GATEWAY_URL",
    "http://edge-gateway:8000/telemetry",
)
TELEMETRY_INTERVAL_SECONDS = float(os.getenv("TELEMETRY_INTERVAL_SECONDS", "3"))
REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "5"))
TRAFFIC_PROFILE = os.getenv("TRAFFIC_PROFILE", "normal").lower()
BURST_SIZE = int(os.getenv("BURST_SIZE", "10"))
BURST_INTERVAL_SECONDS = float(os.getenv("BURST_INTERVAL_SECONDS", "10"))
OVERLOAD_INTERVAL_SECONDS = float(os.getenv("OVERLOAD_INTERVAL_SECONDS", "0.05"))
CRITICAL_BURST_SIZE = int(os.getenv("CRITICAL_BURST_SIZE", "5"))
CRITICAL_BURST_EVERY_N_MESSAGES = int(os.getenv("CRITICAL_BURST_EVERY_N_MESSAGES", "20"))

PRIORITY_DISTRIBUTION = {
    PriorityLevel.LOW: float(os.getenv("LOW_TRAFFIC_PERCENT", "70")),
    PriorityLevel.MEDIUM: float(os.getenv("MEDIUM_TRAFFIC_PERCENT", "20")),
    PriorityLevel.HIGH: float(os.getenv("HIGH_TRAFFIC_PERCENT", "8")),
    PriorityLevel.CRITICAL: float(os.getenv("CRITICAL_TRAFFIC_PERCENT", "2")),
}

if os.getenv("DEVICE_SEED"):
    random.seed(int(os.environ["DEVICE_SEED"]))


def validate_configuration():
    if TRAFFIC_PROFILE not in {"normal", "burst", "overload", "critical_burst"}:
        raise ValueError("unknown traffic profile")
    for value in (TELEMETRY_INTERVAL_SECONDS, REQUEST_TIMEOUT_SECONDS, BURST_INTERVAL_SECONDS,
                  OVERLOAD_INTERVAL_SECONDS, BURST_SIZE, CRITICAL_BURST_SIZE, CRITICAL_BURST_EVERY_N_MESSAGES):
        if not math.isfinite(value) or value <= 0:
            raise ValueError("device intervals and burst counts must be finite and positive")
    weights = list(PRIORITY_DISTRIBUTION.values())
    if any(not math.isfinite(value) or value < 0 for value in weights) or abs(sum(weights) - 100) > 0.001:
        raise ValueError("device priority percentages must be nonnegative and total 100")


validate_configuration()


def generate_telemetry(priority: PriorityLevel | None = None) -> EdgeTelemetryMessage:
    selected_priority = priority or _choose_priority()
    values = _profile_values(selected_priority)
    return EdgeTelemetryMessage(
        device_id=DEVICE_ID,
        timestamp=datetime.now(timezone.utc),
        telemetry_type=DEVICE_TYPE,
        **values,
    )


def _profile_values(priority: PriorityLevel) -> dict[str, object]:
    elevated = priority in {PriorityLevel.HIGH, PriorityLevel.CRITICAL}
    warning = priority == PriorityLevel.MEDIUM
    base: dict[str, object] = {
        "temperature": round(random.uniform(24.0, 27.0), 2),
        "humidity": round(random.uniform(45.0, 60.0), 2),
        "status": "normal",
        "event_type": f"{DEVICE_TYPE}_telemetry",
        "attributes": {"virtual_node": True},
    }

    if DEVICE_TYPE == TelemetryType.ENVIRONMENTAL:
        base.update(
            temperature=round(random.uniform(40.0, 45.0), 2) if elevated else base["temperature"],
            humidity=round(random.uniform(70.0, 90.0), 2) if warning else base["humidity"],
            status="hot" if elevated else "warning" if warning else "normal",
            measurements={"air_quality_index": random.uniform(20.0, 75.0)},
        )
    elif DEVICE_TYPE == TelemetryType.SYSTEM:
        base.update(
            event_type="resource",
            status="critical" if priority == PriorityLevel.CRITICAL else "degraded" if warning else "normal",
            cpu_usage=round(random.uniform(92.0, 99.0), 2) if elevated else round(random.uniform(20.0, 65.0), 2),
            memory_usage=round(random.uniform(88.0, 97.0), 2) if warning or elevated else round(random.uniform(30.0, 70.0), 2),
            measurements={"load_average": round(random.uniform(0.5, 8.0), 2)},
        )
    elif DEVICE_TYPE == TelemetryType.NETWORK:
        base.update(
            event_type="network",
            status="traffic_spike" if elevated else "degraded" if warning else "normal",
            measurements={
                "packets_per_second": round(random.uniform(8500.0, 13000.0), 2) if elevated else round(random.uniform(800.0, 3500.0), 2),
                "network_latency_ms": round(random.uniform(260.0, 500.0), 2) if warning else round(random.uniform(10.0, 80.0), 2),
                "packet_loss_percent": round(random.uniform(0.0, 3.0), 3),
            },
        )
    elif DEVICE_TYPE == TelemetryType.SECURITY:
        failed = random.randint(6, 15) if elevated else random.randint(0, 2)
        base.update(
            event_type="intrusion" if priority == PriorityLevel.CRITICAL else "security",
            status="critical" if elevated else "warning" if warning else "normal",
            measurements={"failed_logins": float(failed), "blocked_connections": float(random.randint(0, 8))},
        )
    else:
        base.update(
            event_type="industrial_process",
            status="critical" if priority == PriorityLevel.CRITICAL else "warning" if warning else "normal",
            measurements={
                "pressure_bar": round(random.uniform(14.5, 18.0), 2) if elevated else round(random.uniform(7.0, 11.0), 2),
                "vibration_mm_s": round(random.uniform(8.5, 12.0), 2) if elevated else round(random.uniform(1.0, 4.0), 2),
                "rpm": round(random.uniform(1200.0, 1800.0), 2),
            },
        )
    if priority == PriorityLevel.CRITICAL:
        base["status"] = "critical"
    return base


async def send_forever() -> None:
    logger.info(
        "[EDGE DEVICE] Starting traffic profile=%s device_id=%s type=%s",
        TRAFFIC_PROFILE,
        DEVICE_ID,
        DEVICE_TYPE,
    )
    logger.info("[EDGE DEVICE] Sending to %s", EDGE_GATEWAY_URL)

    message_count = 0
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        while True:
            if TRAFFIC_PROFILE == "burst":
                for _ in range(BURST_SIZE):
                    message_count += 1
                    await _send_one(client, generate_telemetry())
                await asyncio.sleep(BURST_INTERVAL_SECONDS)
                continue

            if TRAFFIC_PROFILE == "overload":
                message_count += 1
                await _send_one(client, generate_telemetry())
                await asyncio.sleep(OVERLOAD_INTERVAL_SECONDS)
                continue

            if (
                TRAFFIC_PROFILE == "critical_burst"
                and message_count > 0
                and message_count % CRITICAL_BURST_EVERY_N_MESSAGES == 0
            ):
                for _ in range(CRITICAL_BURST_SIZE):
                    await _send_one(client, generate_telemetry(PriorityLevel.CRITICAL))
                message_count += CRITICAL_BURST_SIZE
                await asyncio.sleep(TELEMETRY_INTERVAL_SECONDS)
                continue

            message_count += 1
            await _send_one(client, generate_telemetry())
            await asyncio.sleep(TELEMETRY_INTERVAL_SECONDS)


async def _send_one(client: httpx.AsyncClient, message: EdgeTelemetryMessage) -> None:
    logger.info(
        "[EDGE DEVICE] Generated unsigned telemetry event_type=%s status=%s",
        message.event_type,
        message.status,
        extra=log_context(
            "telemetry_generated",
            device_id=message.device_id,
            correlation_id=f"{message.device_id}:{message.timestamp.isoformat()}",
            telemetry_type=message.telemetry_type,
        ),
    )
    try:
        headers = None
        if os.getenv("RULE_COVERAGE_ENABLED", "false").lower() == "true":
            from shared.edge.coverage_client import research_headers
            headers = research_headers(message.device_id)
        response = await client.post(
            EDGE_GATEWAY_URL,
            json=message.model_dump(mode="json"),
            **({"headers": headers} if headers else {}),
        )
        response.raise_for_status()
        logger.info("[EDGE DEVICE] Gateway response=%s", response.json())
    except httpx.HTTPError as exc:
        logger.error("[EDGE DEVICE] Failed to send telemetry: %s", exc)


def _choose_priority() -> PriorityLevel:
    levels = list(PRIORITY_DISTRIBUTION.keys())
    weights = list(PRIORITY_DISTRIBUTION.values())
    return random.choices(levels, weights=weights, k=1)[0]


if __name__ == "__main__":
    asyncio.run(send_forever())

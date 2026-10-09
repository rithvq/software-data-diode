import asyncio
from datetime import datetime, timezone
import logging
import os
import random
from uuid import uuid4

import httpx

from .models import Payload, Telemetry


def generate(sequence: int, rng: random.Random, device_id: str = "edge-device-01") -> Telemetry:
    return Telemetry(
        message_id=uuid4(), device_id=device_id, timestamp=datetime.now(timezone.utc),
        sequence_number=sequence,
        payload=Payload(temperature=round(rng.uniform(24, 29), 2), humidity=round(rng.uniform(40, 65), 2), status="normal"),
    )


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    rng = random.Random(int(os.getenv("PHASE1_DEVICE_SEED", "101")))
    interval = float(os.getenv("PHASE1_DEVICE_INTERVAL", "1"))
    if interval <= 0:
        raise ValueError("device interval must be positive")
    sequence = 0
    async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
        while True:
            sequence += 1
            message = generate(sequence, rng)
            while True:
                try:
                    response = await client.post("http://edge-gateway:8000/telemetry", content=message.model_dump_json(), headers={"content-type": "application/json"})
                    response.raise_for_status()
                    break
                except httpx.HTTPError as exc:
                    logging.warning("Retrying message_id=%s sequence_number=%s: %s", message.message_id, sequence, exc)
                    await asyncio.sleep(1)
            logging.info("Generated message_id=%s device_id=%s sequence_number=%s", message.message_id, message.device_id, sequence)
            await asyncio.sleep(interval)


if __name__ == "__main__":
    asyncio.run(main())

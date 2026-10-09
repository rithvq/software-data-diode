import asyncio
import logging
import os
from pathlib import Path
import random
import sqlite3

import httpx

from phase1.device import generate
from .models import SourceMessage
from .security import canonical


def generate_source(sequence, rng):
    original = generate(sequence, rng)
    payload = original.payload.model_dump(mode="json")
    return SourceMessage(**{**original.model_dump(mode="python"), "payload": payload},
                         created_at=original.timestamp, message_type="environmental",
                         priority="LOW", base_priority="LOW", event_class="TEMPERATURE_STATE",
                         payload_size=len(canonical(payload)), supersession_key="edge01.temperature.current",
                         aggregation_allowed=True, sampling_allowed=True, must_preserve=False)


class DeviceState:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS device (id INTEGER PRIMARY KEY, sequence INTEGER, pending TEXT)")
        self.db.execute("INSERT OR IGNORE INTO device VALUES (1, 0, NULL)")
        self.db.commit()

    def next(self, rng):
        sequence, pending = self.db.execute("SELECT sequence, pending FROM device WHERE id=1").fetchone()
        if pending:
            return SourceMessage.model_validate_json(pending)
        message = generate_source(sequence + 1, rng)
        with self.db:
            self.db.execute("UPDATE device SET sequence=?, pending=? WHERE id=1",
                            (sequence + 1, message.model_dump_json()))
        return message

    def complete(self):
        with self.db:
            self.db.execute("UPDATE device SET pending=NULL WHERE id=1")


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    directory = Path(os.getenv("PHASE2_STATE_DIRECTORY", "/state"))
    directory.mkdir(parents=True, exist_ok=True)
    state = DeviceState(directory / "device.sqlite3")
    rng = random.Random(101)
    interval = float(os.getenv("PHASE2_DEVICE_INTERVAL", "1"))
    if interval <= 0:
        raise ValueError("device interval must be positive")
    async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
        while True:
            message = state.next(rng)
            try:
                response = await client.post("http://edge-gateway:8000/telemetry",
                                             content=canonical(message.model_dump(mode="json")),
                                             headers={"content-type": "application/json"})
                if 400 <= response.status_code < 500 and response.status_code not in {408, 429}:
                    logging.error("Rejected message_id=%s reason=%s", message.message_id, response.text[:200])
                else:
                    response.raise_for_status()
                    logging.info("Sent message_id=%s sequence=%s", message.message_id, message.sequence_number)
                state.complete()
                await asyncio.sleep(interval)
            except httpx.HTTPError as exc:
                logging.warning("Retrying message_id=%s: %s", message.message_id, exc)
                await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from shared.models import PriorityLevel, SecureTelemetryEnvelope, TelemetryPayload
from shared.security import compute_payload_hash, load_private_key, sign_envelope


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a valid signed telemetry envelope.")
    parser.add_argument("--private-key", default="secrets/edge_private_key.pem")
    parser.add_argument("--output", default="sample-envelope.json")
    parser.add_argument("--device-id", default="edge-device-001")
    parser.add_argument("--sequence-number", type=int, default=1)
    parser.add_argument(
        "--priority",
        choices=[priority.value for priority in PriorityLevel],
        default=PriorityLevel.LOW.value,
    )
    parser.add_argument("--estimated-transmission-cost", type=float, default=1.0)
    parser.add_argument("--temperature", type=float, default=28.5)
    parser.add_argument("--humidity", type=float, default=62.3)
    parser.add_argument("--status", default="normal")
    parser.add_argument("--event-type", default="telemetry")
    args = parser.parse_args()

    payload = TelemetryPayload(
        temperature=args.temperature,
        humidity=args.humidity,
        status=args.status,
        event_type=args.event_type,
    )
    envelope = SecureTelemetryEnvelope(
        message_id=uuid4(),
        device_id=args.device_id,
        created_at=datetime.now(timezone.utc),
        sequence_number=args.sequence_number,
        priority=PriorityLevel(args.priority),
        payload=payload,
        payload_hash=compute_payload_hash(payload),
        signature="unsigned",
        estimated_transmission_cost=args.estimated_transmission_cost,
        schema_version="1.0",
    )
    signature = sign_envelope(envelope, load_private_key(args.private_key))
    signed = envelope.model_copy(update={"signature": signature})

    Path(args.output).write_text(
        json.dumps(signed.model_dump(mode="json"), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(f"Wrote signed envelope: {args.output}")


if __name__ == "__main__":
    main()

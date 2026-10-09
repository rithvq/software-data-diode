import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a tampered envelope JSON file.")
    parser.add_argument("input", help="Source envelope JSON file")
    parser.add_argument("output", help="Destination tampered JSON file")
    parser.add_argument(
        "--attack",
        choices=["payload", "hash", "signature", "timestamp", "sequence"],
        required=True,
    )
    args = parser.parse_args()

    data = json.loads(Path(args.input).read_text(encoding="utf-8"))

    if args.attack == "payload":
        data["payload"]["temperature"] = float(data["payload"]["temperature"]) + 99.0
    elif args.attack == "hash":
        data["payload_hash"] = "0" * 64
    elif args.attack == "signature":
        data["signature"] = "invalid-signature"
    elif args.attack == "timestamp":
        data["created_at"] = "2000-01-01T00:00:00Z"
    elif args.attack == "sequence":
        data["sequence_number"] = 0

    Path(args.output).write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote tampered envelope: {args.output}")


if __name__ == "__main__":
    main()

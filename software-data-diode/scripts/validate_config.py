from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDER_MARKERS = ("replace-", "change-me", "example-password")
REQUIRED_SECRETS = ("POSTGRES_PASSWORD", "OBSERVABILITY_TOKEN", "GRAFANA_ADMIN_PASSWORD")
POSITIVE_NUMBERS = (
    "FORWARD_TIMEOUT_SECONDS",
    "FOG_FRESHNESS_WINDOW_SECONDS",
    "DUPLICATE_TTL_SECONDS",
    "MAX_MESSAGES_PER_SECOND",
    "BURST_LIMIT",
    "MAX_PAYLOAD_BYTES",
    "MAX_QUEUE_SIZE",
    "EGRESS_MESSAGES_PER_SECOND",
)


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"{path}: line {line_number} is not KEY=VALUE")
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def validate_environment(values: dict[str, str], *, allow_placeholders: bool = False) -> None:
    for name in REQUIRED_SECRETS:
        value = values.get(name, "")
        if not value:
            raise ValueError(f"missing required setting: {name}")
        if not allow_placeholders and any(marker in value.lower() for marker in PLACEHOLDER_MARKERS):
            raise ValueError(f"placeholder value is not allowed for {name}")
    for name in POSITIVE_NUMBERS:
        if name in values and (not math.isfinite(float(values[name])) or float(values[name]) <= 0):
            raise ValueError(f"{name} must be finite and greater than zero")
    priorities = [
        float(values.get(name, 0))
        for name in (
            "LOW_TRAFFIC_PERCENT",
            "MEDIUM_TRAFFIC_PERCENT",
            "HIGH_TRAFFIC_PERCENT",
            "CRITICAL_TRAFFIC_PERCENT",
        )
    ]
    if any(not math.isfinite(value) or value < 0 for value in priorities) or abs(sum(priorities) - 100.0) > 0.001:
        raise ValueError("default priority percentages must total 100")


def validate_json_files(root: Path) -> None:
    for relative in (
        "config/anomaly_rules.json",
        "config/correlation_rules.json",
        "config/information_policy.json",
        "experiments/workloads/information_workloads.json",
        "experiments/workloads/phase7_workloads.json",
    ):
        path = root / relative
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid JSON configuration: {path}: {exc}") from exc


def validate_constraints(path: Path) -> None:
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.-]+==[^\s]+", line):
            raise ValueError(f"{path}: line {line_number} is not exactly pinned")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate deployment configuration.")
    parser.add_argument("--env-file", type=Path, default=PROJECT_ROOT / ".env")
    parser.add_argument(
        "--example",
        action="store_true",
        help="Validate .env.example structure while permitting placeholders.",
    )
    args = parser.parse_args()
    env_path = PROJECT_ROOT / ".env.example" if args.example else args.env_file
    validate_environment(parse_env(env_path), allow_placeholders=args.example)
    validate_json_files(PROJECT_ROOT)
    validate_constraints(PROJECT_ROOT / "constraints.txt")
    print(f"Configuration valid: {env_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Configuration error: {exc}") from exc

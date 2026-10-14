"""Bounded experimental configuration and reproducible retained inputs, not runtime policy."""

import csv
import ctypes
import gzip
import hashlib
import json
import platform
import random
import re
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path

from shared.coverage.budget import AdmissionConfig, validate_budget
from shared.coverage.contracts import load_contract
from shared.coverage.models import IngressObservation, MetricReading
from shared.models import EdgeTelemetryMessage
from shared.security.crypto import canonical_bytes
from shared.traffic.priority import PriorityRuleConfig, classify_priority

ROOT = Path(__file__).resolve().parents[2]
EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)
ARMS = (
    "compact_summary",
    "fifo_gap",
    "legacy",
    "heartbeat",
    "fixed_summary",
    "rccd",
    "always_unknown",
    "no_semantics",
    "no_advance",
    "no_service",
    "no_repeats",
    "no_recovery",
)
FAULTS = ("none", "independent", "burst_loss", "evidence_only", "delay")


def read_config(path):
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if doc.get("schema_version") != "coverage-experiment-v1":
        raise ValueError("unsupported experiment schema")
    if (
        type(doc["runs_per_configuration"]) is not int
        or not 5 <= doc["runs_per_configuration"] <= 10
    ):
        raise ValueError("five to ten paired trials required")
    if (
        type(doc["duration_seconds"]) is not int
        or not 10 <= doc["duration_seconds"] <= 40
        or doc["duration_seconds"] % 10
    ):
        raise ValueError("bounded aligned 10-second windows required")
    if (
        not 1 <= doc["deadline_seconds"] <= 10
        or not 0 <= doc["padding_bytes"] <= 5500
        or not 0 <= doc["upstream_loss_probability"] < 1
    ):
        raise ValueError("invalid bounded deadline/padding/upstream probability")
    arms = doc["configurations"]
    if not arms or len(set(arms)) != len(arms) or set(arms) - set(ARMS):
        raise ValueError("unknown or duplicate arm")
    cases = doc["cases"]
    if not cases or len(cases) > 20 or len({c["id"] for c in cases}) != len(cases):
        raise ValueError("bounded unique cases required")
    for c in cases:
        if not all(
            re.fullmatch(r"[a-z][a-z0-9_]{0,48}", c[k]) for k in ("id", "trace_group")
        ):
            raise ValueError("safe case/group identifiers required")
        if (
            c["fault"] not in FAULTS
            or not 0 < c["load"] <= 2
            or type(c["budget"]) is not int
            or not 16384 <= c["budget"] <= 1048576
        ):
            raise ValueError("unsupported load/fault or underfunded budget range")
        if (
            not 0 <= c.get("loss", 0) <= 1
            or not 0 <= c.get("max_delay_seconds", 0) <= 10
            or not 0.1 <= c.get("capacity_multiplier", 1) <= 2
        ):
            raise ValueError("invalid fault/capacity schedule")
        if c.get("restart_seconds", 1) not in range(1, doc["duration_seconds"]):
            raise ValueError("restart outside admission interval")
    if not 1 <= doc["max_trace_records"] <= 10000:
        raise ValueError("trace cardinality bound")
    if type(doc["seed"]) is not int or not 0 <= doc["seed"] <= 2**32:
        raise ValueError("bounded integer seed required")
    if (
        type(doc["reference_bytes_per_second"]) is not int
        or not 1 <= doc["reference_bytes_per_second"] <= 1048576
    ):
        raise ValueError("bounded reference offered rate required")
    for case in cases:
        if (
            not 1 <= case.get("burst_multiplier", 1) <= 3
            or not 0 <= case.get("critical_fraction", 0.03) <= 1
        ):
            raise ValueError("bounded burst/priority fraction required")
        config = AdmissionConfig(
            link_bytes_per_second=case["budget"],
            evidence_share_percent=doc.get("evidence_share_percent", 50),
            protected_share_percent=doc.get("protected_share_percent", 25),
        )
        validate_budget(
            load_contract(ROOT / "config/rule_coverage.json"),
            "coverage-gateway",
            "coverage-key",
            config,
        )
    return doc


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, allow_nan=False)


def write_csv(path, rows, fields=None):
    rows = list(rows)
    fields = fields or list(rows[0])
    with Path(path).open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_jsonl(path, rows):
    with gzip.open(path, "xt", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def read_jsonl(path):
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def seed_for(doc, group, trial):
    return doc["seed"] + int(hashlib.sha256(group.encode()).hexdigest()[:8], 16) + trial


def generate_trace(doc, case, seed, *, epoch=EPOCH):
    rng = random.Random(seed)
    rows = []
    # Declared reference size approximates signed raw frames, not a measured NIC rate.
    rate = (
        doc["reference_bytes_per_second"] * case["load"] / (doc["padding_bytes"] + 1500)
    )
    duration = doc["duration_seconds"]
    groups = {w: rng.choice((False, False, True)) for w in range(duration // 10)}
    for start, end, factor in (
        (0, 0.4 * duration, 1),
        (0.4 * duration, 0.6 * duration, case.get("burst_multiplier", 1)),
        (0.6 * duration, duration, 1),
    ):
        at = start
        while True:
            at += rng.expovariate(rate * factor)
            if at >= end:
                break
            index = len(rows)
            if index >= doc["max_trace_records"]:
                raise ValueError(
                    "declared trace bound exceeded; no truncation permitted"
                )
            device = index % 5 + 1
            kind = ("environmental", "system", "network", "security", "industrial")[
                device - 1
            ]
            matching = groups[int(at // 10)] and rng.random() < 0.15
            critical = rng.random() < case.get("critical_fraction", 0.03)
            values = (
                {"temperature": 40 if matching else 25 + rng.uniform(-0.02, 0.02)},
                {"cpu_usage": 95 if matching else 40 + rng.uniform(-0.02, 0.02)},
                {
                    "measurements": {
                        "packets_per_second": 9000
                        if matching
                        else 1000 + rng.uniform(-0.02, 0.02)
                    }
                },
                {"measurements": {"failed_logins": 6 if matching else 0}},
                {"measurements": {"vibration_mm_s": 9 if matching else 2}},
            )[device - 1]
            at_us = round(at * 1e6)
            message = (
                EdgeTelemetryMessage(
                    device_id=f"edge-device-{device:02d}",
                    timestamp=epoch + timedelta(microseconds=at_us),
                    telemetry_type=kind,
                    temperature=25,
                    humidity=50,
                    status="critical" if critical else "normal",
                    attributes={"padding": "x" * doc["padding_bytes"]},
                    **values,
                )
                if device != 1
                else EdgeTelemetryMessage(
                    device_id="edge-device-01",
                    timestamp=epoch + timedelta(microseconds=at_us),
                    telemetry_type=kind,
                    humidity=50,
                    status="critical" if critical else "normal",
                    attributes={"padding": "x" * doc["padding_bytes"]},
                    **values,
                )
            )
            rows.append(
                {
                    "source_id": index,
                    "at_us": at_us,
                    "upstream_delivered": rng.random()
                    >= doc["upstream_loss_probability"],
                    "priority": classify_priority(message, PriorityRuleConfig()).value,
                    "message": message.model_dump(mode="json"),
                }
            )
    return rows


def fault_schedule(doc, case, seed):
    rng = random.Random(seed + 991)
    end = doc["duration_seconds"] + doc["deadline_seconds"]
    # A common absolute-time field, not a receiver-driven loss estimate.
    return [
        {
            "slot": i,
            "at_seconds": i * 0.001,
            "uniform": round(rng.random(), 9),
            "delay_uniform": round(rng.random(), 9),
        }
        for i in range(round(end * 1000) + 1)
    ]


class VirtualClock:
    def __init__(self, epoch=EPOCH):
        self.epoch, self.us = epoch, 0

    def utc_now(self):
        return self.epoch + timedelta(microseconds=self.us)

    def monotonic_ns(self):
        return self.us * 1000

    def move(self, seconds):
        value = round(seconds * 1e6)
        if value < self.us:
            raise ValueError("virtual clock regression")
        self.us = value


def normalize_original(contract, record):
    """Independent normalization of saved originals; no fact/policy implementation."""
    message = record["message"]
    device = next(d for d in contract.devices if d.device_id == record["device_id"])
    metrics = []
    for definition in device.metrics:
        value = (
            message.get("measurements", {}).get(definition.path.split(".", 1)[1])
            if definition.path.startswith("measurements.")
            else message.get(definition.path)
        )
        metrics.append(MetricReading(path=definition.path, value=value))
    return IngressObservation(
        ledger_epoch=record["ledger_epoch"],
        device_id=record["device_id"],
        ingress_sequence=record["ingress_sequence"],
        ingress_utc_us=record["ingress_utc_us"],
        telemetry_type=message["telemetry_type"],
        metrics=tuple(metrics),
    )


def environment():
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "dependencies": {
            name: version(name) for name in ("pydantic", "cryptography", "matplotlib")
        },
    }


def process_rss():
    if platform.system() == "Windows":

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("faults", ctypes.c_ulong),
                *[
                    (name, ctypes.c_size_t)
                    for name in (
                        "peak",
                        "rss",
                        "pp",
                        "p",
                        "pn",
                        "n",
                        "page",
                        "peakpage",
                    )
                ],
            ]

        counter = Counters()
        counter.cb = ctypes.sizeof(counter)
        ctypes.windll.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        process = ctypes.windll.kernel32.GetCurrentProcess()
        if ctypes.windll.psapi.GetProcessMemoryInfo(
            ctypes.c_void_p(process), ctypes.byref(counter), counter.cb
        ):
            return counter.rss
        return None
    if Path("/proc/self/status").exists():
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    return None

"""Paired-seed discrete-event experiments using the deployed policy engine."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta, timezone
import hashlib
from importlib.metadata import version
import json
import math
from pathlib import Path
import platform
import random
import time
from uuid import NAMESPACE_URL, uuid5

from experiments.runners.benchmark import percentile
from shared.models import EdgeTelemetryMessage, PriorityLevel
from shared.traffic.information import InformationEngine, InformationPolicyConfig


ROOT = Path(__file__).resolve().parents[2]
EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)
TYPES = ("environmental", "system", "network", "security", "industrial")


def generate_trace(workload: dict, duration: float, capacity: float, seed: int) -> list[dict]:
    rng = random.Random(seed)
    rows = []
    now = 0.0
    # Piecewise Poisson arrivals use exact segment boundaries for the burst.
    segments = [(0.0, .4 * duration, 1), (.4 * duration, .6 * duration, workload.get("burst_multiplier", 1)), (.6 * duration, duration, 1)]
    for start, end, multiplier in segments:
        now = start
        rate = capacity * workload["load"] * multiplier
        while True:
            now += rng.expovariate(rate)
            if now >= end:
                break
            index = len(rows)
            kind = TYPES[index % len(TYPES)]
            critical = rng.random() < workload.get("critical_fraction", .02)
            priority = PriorityLevel.CRITICAL if critical else rng.choices(
                [PriorityLevel.LOW, PriorityLevel.MEDIUM, PriorityLevel.HIGH], [70, 20, 8]
            )[0]
            noise = rng.uniform(-.04, .04)
            values = {
                "environmental": {"temperature": 25 + noise},
                "system": {"cpu_usage": 40 + noise, "memory_usage": 50 + noise},
                "network": {"measurements": {"packets_per_second": 1000 + noise, "network_latency_ms": 20}},
                "security": {"measurements": {"failed_logins": 0, "blocked_connections": 0}},
                "industrial": {"measurements": {"pressure_bar": 8 + noise, "vibration_mm_s": 2, "rpm": 1500}},
            }[kind]
            message = EdgeTelemetryMessage.model_validate({
                "device_id": f"edge-device-{index % 5 + 1:02d}",
                "timestamp": EPOCH + timedelta(seconds=now), "telemetry_type": kind,
                "temperature": 25, "humidity": 50,
                "status": "critical" if critical else "warning" if priority == PriorityLevel.HIGH else "normal",
                "event_type": "INTRUSION_DETECTED" if critical else "telemetry", **values,
            })
            rows.append({
                "at": now, "message_id": str(uuid5(NAMESPACE_URL, f"{seed}:{index}")),
                "priority": priority.value, "message": message.model_dump(mode="json"),
            })
    return rows


def simulate(trace: list[dict], config: InformationPolicyConfig, workload: dict,
             duration: float, on_decision=None) -> tuple[dict, list[dict]]:
    engine = InformationEngine(config, on_decision=on_decision)
    prepared = [(row, EdgeTelemetryMessage.model_validate(row["message"])) for row in trace]
    generated = {row["message_id"]: row for row in trace}
    represented: dict[str, float] = {}
    waits = {p.value: [] for p in PriorityLevel}
    latencies = {p.value: [] for p in PriorityLevel}
    sent_messages = 0
    observed_end = duration
    queue_rows = []
    index = 0
    sample_at = 0.0
    link_change_at = duration * .5 if "capacity_multiplier" in workload else math.inf
    while index < len(prepared) or engine.queue or sample_at <= duration:
        arrival_at = prepared[index][0]["at"] if index < len(prepared) else math.inf
        dispatch_at = max(engine.next_dispatch_at, 0) if engine.queue else math.inf
        next_sample = sample_at if sample_at <= duration else math.inf
        now = min(arrival_at, dispatch_at, next_sample, link_change_at)
        if not math.isfinite(now):
            break
        if now == link_change_at:
            engine.configure_local_link(config.link_bytes_per_second * workload["capacity_multiplier"])
            link_change_at = math.inf
            continue
        if now == next_sample:
            local = engine.local.snapshot(now, len(engine.queue))
            queue_rows.append({"time_seconds": now, "queue_size": len(engine.queue), "predicted_queue_size": local["predicted_queue_length"], "congestion_state": local["congestion_state"]})
            sample_at += 1
        if now == arrival_at:
            row, message = prepared[index]
            engine.submit(message, PriorityLevel(row["priority"]), now, EPOCH + timedelta(seconds=now), row["message_id"])
            index += 1
        if engine.queue and now >= engine.next_dispatch_at:
            selected = engine.pop(now)
            if selected is not None:
                completed_at = engine.next_dispatch_at
                observed_end = max(observed_end, completed_at)
                sent_messages += 1
                for identifier in selected.source_ids:
                    source = generated[identifier]
                    represented[identifier] = completed_at
                    waits[source["priority"]].append(max(now - source["at"], 0))
                    latencies[source["priority"]].append(max(completed_at - source["at"], 0))
    all_latencies = [value for values in latencies.values() for value in values]
    critical_ids = {key for key, row in generated.items() if row["priority"] == "CRITICAL"}
    low_ids = {key for key, row in generated.items() if row["priority"] == "LOW"}
    critical_kept = len(critical_ids & represented.keys())
    raw_size = engine.generated_bytes
    metrics = {
        "generated_messages": len(trace), "transmitted_messages": sent_messages,
        "represented_samples": len(represented),
        "represented_sample_percent": 100 * len(represented) / max(len(trace), 1),
        "critical_preservation_percent": 100 * critical_kept / len(critical_ids) if critical_ids else None,
        "throughput_messages_per_second": sent_messages / max(observed_end, .001),
        "latency_p50_seconds": percentile(all_latencies, 50),
        "latency_p95_seconds": percentile(all_latencies, 95),
        "latency_p99_seconds": percentile(all_latencies, 99),
        "critical_p95_seconds": percentile(latencies["CRITICAL"], 95),
        "high_p95_seconds": percentile(latencies["HIGH"], 95),
        "low_starvation_percent": 100 * sum(
            key not in represented or represented[key] - generated[key]["at"] > config.starvation_seconds for key in low_ids
        ) / len(low_ids) if low_ids else None,
        "generated_bytes_estimate": raw_size, "transmitted_bytes_estimate": engine.dispatched_bytes,
        "bandwidth_saving_percent": 100 * (raw_size - engine.dispatched_bytes) / max(raw_size, 1),
        "queue_drop_percent": 100 * engine.action_counts["DROP"] / max(len(trace), 1),
        "maximum_queue_size": max((row["queue_size"] for row in queue_rows), default=0),
        **{f"action_{action}": engine.action_counts[action] for action in ("SEND", "DELAY", "AGGREGATE", "SAMPLE", "SUPERSEDE", "DROP")},
    }
    return metrics, queue_rows


def run(config_path: Path, output: Path) -> None:
    document = json.loads(config_path.read_text(encoding="utf-8"))
    if int(document["runs_per_configuration"]) < 5:
        raise ValueError("at least five repeated trials are required")
    base_path = ROOT / document["policy_config"]
    base = InformationPolicyConfig.from_file(base_path).model_dump(mode="json")
    base.update(document.get("policy_overrides", {}))
    base_config = InformationPolicyConfig.model_validate(base)
    duration = float(document["duration_seconds"])
    if duration <= 0 or document["reference_message_bytes"] <= 0:
        raise ValueError("duration and reference message size must be positive")
    capacity = min(base_config.messages_per_second, base_config.link_bytes_per_second / document["reference_message_bytes"])
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("results directory must be empty to retain previous runs")
    start = datetime.now(timezone.utc)
    rows, queue_rows = [], []
    resolved_configs = {}
    for entry in document["configurations"]:
        values = {**base, **{k: v for k, v in entry.items() if k != "id"}}
        resolved_configs[entry["id"]] = InformationPolicyConfig.model_validate(values)
    with (output / "decisions.jsonl").open("w", encoding="utf-8") as decisions, (output / "workload_trace.jsonl").open("w", encoding="utf-8") as raw_trace:
        for workload_index, workload in enumerate(document["workloads"]):
            if workload["load"] <= 0:
                raise ValueError("workload load must be positive")
            for trial in range(int(document["runs_per_configuration"])):
                seed = int(document["seed"]) + 10000 * workload_index + trial
                trace = generate_trace(workload, duration, capacity, seed)
                for row in trace:
                    raw_trace.write(json.dumps({"workload": workload["id"], "seed": seed, **row}) + "\n")
                for name, policy_config in resolved_configs.items():
                    context = {"workload": workload["id"], "configuration": name, "trial": trial + 1, "seed": seed}
                    context["started_at"] = datetime.now(timezone.utc).isoformat()
                    def record(decision):
                        decisions.write(json.dumps({**context, **decision}, sort_keys=True) + "\n")
                    clock_start, cpu_start = time.perf_counter(), time.process_time()
                    metrics, samples = simulate(trace, policy_config, workload, duration, record)
                    metrics["runner_wall_seconds"] = time.perf_counter() - clock_start
                    metrics["runner_cpu_seconds"] = time.process_time() - cpu_start
                    context["completed_at"] = datetime.now(timezone.utc).isoformat()
                    rows.append({**context, **metrics})
                    queue_rows.extend({**context, **sample} for sample in samples)
            print(f"Completed {workload['id']}: {document['runs_per_configuration']} paired trials per strategy", flush=True)
    for name, records in (("raw_trials.csv", rows), ("queue_timeseries.csv", queue_rows)):
        with (output / name).open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(records[0]))
            writer.writeheader()
            writer.writerows(records)
    sources = [ROOT / "shared/traffic/information.py", ROOT / "shared/models/telemetry.py", Path(__file__), ROOT / "experiments/analysis/information_report.py", ROOT / "edge-gateway/app/main.py", ROOT / "data-diode/app/main.py"]
    fingerprints = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}
    manifest = {
        "started_at": start.isoformat(), "completed_at": datetime.now(timezone.utc).isoformat(),
        "python_version": platform.python_version(), "platform": platform.platform(),
        "source_sha256": fingerprints, "configuration": document,
        "software_version": "information-policy-" + hashlib.sha256(json.dumps(fingerprints, sort_keys=True).encode()).hexdigest()[:16],
        "dependencies": {name: version(name) for name in ("pydantic", "matplotlib", "cryptography")},
        "resolved_policy_configs": {key: value.model_dump(mode="json") for key, value in resolved_configs.items()},
        "measurement_scope": "discrete-event local policy simulation; no receiver, network, or attack detector measured",
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    from experiments.analysis.information_report import analyze
    analyze(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=ROOT / "experiments/workloads/information_workloads.json")
    parser.add_argument("--output", type=Path, default=ROOT / "experiments/results/information-preservation")
    args = parser.parse_args()
    run(args.config, args.output)

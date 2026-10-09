from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import gc
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
from statistics import fmean
import subprocess
import time
import tracemalloc
from typing import Any
from uuid import uuid4

from shared.models import EdgeTelemetryMessage, PriorityLevel
from shared.security.crypto import canonical_json
from shared.traffic import EdgeFilter, EdgeFilterConfig
from shared.traffic.scheduling import (
    AdaptiveScheduler,
    BoundedMessageQueue,
    CongestionMonitor,
    SchedulerWeights,
    new_simulated_envelope,
)


PRIORITIES = tuple(PriorityLevel)
DEVICES = tuple(f"edge-device-{index:02d}" for index in range(1, 6))
FIXED_EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class Arrival:
    sequence_number: int
    arrival_time: float
    device_id: str
    priority: PriorityLevel
    is_anomaly: bool = False
    is_attack: bool = False


@dataclass(frozen=True)
class PreparedArrival:
    source: Arrival
    priority: PriorityLevel
    size_bytes: int


def load_experiment_config(path: str | Path) -> dict[str, Any]:
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    required = {
        "random_seed",
        "runs_per_configuration",
        "duration_seconds",
        "diode_capacity_messages_per_second",
        "max_queue_size",
        "configurations",
        "workloads",
    }
    missing = sorted(required - set(config))
    if missing:
        raise ValueError(f"experiment configuration is missing: {', '.join(missing)}")
    if int(config["runs_per_configuration"]) < 5:
        raise ValueError("research experiments require at least 5 runs per configuration")
    if {item["scheduler"] for item in config["configurations"]} - {"fifo", "adaptive"}:
        raise ValueError("scheduler must be fifo or adaptive")
    return config


def generate_workload(
    workload: dict[str, Any],
    *,
    duration: float,
    capacity: float,
    seed: int,
) -> list[Arrival]:
    rng = random.Random(f"{seed}:{workload['id']}")
    base_rate = capacity * float(workload["load_factor"])
    segments = _rate_segments(workload, duration, base_rate)
    arrival_times: list[float] = []
    for start, end, rate in segments:
        current = start
        while rate > 0:
            current += rng.expovariate(rate)
            if current >= end:
                break
            arrival_times.append(current)
    arrival_times.sort()

    distribution = workload["priority_distribution"]
    priorities = [PriorityLevel(name) for name in distribution]
    weights = [float(distribution[priority.value]) for priority in priorities]
    arrivals = [
        Arrival(
            sequence_number=index,
            arrival_time=round(arrival_time, 6),
            device_id=DEVICES[(index - 1) % len(DEVICES)],
            priority=rng.choices(priorities, weights=weights, k=1)[0],
        )
        for index, arrival_time in enumerate(arrival_times, start=1)
    ]
    return _tag_detection_events(arrivals, workload, rng)


def execute_trial(
    workload: dict[str, Any],
    configuration: dict[str, Any],
    config: dict[str, Any],
    *,
    trial: int,
    seed: int,
    arrivals: list[Arrival],
    software_version: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    started_at = datetime.now(timezone.utc)
    run_id = str(uuid4())
    gc.collect()
    tracemalloc.start()
    wall_started = time.perf_counter()
    cpu_started = time.process_time()

    prepared, preparation = prepare_arrivals(
        arrivals,
        filtering=bool(configuration["filtering"]),
        filter_config=config.get("filter", {}),
    )
    metrics, message_rows, queue_rows = simulate(
        prepared,
        arrivals,
        scheduler_mode=configuration["scheduler"],
        capacity=float(config["diode_capacity_messages_per_second"]),
        max_queue_size=int(config["max_queue_size"]),
        duration=float(config["duration_seconds"]),
        sample_interval=float(config.get("queue_sample_interval_seconds", 0.25)),
        starvation_threshold=float(config.get("low_starvation_threshold_seconds", 5.0)),
    )
    cpu_seconds = time.process_time() - cpu_started
    wall_seconds = max(time.perf_counter() - wall_started, 0.000001)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    completed_at = datetime.now(timezone.utc)

    generated_bytes = preparation["generated_bytes"]
    transmitted_bytes = metrics["transmitted_bytes"]
    result = {
        "run_id": run_id,
        "experiment_name": config.get("experiment_name", "phase7"),
        "workload": workload["id"],
        "workload_label": workload["label"],
        "configuration": configuration["id"],
        "configuration_label": configuration["label"],
        "configuration_role": configuration["role"],
        "scheduler": configuration["scheduler"],
        "filtering_enabled": bool(configuration["filtering"]),
        "trial": trial,
        "seed": seed,
        "software_version": software_version,
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "offered_load_percent": round(_mean_load_factor(workload) * 100, 3),
        "peak_load_percent": round(_peak_load_factor(workload) * 100, 3),
        "capacity_messages_per_second": float(config["diode_capacity_messages_per_second"]),
        "duration_seconds": float(config["duration_seconds"]),
        "max_queue_size": int(config["max_queue_size"]),
        "generated_messages": len(arrivals),
        "scheduled_messages": len(prepared),
        "filtered_messages": preparation["filtered_messages"],
        "generated_bytes": generated_bytes,
        "filtered_bytes": preparation["filtered_bytes"],
        "bandwidth_saving_percent": (
            100.0 * (generated_bytes - transmitted_bytes) / generated_bytes
            if generated_bytes
            else 0.0
        ),
        "benchmark_wall_seconds": wall_seconds,
        "process_cpu_seconds": cpu_seconds,
        "cpu_utilization_percent": min(100.0 * cpu_seconds / wall_seconds, 100.0),
        "peak_memory_mb": peak_bytes / (1024 * 1024),
        **metrics,
    }
    context = {
        "run_id": run_id,
        "workload": workload["id"],
        "configuration": configuration["id"],
        "trial": trial,
        "seed": seed,
    }
    for row in message_rows:
        row.update(context)
    for row in queue_rows:
        row.update(context)
    return result, message_rows, queue_rows


def prepare_arrivals(
    arrivals: list[Arrival],
    *,
    filtering: bool,
    filter_config: dict[str, Any],
) -> tuple[list[PreparedArrival], dict[str, int]]:
    edge_filter = EdgeFilter(
        EdgeFilterConfig(
            temperature_delta_threshold=float(
                filter_config.get("temperature_delta_threshold", 0.25)
            ),
            humidity_delta_threshold=float(filter_config.get("humidity_delta_threshold", 1.0)),
            aggregation_sample_count=int(filter_config.get("aggregation_sample_count", 5)),
            enable_aggregation=bool(filter_config.get("enable_aggregation", True)),
        )
    )
    prepared: list[PreparedArrival] = []
    generated_bytes = 0
    filtered_bytes = 0
    filtered_messages = 0
    for arrival in arrivals:
        message = message_for_arrival(arrival)
        raw_size = len(canonical_json(message.model_dump(mode="json")).encode("utf-8"))
        generated_bytes += raw_size
        if not filtering:
            prepared.append(PreparedArrival(arrival, arrival.priority, raw_size))
            continue
        decision = edge_filter.evaluate(message, arrival.priority)
        filtered_bytes += decision.filtered_bytes
        if decision.message is None:
            filtered_messages += 1
            continue
        if decision.action == "aggregate":
            filtered_messages += 1
        output_size = len(
            canonical_json(decision.message.model_dump(mode="json")).encode("utf-8")
        )
        prepared.append(
            PreparedArrival(
                arrival,
                PriorityLevel.LOW if decision.action == "aggregate" else arrival.priority,
                output_size,
            )
        )
    return prepared, {
        "generated_bytes": generated_bytes,
        "filtered_bytes": filtered_bytes,
        "filtered_messages": filtered_messages,
    }


def simulate(
    prepared: list[PreparedArrival],
    all_arrivals: list[Arrival],
    *,
    scheduler_mode: str,
    capacity: float,
    max_queue_size: int,
    duration: float,
    sample_interval: float,
    starvation_threshold: float,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    queue = BoundedMessageQueue(max_queue_size)
    scheduler = AdaptiveScheduler(SchedulerWeights())
    congestion = CongestionMonitor()
    prepared_by_sequence = {item.source.sequence_number: item for item in prepared}
    outcomes: dict[int, dict[str, Any]] = {
        arrival.sequence_number: {
            "outcome": "FILTERED" if arrival.sequence_number not in prepared_by_sequence else "PENDING",
            "queue_wait_seconds": None,
            "latency_seconds": None,
        }
        for arrival in all_arrivals
    }
    delivered_latencies: dict[PriorityLevel, list[float]] = {
        priority: [] for priority in PRIORITIES
    }
    queue_waits: dict[PriorityLevel, list[float]] = {priority: [] for priority in PRIORITIES}
    delivered_counts = {priority: 0 for priority in PRIORITIES}
    dropped_counts = {priority: 0 for priority in PRIORITIES}
    scheduled_counts = {priority: 0 for priority in PRIORITIES}
    completion_by_sequence: dict[int, float] = {}
    transmitted_bytes = 0
    arrival_index = 0
    next_departure = 0.0
    service_interval = 1.0 / capacity
    queue_events: list[tuple[float, int]] = [(0.0, 0)]
    last_completion = 0.0

    while arrival_index < len(prepared) or len(queue) > 0:
        if arrival_index < len(prepared) and len(queue) == 0:
            next_departure = max(next_departure, prepared[arrival_index].source.arrival_time)
        next_arrival = (
            prepared[arrival_index].source.arrival_time
            if arrival_index < len(prepared)
            else math.inf
        )
        if next_arrival <= next_departure:
            now = next_arrival
            while (
                arrival_index < len(prepared)
                and prepared[arrival_index].source.arrival_time == now
            ):
                item = prepared[arrival_index]
                scheduled_counts[item.priority] += 1
                envelope = new_simulated_envelope(
                    item.priority,
                    FIXED_EPOCH + timedelta(seconds=item.source.arrival_time),
                    item.source.sequence_number,
                    estimated_transmission_cost=item.size_bytes,
                ).model_copy(update={"device_id": item.source.device_id})
                push = queue.push(envelope, item.size_bytes, now=now)
                congestion.record_incoming(now)
                if push.accepted and push.dropped is not None:
                    victim_sequence = push.dropped.envelope.sequence_number
                    victim = prepared_by_sequence[victim_sequence]
                    dropped_counts[victim.priority] += 1
                    outcomes[victim_sequence]["outcome"] = "DROPPED_EVICTED"
                elif not push.accepted:
                    dropped_counts[item.priority] += 1
                    outcomes[item.source.sequence_number]["outcome"] = "DROPPED_QUEUE_FULL"
                queue_events.append((now, len(queue)))
                arrival_index += 1
            continue

        now = next_departure
        state = congestion.state(len(queue), max_queue_size)
        queued = (
            queue.pop_fifo()
            if scheduler_mode == "fifo"
            else queue.pop_adaptive(scheduler, now, state)
        )
        if queued is not None:
            source = prepared_by_sequence[queued.envelope.sequence_number]
            queue_wait = max(now - source.source.arrival_time, 0.0)
            completion = now + service_interval
            latency = completion - source.source.arrival_time
            delivered_counts[source.priority] += 1
            delivered_latencies[source.priority].append(latency)
            queue_waits[source.priority].append(queue_wait)
            transmitted_bytes += source.size_bytes
            completion_by_sequence[source.source.sequence_number] = completion
            outcomes[source.source.sequence_number] = {
                "outcome": "DELIVERED",
                "queue_wait_seconds": queue_wait,
                "latency_seconds": latency,
            }
            congestion.record_outgoing(latency, now)
            last_completion = max(last_completion, completion)
            queue_events.append((now, len(queue)))
        next_departure += service_interval

    simulation_end = max(duration, last_completion)
    sampled_queue = _sample_queue(queue_events, simulation_end, sample_interval)
    queue_values = [size for _, size in sampled_queue]
    delivered_total = sum(delivered_counts.values())
    dropped_total = sum(dropped_counts.values())
    all_latencies = [value for values in delivered_latencies.values() for value in values]
    all_waits = [value for values in queue_waits.values() for value in values]
    low_total = scheduled_counts[PriorityLevel.LOW]
    low_starved = dropped_counts[PriorityLevel.LOW] + sum(
        wait > starvation_threshold for wait in queue_waits[PriorityLevel.LOW]
    )
    delivery_ratios = [
        delivered_counts[priority] / scheduled_counts[priority]
        for priority in PRIORITIES
        if scheduled_counts[priority] > 0
    ]
    anomaly_sequences = {
        arrival.sequence_number for arrival in all_arrivals if arrival.is_anomaly
    }
    attack_sequences = {arrival.sequence_number for arrival in all_arrivals if arrival.is_attack}
    anomaly_latencies = [
        completion_by_sequence[sequence]
        - next(item.arrival_time for item in all_arrivals if item.sequence_number == sequence)
        for sequence in anomaly_sequences & completion_by_sequence.keys()
    ]
    attack_latencies = [
        completion_by_sequence[sequence]
        - next(item.arrival_time for item in all_arrivals if item.sequence_number == sequence)
        for sequence in attack_sequences & completion_by_sequence.keys()
    ]

    metrics: dict[str, Any] = {
        "simulation_elapsed_seconds": simulation_end,
        "delivered_messages": delivered_total,
        "dropped_messages": dropped_total,
        "throughput_messages_per_second": delivered_total / simulation_end if simulation_end else 0.0,
        "latency_p50_seconds": percentile(all_latencies, 50),
        "latency_p95_seconds": percentile(all_latencies, 95),
        "latency_p99_seconds": percentile(all_latencies, 99),
        "queue_wait_p50_seconds": percentile(all_waits, 50),
        "queue_wait_p95_seconds": percentile(all_waits, 95),
        "queue_wait_p99_seconds": percentile(all_waits, 99),
        "average_queue_size": fmean(queue_values) if queue_values else 0.0,
        "maximum_queue_size": max(queue_values, default=0),
        "average_queue_utilization": (
            fmean(queue_values) / max_queue_size if max_queue_size else 0.0
        ),
        "maximum_queue_utilization": (
            max(queue_values, default=0) / max_queue_size if max_queue_size else 0.0
        ),
        "drop_rate_percent": (
            100.0 * dropped_total / len(prepared) if prepared else 0.0
        ),
        "low_starvation_rate_percent": 100.0 * low_starved / low_total if low_total else 0.0,
        "jain_fairness_index": _jain_index(delivery_ratios),
        "transmitted_bytes": transmitted_bytes,
        "anomaly_detection_latency_seconds": (
            fmean(anomaly_latencies) if anomaly_latencies else None
        ),
        "attack_detection_latency_seconds": fmean(attack_latencies) if attack_latencies else None,
        "anomaly_detection_rate_percent": (
            100.0 * len(anomaly_latencies) / len(anomaly_sequences)
            if anomaly_sequences
            else None
        ),
        "security_detection_rate_percent": (
            100.0 * len(attack_latencies) / len(attack_sequences) if attack_sequences else None
        ),
    }
    for priority in PRIORITIES:
        prefix = priority.value.lower()
        metrics[f"{prefix}_scheduled"] = scheduled_counts[priority]
        metrics[f"{prefix}_delivered"] = delivered_counts[priority]
        metrics[f"{prefix}_dropped"] = dropped_counts[priority]
        metrics[f"{prefix}_latency_p50_seconds"] = percentile(
            delivered_latencies[priority], 50
        )
        metrics[f"{prefix}_latency_p95_seconds"] = percentile(
            delivered_latencies[priority], 95
        )
        metrics[f"{prefix}_latency_p99_seconds"] = percentile(
            delivered_latencies[priority], 99
        )
        metrics[f"{prefix}_queue_wait_p95_seconds"] = percentile(queue_waits[priority], 95)

    message_rows = []
    generated_sizes = {
        arrival.sequence_number: len(
            canonical_json(message_for_arrival(arrival).model_dump(mode="json")).encode("utf-8")
        )
        for arrival in all_arrivals
    }
    for arrival in all_arrivals:
        message_rows.append(
            {
                "sequence_number": arrival.sequence_number,
                "arrival_time_seconds": arrival.arrival_time,
                "device_id": arrival.device_id,
                "priority": arrival.priority.value,
                "is_anomaly": arrival.is_anomaly,
                "is_attack": arrival.is_attack,
                "generated_bytes": generated_sizes[arrival.sequence_number],
                **outcomes[arrival.sequence_number],
            }
        )
    queue_rows = [
        {
            "simulation_time_seconds": sample_time,
            "queue_size": queue_size,
            "queue_utilization": queue_size / max_queue_size if max_queue_size else 0.0,
        }
        for sample_time, queue_size in sampled_queue
    ]
    return metrics, message_rows, queue_rows


def message_for_arrival(arrival: Arrival) -> EdgeTelemetryMessage:
    timestamp = FIXED_EPOCH + timedelta(seconds=arrival.arrival_time)
    if arrival.is_attack:
        return EdgeTelemetryMessage(
            device_id=arrival.device_id,
            timestamp=timestamp,
            temperature=30.0,
            humidity=50.0,
            status="critical",
            event_type="attack",
            measurements={"failed_logins": 12.0},
        )
    if arrival.is_anomaly:
        return EdgeTelemetryMessage(
            device_id=arrival.device_id,
            timestamp=timestamp,
            temperature=45.0,
            humidity=60.0,
            status="abnormal",
            event_type="telemetry",
        )
    if arrival.priority == PriorityLevel.CRITICAL:
        return EdgeTelemetryMessage(
            device_id=arrival.device_id,
            timestamp=timestamp,
            temperature=30.0,
            humidity=55.0,
            status="critical",
            event_type="intrusion",
        )
    if arrival.priority == PriorityLevel.HIGH:
        return EdgeTelemetryMessage(
            device_id=arrival.device_id,
            timestamp=timestamp,
            temperature=40.0,
            humidity=58.0,
            status="hot",
            event_type="telemetry",
        )
    if arrival.priority == PriorityLevel.MEDIUM:
        return EdgeTelemetryMessage(
            device_id=arrival.device_id,
            timestamp=timestamp,
            temperature=35.0,
            humidity=57.0,
            status="warning",
            event_type="resource",
            cpu_usage=90.0,
        )
    return EdgeTelemetryMessage(
        device_id=arrival.device_id,
        timestamp=timestamp,
        temperature=25.0 + (arrival.sequence_number % 3) * 0.05,
        humidity=50.0,
        status="normal",
        event_type="telemetry",
    )


def percentile(values: list[float], percentile_value: int) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (percentile_value / 100) * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def software_version(project_root: Path, config_path: Path) -> tuple[str, str]:
    files = [
        project_root / "shared/traffic/filtering.py",
        project_root / "shared/traffic/scheduling.py",
        project_root / "experiments/runners/benchmark.py",
        project_root / "experiments/analysis/analyze.py",
        Path(config_path),
    ]
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.read_bytes())
    fingerprint = digest.hexdigest()
    configured = os.getenv("SOFTWARE_VERSION")
    if configured:
        return configured, fingerprint
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = f"phase7-local-{fingerprint[:12]}"
    return commit, fingerprint


def environment_metadata() -> dict[str, str]:
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
    }


def _rate_segments(
    workload: dict[str, Any], duration: float, base_rate: float
) -> list[tuple[float, float, float]]:
    multiplier = float(workload.get("burst_multiplier", 1.0))
    if multiplier == 1.0:
        return [(0.0, duration, base_rate)]
    burst_start = duration * float(workload.get("burst_start_fraction", 0.4))
    burst_end = burst_start + duration * float(workload.get("burst_duration_fraction", 0.2))
    return [
        (0.0, burst_start, base_rate),
        (burst_start, min(burst_end, duration), base_rate * multiplier),
        (min(burst_end, duration), duration, base_rate),
    ]


def _tag_detection_events(
    arrivals: list[Arrival], workload: dict[str, Any], rng: random.Random
) -> list[Arrival]:
    if not arrivals:
        return arrivals
    indices = list(range(len(arrivals)))
    anomaly_count = max(1, round(len(arrivals) * float(workload.get("anomaly_fraction", 0))))
    anomaly_indices = set(rng.sample(indices, min(anomaly_count, len(indices))))
    available = [index for index in indices if index not in anomaly_indices]
    attack_count = max(1, round(len(arrivals) * float(workload.get("attack_fraction", 0))))
    attack_indices = set(rng.sample(available, min(attack_count, len(available))))
    tagged = []
    for index, arrival in enumerate(arrivals):
        if index in attack_indices:
            tagged.append(replace(arrival, priority=PriorityLevel.CRITICAL, is_attack=True))
        elif index in anomaly_indices:
            tagged.append(replace(arrival, priority=PriorityLevel.HIGH, is_anomaly=True))
        else:
            tagged.append(arrival)
    return tagged


def _sample_queue(
    events: list[tuple[float, int]], end_time: float, interval: float
) -> list[tuple[float, int]]:
    samples: list[tuple[float, int]] = []
    event_index = 0
    current_size = 0
    sample_time = 0.0
    while sample_time <= end_time + 1e-9:
        while event_index < len(events) and events[event_index][0] <= sample_time:
            current_size = events[event_index][1]
            event_index += 1
        samples.append((round(sample_time, 6), current_size))
        sample_time += interval
    return samples


def _jain_index(values: list[float]) -> float | None:
    if not values or sum(value * value for value in values) == 0:
        return None
    return sum(values) ** 2 / (len(values) * sum(value * value for value in values))


def _mean_load_factor(workload: dict[str, Any]) -> float:
    base = float(workload["load_factor"])
    duration_fraction = float(workload.get("burst_duration_fraction", 0.0))
    multiplier = float(workload.get("burst_multiplier", 1.0))
    return base * ((1.0 - duration_fraction) + duration_fraction * multiplier)


def _peak_load_factor(workload: dict[str, Any]) -> float:
    return float(workload["load_factor"]) * float(workload.get("burst_multiplier", 1.0))

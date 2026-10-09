from pathlib import Path

import pytest

from experiments.analysis.analyze import calculate_statistics
from experiments.runners.benchmark import (
    _rate_segments,
    execute_trial,
    generate_workload,
    load_experiment_config,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "experiments/workloads/phase7_workloads.json"


def test_phase7_configuration_has_required_workloads_and_ablation_arms() -> None:
    config = load_experiment_config(CONFIG_PATH)

    assert config["runs_per_configuration"] >= 5
    assert {item["id"] for item in config["workloads"]} == {
        "light",
        "moderate",
        "near_saturation",
        "overload",
        "burst",
        "critical_storm",
    }
    arms = {
        (item["scheduler"], item["filtering"])
        for item in config["configurations"]
    }
    assert arms == {
        ("fifo", False),
        ("adaptive", False),
        ("fifo", True),
        ("adaptive", True),
    }


def test_workload_generation_is_reproducible_for_the_same_seed() -> None:
    config = load_experiment_config(CONFIG_PATH)
    workload = config["workloads"][2]

    first = generate_workload(workload, duration=5, capacity=20, seed=1234)
    second = generate_workload(workload, duration=5, capacity=20, seed=1234)

    assert first == second
    assert first != generate_workload(workload, duration=5, capacity=20, seed=1235)


def test_burst_workload_contains_a_three_times_rate_segment() -> None:
    config = load_experiment_config(CONFIG_PATH)
    workload = next(item for item in config["workloads"] if item["id"] == "burst")

    segments = _rate_segments(workload, duration=30, base_rate=20)

    assert segments == [(0.0, 12.0, 20), (12.0, 18.0, 60.0), (18.0, 30, 20)]


def test_trial_records_bounded_queue_bandwidth_and_detection_metrics() -> None:
    config = load_experiment_config(CONFIG_PATH)
    config = {
        **config,
        "duration_seconds": 3.0,
        "diode_capacity_messages_per_second": 10.0,
        "max_queue_size": 5,
    }
    workload = next(item for item in config["workloads"] if item["id"] == "overload")
    proposed = next(item for item in config["configurations"] if item["id"] == "proposed")
    arrivals = generate_workload(workload, duration=3, capacity=10, seed=77)

    summary, messages, queue = execute_trial(
        workload,
        proposed,
        config,
        trial=1,
        seed=77,
        arrivals=arrivals,
        software_version="test-version",
    )

    expected_saving = (
        100
        * (summary["generated_bytes"] - summary["transmitted_bytes"])
        / summary["generated_bytes"]
    )
    assert summary["maximum_queue_size"] <= 5
    assert summary["bandwidth_saving_percent"] == pytest.approx(expected_saving)
    assert summary["software_version"] == "test-version"
    assert summary["security_detection_rate_percent"] is not None
    assert len(messages) == len(arrivals)
    assert queue


def test_virtual_time_metrics_repeat_exactly_for_the_same_trace() -> None:
    config = load_experiment_config(CONFIG_PATH)
    config = {
        **config,
        "duration_seconds": 2.0,
        "diode_capacity_messages_per_second": 10.0,
        "max_queue_size": 5,
    }
    workload = next(item for item in config["workloads"] if item["id"] == "overload")
    arm = next(item for item in config["configurations"] if item["id"] == "adaptive_only")
    arrivals = generate_workload(workload, duration=2, capacity=10, seed=9001)

    first, _, first_queue = execute_trial(
        workload, arm, config, trial=1, seed=9001, arrivals=arrivals, software_version="test"
    )
    second, _, second_queue = execute_trial(
        workload, arm, config, trial=1, seed=9001, arrivals=arrivals, software_version="test"
    )

    deterministic_metrics = (
        "delivered_messages",
        "dropped_messages",
        "latency_p95_seconds",
        "critical_latency_p95_seconds",
        "maximum_queue_size",
        "bandwidth_saving_percent",
        "low_starvation_rate_percent",
    )
    assert {key: first[key] for key in deterministic_metrics} == {
        key: second[key] for key in deterministic_metrics
    }
    queue_fields = ("simulation_time_seconds", "queue_size", "queue_utilization")
    assert [
        {key: row[key] for key in queue_fields} for row in first_queue
    ] == [
        {key: row[key] for key in queue_fields} for row in second_queue
    ]


def test_statistics_use_repeated_trials_and_report_confidence_interval() -> None:
    rows = []
    for trial, value in enumerate([8.0, 9.0, 10.0, 11.0, 12.0], start=1):
        rows.append(
            {
                "workload": "light",
                "workload_label": "A - Light",
                "configuration": "proposed",
                "configuration_label": "Proposed",
                "trial": str(trial),
                "throughput_messages_per_second": str(value),
            }
        )

    result = calculate_statistics(rows)
    throughput = next(item for item in result if item["metric"] == "throughput_messages_per_second")

    assert throughput["n"] == 5
    assert throughput["mean"] == 10.0
    assert throughput["median"] == 10.0
    assert throughput["sample_standard_deviation"] > 0
    assert throughput["ci95_lower"] < 10 < throughput["ci95_upper"]

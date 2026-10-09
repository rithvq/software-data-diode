from __future__ import annotations

from collections import defaultdict
import argparse
import csv
import json
import math
import os
from pathlib import Path
from statistics import fmean, median, stdev
from typing import Any


ANALYSIS_METRICS = (
    "throughput_messages_per_second",
    "latency_p50_seconds",
    "latency_p95_seconds",
    "latency_p99_seconds",
    "queue_wait_p50_seconds",
    "queue_wait_p95_seconds",
    "queue_wait_p99_seconds",
    "average_queue_size",
    "average_queue_utilization",
    "maximum_queue_size",
    "drop_rate_percent",
    "cpu_utilization_percent",
    "peak_memory_mb",
    "bandwidth_saving_percent",
    "anomaly_detection_latency_seconds",
    "attack_detection_latency_seconds",
    "security_detection_rate_percent",
    "low_starvation_rate_percent",
    "jain_fairness_index",
    "critical_latency_p50_seconds",
    "critical_latency_p95_seconds",
    "critical_latency_p99_seconds",
    "high_latency_p50_seconds",
    "high_latency_p95_seconds",
    "high_latency_p99_seconds",
    "medium_latency_p95_seconds",
    "low_latency_p95_seconds",
)

COLORS = {
    "baseline_a_direct": "#4C566A",
    "baseline_b_fifo": "#2A9D8F",
    "adaptive_only": "#E9C46A",
    "proposed": "#D1495B",
}


def analyze_results(
    result_dir: str | Path,
    config: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    result_path = Path(result_dir)
    trial_rows = _read_csv(result_path / "raw_trials.csv")
    queue_rows = _read_csv(result_path / "queue_timeseries.csv")
    statistics_rows = calculate_statistics(trial_rows)
    _write_csv(result_path / "aggregate_statistics.csv", statistics_rows)
    scheduler_rows = scheduler_comparisons(trial_rows, config)
    _write_csv(result_path / "scheduler_comparison.csv", scheduler_rows)
    figure_dir = result_path / "figures"
    figure_dir.mkdir(parents=True, exist_ok=True)
    figure_files = generate_figures(trial_rows, queue_rows, config, figure_dir)
    report_path = result_path / "experiment_summary.md"
    write_report(report_path, statistics_rows, scheduler_rows, config, manifest)
    return {
        "aggregate_statistics": "aggregate_statistics.csv",
        "scheduler_comparison": "scheduler_comparison.csv",
        "figures": figure_files,
        "report": report_path.name,
    }


def calculate_statistics(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    labels: dict[tuple[str, str], tuple[str, str]] = {}
    for row in rows:
        key = (row["workload"], row["configuration"])
        labels[key] = (row["workload_label"], row["configuration_label"])
        for metric in ANALYSIS_METRICS:
            value = _number(row.get(metric))
            if value is not None:
                grouped[(key[0], key[1], metric)].append(value)

    results = []
    for (workload, configuration, metric), values in sorted(grouped.items()):
        sample_stddev = stdev(values) if len(values) > 1 else 0.0
        margin = _t_critical_95(len(values) - 1) * sample_stddev / math.sqrt(len(values))
        mean_value = fmean(values)
        workload_label, configuration_label = labels[(workload, configuration)]
        results.append(
            {
                "workload": workload,
                "workload_label": workload_label,
                "configuration": configuration,
                "configuration_label": configuration_label,
                "metric": metric,
                "n": len(values),
                "mean": mean_value,
                "median": median(values),
                "sample_standard_deviation": sample_stddev,
                "ci95_lower": mean_value - margin,
                "ci95_upper": mean_value + margin,
                "ci95_margin": margin,
            }
        )
    return results


def scheduler_comparisons(
    rows: list[dict[str, str]], config: dict[str, Any]
) -> list[dict[str, Any]]:
    grouped = _trial_means(rows)
    comparisons = []
    for workload in config["workloads"]:
        workload_id = workload["id"]
        fifo = grouped.get((workload_id, "baseline_a_direct"), {})
        adaptive = grouped.get((workload_id, "adaptive_only"), {})
        proposed = grouped.get((workload_id, "proposed"), {})
        comparisons.append(
            {
                "workload": workload_id,
                "workload_label": workload["label"],
                "critical_latency_improvement_percent": _improvement(
                    fifo.get("critical_latency_p95_seconds"),
                    adaptive.get("critical_latency_p95_seconds"),
                ),
                "high_latency_improvement_percent": _improvement(
                    fifo.get("high_latency_p95_seconds"),
                    adaptive.get("high_latency_p95_seconds"),
                ),
                "fifo_low_starvation_rate_percent": fifo.get(
                    "low_starvation_rate_percent"
                ),
                "adaptive_low_starvation_rate_percent": adaptive.get(
                    "low_starvation_rate_percent"
                ),
                "queue_overflow_reduction_percent": _improvement(
                    fifo.get("dropped_messages"), proposed.get("dropped_messages")
                ),
            }
        )
    return comparisons


def generate_figures(
    trials: list[dict[str, str]],
    queue_rows: list[dict[str, str]],
    config: dict[str, Any],
    output_dir: Path,
) -> list[str]:
    cache_dir = output_dir.parent / ".matplotlib-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(cache_dir))
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 9,
            "axes.titlesize": 11,
            "axes.labelsize": 9,
            "legend.fontsize": 8,
            "figure.dpi": 140,
            "savefig.dpi": 300,
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )
    files: list[str] = []
    standard_workloads = {"light", "moderate", "near_saturation", "overload"}

    files.append(
        _line_metric_figure(
            trials,
            config,
            output_dir,
            "01_throughput_vs_offered_load",
            "throughput_messages_per_second",
            "Throughput vs Offered Load",
            "Throughput (messages/s)",
            plt,
            workload_filter=standard_workloads,
        )
    )
    files.append(
        _line_metric_figure(
            trials,
            config,
            output_dir,
            "02_p95_latency_vs_offered_load",
            "latency_p95_seconds",
            "p95 Latency vs Offered Load",
            "p95 latency (s)",
            plt,
            workload_filter=standard_workloads,
        )
    )
    files.append(_priority_latency_figure(trials, config, output_dir, plt))
    files.append(_fifo_adaptive_figure(trials, config, output_dir, plt))
    files.append(_queue_time_figure(queue_rows, config, output_dir, plt))
    files.append(
        _categorical_metric_figure(
            trials,
            config,
            output_dir,
            "06_bandwidth_saved",
            "bandwidth_saving_percent",
            "Bandwidth Saved",
            "Bandwidth saving (%)",
            plt,
        )
    )
    files.append(
        _categorical_metric_figure(
            trials,
            config,
            output_dir,
            "07_drop_rate",
            "drop_rate_percent",
            "Drop Rate",
            "Dropped scheduled messages (%)",
            plt,
        )
    )
    files.append(
        _categorical_metric_figure(
            trials,
            config,
            output_dir,
            "08_security_detection_rate",
            "security_detection_rate_percent",
            "Security Detection Rate",
            "Tagged attacks detected (%)",
            plt,
        )
    )
    files.append(
        _categorical_metric_figure(
            trials,
            config,
            output_dir,
            "09_cpu_usage",
            "cpu_utilization_percent",
            "Benchmark Process CPU Usage",
            "CPU utilization (%)",
            plt,
        )
    )
    files.append(_critical_congestion_figure(trials, config, output_dir, plt))
    return files


def write_report(
    path: Path,
    statistics_rows: list[dict[str, Any]],
    scheduler_rows: list[dict[str, Any]],
    config: dict[str, Any],
    manifest: dict[str, Any],
) -> None:
    index = {
        (row["workload"], row["configuration"], row["metric"]): row
        for row in statistics_rows
    }
    lines = [
        "# Phase 7 Experimental Summary",
        "",
        "This report presents measured values without asserting that any configuration is superior.",
        "",
        "## Reproducibility",
        "",
        f"- Experiment ID: `{manifest['experiment_id']}`",
        f"- Software version: `{manifest['software_version']}`",
        f"- Source/config SHA-256: `{manifest['source_fingerprint_sha256']}`",
        f"- Base random seed: `{manifest['random_seed']}`",
        f"- Runs per configuration: `{manifest['runs_per_configuration']}`",
        f"- Start: `{manifest['started_at']}`",
        f"- End: `{manifest['completed_at']}`",
        f"- Python: `{manifest['environment']['python_version']}`",
        f"- Platform: `{manifest['environment']['platform']}`",
        "",
        "Arrivals use seeded Poisson processes. Each workload/trial arrival trace is reused across all configurations. Means, medians, sample standard deviations, and two-sided 95% Student-t confidence intervals are calculated across repeated trials.",
        "",
        "Bandwidth saving is `(generated bytes - transmitted bytes) / generated bytes * 100`.",
        "CPU and peak memory values describe the benchmark process, measured with process CPU time and Python `tracemalloc`; they are not Docker host telemetry.",
        "Anomaly and attack detection latency is the simulated end-to-end time from generation of a tagged HIGH/CRITICAL event until Fog delivery.",
        "",
        "## Configurations",
        "",
        "| Configuration | Scheduler | Edge filtering | Role |",
        "|---|---:|---:|---|",
    ]
    for item in config["configurations"]:
        lines.append(
            f"| {item['label']} | {item['scheduler']} | {str(item['filtering']).lower()} | {item['role']} |"
        )
    lines.extend(
        [
            "",
            "## Aggregate Results",
            "",
            "Values are trial means; parentheses contain the 95% confidence interval.",
            "",
            "| Workload | Configuration | Throughput msg/s | p95 latency s | Drop % | Bandwidth saving % |",
            "|---|---|---:|---:|---:|---:|",
        ]
    )
    for workload in config["workloads"]:
        for configuration in config["configurations"]:
            key = (workload["id"], configuration["id"])
            lines.append(
                "| {workload} | {configuration} | {throughput} | {latency} | {drop} | {bandwidth} |".format(
                    workload=workload["label"],
                    configuration=configuration["label"],
                    throughput=_mean_ci(index.get((*key, "throughput_messages_per_second"))),
                    latency=_mean_ci(index.get((*key, "latency_p95_seconds"))),
                    drop=_mean_ci(index.get((*key, "drop_rate_percent"))),
                    bandwidth=_mean_ci(index.get((*key, "bandwidth_saving_percent"))),
                )
            )
    lines.extend(
        [
            "",
            "## Scheduler Metrics",
            "",
            "Latency and starvation compare unfiltered FIFO with the unfiltered adaptive-scheduling arm. Queue-overflow reduction compares direct FIFO with the full proposed arm. Positive improvement percentages indicate a lower measured value in the compared adaptive/proposed arm; negative values indicate an increase.",
            "",
            "| Workload | CRITICAL p95 improvement % | HIGH p95 improvement % | FIFO LOW starvation % | Adaptive LOW starvation % | Queue overflow reduction % |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in scheduler_rows:
        lines.append(
            f"| {row['workload_label']} | {_format(row['critical_latency_improvement_percent'])} | {_format(row['high_latency_improvement_percent'])} | {_format(row['fifo_low_starvation_rate_percent'])} | {_format(row['adaptive_low_starvation_rate_percent'])} | {_format(row['queue_overflow_reduction_percent'])} |"
        )
    lines.extend(
        [
            "",
            "## Resource and Detection Metrics",
            "",
            "| Workload | Configuration | CPU % | Peak memory MB | Attack detection latency s | Security detection % | Fairness index |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
    )
    for workload in config["workloads"]:
        for configuration in config["configurations"]:
            key = (workload["id"], configuration["id"])
            lines.append(
                "| {workload} | {configuration} | {cpu} | {memory} | {attack} | {detection} | {fairness} |".format(
                    workload=workload["label"],
                    configuration=configuration["label"],
                    cpu=_mean_ci(index.get((*key, "cpu_utilization_percent"))),
                    memory=_mean_ci(index.get((*key, "peak_memory_mb"))),
                    attack=_mean_ci(index.get((*key, "attack_detection_latency_seconds"))),
                    detection=_mean_ci(index.get((*key, "security_detection_rate_percent"))),
                    fairness=_mean_ci(index.get((*key, "jain_fairness_index"))),
                )
            )
    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            "- `raw_trials.csv`: one row per repeated trial and configuration.",
            "- `message_metrics.csv`: generated-message outcome and latency records.",
            "- `queue_timeseries.csv`: sampled queue state over simulated time.",
            "- `aggregate_statistics.csv`: mean, median, sample standard deviation, and 95% CI.",
            "- `scheduler_comparison.csv`: derived scheduler metrics.",
            "- `figures/`: each PNG/PDF has a same-named source CSV.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def _line_metric_figure(
    trials: list[dict[str, str]],
    config: dict[str, Any],
    output_dir: Path,
    filename: str,
    metric: str,
    title: str,
    ylabel: str,
    plt: Any,
    workload_filter: set[str] | None = None,
) -> str:
    data = _aggregate_for_figure(trials, config, metric, workload_filter=workload_filter)
    _write_csv(output_dir / f"{filename}.csv", data)
    fig, ax = plt.subplots(figsize=(6.7, 4.0), constrained_layout=True)
    markers = ("o", "s", "^", "D")
    linestyles = ("-", "-", "--", "--")
    for index, configuration in enumerate(config["configurations"]):
        subset = [row for row in data if row["configuration"] == configuration["id"]]
        subset.sort(key=lambda row: row["workload_order"])
        ax.errorbar(
            [row["offered_load_percent"] for row in subset],
            [row["mean"] for row in subset],
            yerr=[row["ci95_margin"] for row in subset],
            marker=markers[index],
            linestyle=linestyles[index],
            linewidth=1.6,
            capsize=3,
            label=configuration["label"],
            color=COLORS.get(configuration["id"]),
        )
    ax.set(title=title, xlabel="Mean offered load (% of diode capacity)", ylabel=ylabel)
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False)
    _save_figure(fig, output_dir / filename)
    plt.close(fig)
    return filename


def _categorical_metric_figure(
    trials: list[dict[str, str]],
    config: dict[str, Any],
    output_dir: Path,
    filename: str,
    metric: str,
    title: str,
    ylabel: str,
    plt: Any,
) -> str:
    data = _aggregate_for_figure(trials, config, metric)
    _write_csv(output_dir / f"{filename}.csv", data)
    fig, ax = plt.subplots(figsize=(7.0, 4.0), constrained_layout=True)
    x = list(range(len(config["workloads"])))
    markers = ("o", "s", "^", "D")
    linestyles = ("-", "-", "--", "--")
    for index, configuration in enumerate(config["configurations"]):
        subset = sorted(
            [row for row in data if row["configuration"] == configuration["id"]],
            key=lambda row: row["workload_order"],
        )
        ax.errorbar(
            x,
            [row["mean"] for row in subset],
            yerr=[row["ci95_margin"] for row in subset],
            marker=markers[index],
            linestyle=linestyles[index],
            linewidth=1.6,
            capsize=3,
            label=configuration["label"],
            color=COLORS.get(configuration["id"]),
        )
    ax.set(
        title=title,
        ylabel=ylabel,
        xticks=x,
        xticklabels=[item["label"].split(" - ", 1)[0] for item in config["workloads"]],
    )
    ax.set_xlabel("Workload")
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False)
    _save_figure(fig, output_dir / filename)
    plt.close(fig)
    return filename


def _priority_latency_figure(
    trials: list[dict[str, str]], config: dict[str, Any], output_dir: Path, plt: Any
) -> str:
    filename = "03_latency_by_priority"
    priorities = ("critical", "high", "medium", "low")
    proposed = [row for row in trials if row["configuration"] == "proposed"]
    data = []
    for workload_order, workload in enumerate(config["workloads"]):
        selected = [row for row in proposed if row["workload"] == workload["id"]]
        for priority in priorities:
            values = [
                value
                for row in selected
                if (value := _number(row.get(f"{priority}_latency_p95_seconds"))) is not None
            ]
            stats = _summary(values)
            data.append(
                {
                    "workload": workload["id"],
                    "workload_label": workload["label"],
                    "workload_order": workload_order,
                    "priority": priority.upper(),
                    **stats,
                }
            )
    _write_csv(output_dir / f"{filename}.csv", data)
    fig, ax = plt.subplots(figsize=(7.2, 4.2), constrained_layout=True)
    x = list(range(len(config["workloads"])))
    width = 0.19
    palette = ["#D1495B", "#E9C46A", "#2A9D8F", "#4C566A"]
    for offset, priority in enumerate(priorities):
        selected = [row for row in data if row["priority"] == priority.upper()]
        ax.bar(
            [position + (offset - 1.5) * width for position in x],
            [row["mean"] for row in selected],
            width,
            yerr=[row["ci95_margin"] for row in selected],
            capsize=2,
            label=priority.upper(),
            color=palette[offset],
        )
    ax.set(
        title="Proposed-System p95 Latency by Priority",
        ylabel="p95 latency (s)",
        xticks=x,
        xticklabels=[item["label"].split(" - ", 1)[0] for item in config["workloads"]],
    )
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False, ncol=4)
    _save_figure(fig, output_dir / filename)
    plt.close(fig)
    return filename


def _fifo_adaptive_figure(
    trials: list[dict[str, str]], config: dict[str, Any], output_dir: Path, plt: Any
) -> str:
    filename = "04_fifo_vs_adaptive_scheduler"
    relevant = {"baseline_a_direct": "FIFO", "adaptive_only": "Adaptive"}
    standard = {"light", "moderate", "near_saturation", "overload"}
    data = []
    for configuration, label in relevant.items():
        for priority in ("critical", "high"):
            rows = _aggregate_for_figure(
                [row for row in trials if row["configuration"] == configuration],
                config,
                f"{priority}_latency_p95_seconds",
                workload_filter=standard,
            )
            for row in rows:
                row["series"] = f"{label} - {priority.upper()}"
                row["priority"] = priority.upper()
                data.append(row)
    _write_csv(output_dir / f"{filename}.csv", data)
    fig, ax = plt.subplots(figsize=(6.7, 4.0), constrained_layout=True)
    styles = {
        "FIFO - CRITICAL": ("#4C566A", "-"),
        "FIFO - HIGH": ("#2A9D8F", "--"),
        "Adaptive - CRITICAL": ("#D1495B", "-"),
        "Adaptive - HIGH": ("#E9C46A", "--"),
    }
    for series, (color, linestyle) in styles.items():
        selected = sorted(
            [row for row in data if row["series"] == series],
            key=lambda row: row["workload_order"],
        )
        ax.plot(
            [row["offered_load_percent"] for row in selected],
            [row["mean"] for row in selected],
            marker="o",
            color=color,
            linestyle=linestyle,
            label=series,
        )
    ax.set(
        title="FIFO vs Adaptive Scheduler",
        xlabel="Offered load (% of diode capacity)",
        ylabel="p95 latency (s)",
    )
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False)
    _save_figure(fig, output_dir / filename)
    plt.close(fig)
    return filename


def _queue_time_figure(
    queue_rows: list[dict[str, str]], config: dict[str, Any], output_dir: Path, plt: Any
) -> str:
    filename = "05_queue_size_over_time"
    grouped: dict[tuple[str, float], list[float]] = defaultdict(list)
    labels = {item["id"]: item["label"] for item in config["configurations"]}
    duration = float(config["duration_seconds"])
    for row in queue_rows:
        sample_time = _number(row.get("simulation_time_seconds"))
        size = _number(row.get("queue_size"))
        if row["workload"] == "overload" and sample_time is not None and size is not None:
            if sample_time <= duration:
                grouped[(row["configuration"], sample_time)].append(size)
    data = []
    for (configuration, sample_time), values in sorted(grouped.items()):
        data.append(
            {
                "configuration": configuration,
                "configuration_label": labels[configuration],
                "simulation_time_seconds": sample_time,
                **_summary(values),
            }
        )
    _write_csv(output_dir / f"{filename}.csv", data)
    fig, ax = plt.subplots(figsize=(6.7, 4.0), constrained_layout=True)
    for configuration in config["configurations"]:
        selected = [row for row in data if row["configuration"] == configuration["id"]]
        ax.plot(
            [row["simulation_time_seconds"] for row in selected],
            [row["mean"] for row in selected],
            label=configuration["label"],
            color=COLORS.get(configuration["id"]),
            linewidth=1.5,
        )
    ax.set(
        title="Queue Size Over Time at 150% Offered Load",
        xlabel="Simulation time (s)",
        ylabel="Mean queued messages",
    )
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False)
    _save_figure(fig, output_dir / filename)
    plt.close(fig)
    return filename


def _critical_congestion_figure(
    trials: list[dict[str, str]], config: dict[str, Any], output_dir: Path, plt: Any
) -> str:
    filename = "10_critical_traffic_during_congestion"
    congested = {"near_saturation", "overload", "burst", "critical_storm"}
    data = _aggregate_for_figure(
        trials,
        config,
        "critical_latency_p95_seconds",
        workload_filter=congested,
    )
    _write_csv(output_dir / f"{filename}.csv", data)
    fig, ax = plt.subplots(figsize=(6.7, 4.0), constrained_layout=True)
    workload_ids = [item["id"] for item in config["workloads"] if item["id"] in congested]
    x = list(range(len(workload_ids)))
    width = 0.19
    for index, configuration in enumerate(config["configurations"]):
        selected = sorted(
            [row for row in data if row["configuration"] == configuration["id"]],
            key=lambda row: workload_ids.index(row["workload"]),
        )
        ax.bar(
            [position + (index - 1.5) * width for position in x],
            [row["mean"] for row in selected],
            width,
            yerr=[row["ci95_margin"] for row in selected],
            capsize=2,
            label=configuration["label"],
            color=COLORS.get(configuration["id"]),
        )
    ax.set(
        title="CRITICAL Traffic Latency During Congestion",
        ylabel="CRITICAL p95 latency (s)",
        xticks=x,
        xticklabels=[item.replace("_", " ").title() for item in workload_ids],
    )
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False, fontsize=7)
    _save_figure(fig, output_dir / filename)
    plt.close(fig)
    return filename


def _aggregate_for_figure(
    trials: list[dict[str, str]],
    config: dict[str, Any],
    metric: str,
    *,
    workload_filter: set[str] | None = None,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[float]] = defaultdict(list)
    load: dict[str, float] = {}
    workload_order = {item["id"]: index for index, item in enumerate(config["workloads"])}
    workload_labels = {item["id"]: item["label"] for item in config["workloads"]}
    configuration_labels = {item["id"]: item["label"] for item in config["configurations"]}
    for row in trials:
        if workload_filter is not None and row["workload"] not in workload_filter:
            continue
        value = _number(row.get(metric))
        if value is None:
            continue
        grouped[(row["workload"], row["configuration"])].append(value)
        load[row["workload"]] = _number(row.get("offered_load_percent")) or 0.0
    output = []
    for (workload, configuration), values in sorted(grouped.items()):
        output.append(
            {
                "workload": workload,
                "workload_label": workload_labels[workload],
                "workload_order": workload_order[workload],
                "offered_load_percent": load[workload],
                "configuration": configuration,
                "configuration_label": configuration_labels[configuration],
                "metric": metric,
                **_summary(values),
            }
        )
    return output


def _trial_means(rows: list[dict[str, str]]) -> dict[tuple[str, str], dict[str, float]]:
    metrics = set(ANALYSIS_METRICS) | {"dropped_messages"}
    grouped: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    for row in rows:
        for metric in metrics:
            value = _number(row.get(metric))
            if value is not None:
                grouped[(row["workload"], row["configuration"], metric)].append(value)
    output: dict[tuple[str, str], dict[str, float]] = defaultdict(dict)
    for (workload, configuration, metric), values in grouped.items():
        output[(workload, configuration)][metric] = fmean(values)
    return output


def _summary(values: list[float]) -> dict[str, float | int]:
    if not values:
        return {"n": 0, "mean": 0.0, "sample_standard_deviation": 0.0, "ci95_margin": 0.0}
    sample_stddev = stdev(values) if len(values) > 1 else 0.0
    margin = _t_critical_95(len(values) - 1) * sample_stddev / math.sqrt(len(values))
    return {
        "n": len(values),
        "mean": fmean(values),
        "sample_standard_deviation": sample_stddev,
        "ci95_margin": margin,
    }


def _t_critical_95(degrees_freedom: int) -> float:
    values = {
        1: 12.706,
        2: 4.303,
        3: 3.182,
        4: 2.776,
        5: 2.571,
        6: 2.447,
        7: 2.365,
        8: 2.306,
        9: 2.262,
        10: 2.228,
        11: 2.201,
        12: 2.179,
        13: 2.160,
        14: 2.145,
        15: 2.131,
        16: 2.120,
        17: 2.110,
        18: 2.101,
        19: 2.093,
        20: 2.086,
        25: 2.060,
        30: 2.042,
    }
    if degrees_freedom <= 0:
        return 0.0
    # Use the lower tabulated degrees of freedom for a conservative interval.
    for boundary in sorted(values, reverse=True):
        if degrees_freedom >= boundary:
            return values[boundary]
    return values[1]


def _improvement(baseline: float | None, proposed: float | None) -> float | None:
    if baseline is None or proposed is None:
        return None
    if baseline == 0:
        return 0.0 if proposed == 0 else None
    return 100.0 * (baseline - proposed) / baseline


def _number(value: Any) -> float | None:
    if value in (None, "", "None", "null"):
        return None
    try:
        number = float(value)
        return number if math.isfinite(number) else None
    except (TypeError, ValueError):
        return None


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as input_file:
        return list(csv.DictReader(input_file))


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise ValueError(f"cannot write empty analysis data: {path}")
    fieldnames = list(rows[0])
    additional = sorted({key for row in rows for key in row} - set(fieldnames))
    with path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames + additional)
        writer.writeheader()
        writer.writerows(rows)


def _save_figure(figure: Any, path_without_suffix: Path) -> None:
    figure.savefig(path_without_suffix.with_suffix(".png"), bbox_inches="tight")
    figure.savefig(path_without_suffix.with_suffix(".pdf"), bbox_inches="tight")


def _mean_ci(row: dict[str, Any] | None) -> str:
    if row is None:
        return "n/a"
    return f"{row['mean']:.3f} ({row['ci95_lower']:.3f}, {row['ci95_upper']:.3f})"


def _format(value: Any) -> str:
    return "n/a" if value is None else f"{float(value):.3f}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate Phase 7 analysis from raw CSV.")
    parser.add_argument(
        "--result-dir",
        type=Path,
        default=Path("experiments/results/phase7"),
    )
    args = parser.parse_args()
    config = json.loads(
        (args.result_dir / "configuration.json").read_text(encoding="utf-8")
    )
    manifest = json.loads(
        (args.result_dir / "experiment_manifest.json").read_text(encoding="utf-8")
    )
    analyze_results(args.result_dir, config, manifest)
    print(f"Regenerated figures and report in {args.result_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

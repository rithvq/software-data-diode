"""Regenerate research summaries and figures from retained trial CSVs."""
import argparse
from collections import defaultdict
import csv
import os
from pathlib import Path
import statistics


# Two-sided 95% Student-t quantiles. Default repeated trials use df=4.
T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447,
       7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228, 15: 2.131, 20: 2.086, 30: 2.042}


def summary(values):
    mean = statistics.mean(values)
    if len(values) < 2:
        return {"n": len(values), "mean": mean, "median": mean,
                "stddev": None, "ci95_low": None, "ci95_high": None}
    sd = statistics.stdev(values)
    df = len(values) - 1
    critical = T95[max((key for key in T95 if key <= df), default=1)]
    margin = critical * sd / len(values) ** .5
    return {"n": len(values), "mean": mean, "median": statistics.median(values),
            "stddev": sd, "ci95_low": mean - margin, "ci95_high": mean + margin}


def analyze(directory: Path):
    os.environ.setdefault("MPLCONFIGDIR", str(directory.resolve() / ".matplotlib-cache"))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    with (directory / "raw_trials.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    groups = defaultdict(list)
    metadata = {"workload", "configuration", "trial", "seed", "started_at", "completed_at"}
    for row in rows:
        for metric, value in row.items():
            if metric not in metadata and value:
                groups[(row["workload"], row["configuration"], metric)].append(float(value))
    statistics_rows = [
        {"workload": workload, "configuration": config, "metric": metric, **summary(values)}
        for (workload, config, metric), values in sorted(groups.items())
    ]
    with (directory / "statistics.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(statistics_rows[0]))
        writer.writeheader()
        writer.writerows(statistics_rows)
    lines = [
        "# Feedback-Free Information Preservation: Experiment Summary", "",
        "These are repeated, paired-seed discrete-event simulations of the same policy engine used by the gateway.",
        "Service time uses configured bandwidth and estimated envelope bytes. It is not measured Docker throughput.",
        "A represented sample may be part of a statistical aggregate; it is not an exact original reading.",
        "Security detection, anomaly detection, physical network bandwidth, and service memory were not measured.",
        "Confidence intervals are two-sided Student-t intervals (conservative quantile for unlisted degrees of freedom).",
        "Missing priority samples are omitted, never replaced by zero; n<2 has no estimable standard deviation or confidence interval.",
        "No superiority, novelty, patentability, or publication readiness is inferred automatically.", "",
        "| Workload | Configuration | Metric | Runs | Mean | Median | SD | 95% CI |",
        "|---|---|---|---:|---:|---:|---:|---|",
    ]
    reported = {
        "throughput_messages_per_second": "Transmitted messages / simulated second",
        "latency_p95_seconds": "Represented sample p95 latency (s)",
        "critical_p95_seconds": "CRITICAL p95 latency (s)",
        "critical_preservation_percent": "CRITICAL samples represented (%)",
        "bandwidth_saving_percent": "Estimated bandwidth saving (%)",
        "low_starvation_percent": "LOW unavailable or late (%)",
        "queue_drop_percent": "Policy DROP actions / generated (%)",
        "represented_sample_percent": "Samples represented (%)",
    }
    for row in statistics_rows:
        if row["metric"] in reported:
            sd = f"{row['stddev']:.4f}" if row["stddev"] is not None else "NA"
            interval = f"[{row['ci95_low']:.4f}, {row['ci95_high']:.4f}]" if row["ci95_low"] is not None else "not estimable"
            lines.append(f"| {row['workload']} | {row['configuration']} | {row['metric']} | {row['n']} | {row['mean']:.4f} | {row['median']:.4f} | {sd} | {interval} |")
    (directory / "experiment_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    configurations = sorted({row["configuration"] for row in rows})
    workloads = sorted({row["workload"] for row in rows})
    for metric, label in reported.items():
        fig, ax = plt.subplots(figsize=(11, 5))
        for config in configurations:
            points = {r["workload"]: r for r in statistics_rows if r["configuration"] == config and r["metric"] == metric}
            x = [i for i, workload in enumerate(workloads) if workload in points]
            y = [points[workloads[i]]["mean"] for i in x]
            error = [(points[workloads[i]]["ci95_high"] - points[workloads[i]]["mean"]) if points[workloads[i]]["ci95_high"] is not None else 0 for i in x]
            ax.errorbar(x, y, yerr=error, marker="o", capsize=3, label=config, linewidth=1.2)
        ax.set_xticks(range(len(workloads)), workloads, rotation=20, ha="right")
        ax.set_ylabel(label)
        ax.set_title("Trial means; 95% t intervals where at least two values are available", fontsize=10)
        ax.grid(axis="y", alpha=.25)
        ax.legend(fontsize=8, ncol=2)
        fig.tight_layout()
        fig.savefig(directory / f"{metric}.png", dpi=200)
        plt.close(fig)
        with (directory / f"{metric}.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=["workload", "configuration", "trial", "seed", metric])
            writer.writeheader()
            writer.writerows({key: row[key] for key in writer.fieldnames} for row in rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    analyze(parser.parse_args().directory)

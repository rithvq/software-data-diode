"""Regenerate actual transport tables from immutable trial receipts, not model CSV."""

import argparse
import csv
import json
import math
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from statistics import fmean

from experiments.analysis.coverage_report import summarize
from experiments.runners.coverage_common import write_csv, write_json
from scripts.run_n10_udp import actual_metrics


def memory_bytes(text):
    value = text.split(" / ", 1)[0]
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(B|kB|MB|GB|KiB|MiB|GiB)", value)
    if not match:
        raise ValueError("unsupported Docker memory unit")
    scales = {
        "B": 1,
        "kB": 1000,
        "MB": 10**6,
        "GB": 10**9,
        "KiB": 1024,
        "MiB": 1024**2,
        "GiB": 1024**3,
    }
    return float(match[1]) * scales[match[2]]


def resources(folder):
    meta = json.loads((folder / "sender/replay_metadata.json").read_text())
    config = json.loads((folder / "sender/configuration.json").read_text())
    start = datetime.fromisoformat(meta["epoch_utc"]).timestamp()
    end = start + config["duration_seconds"] + config["deadline_seconds"]
    samples = defaultdict(list)
    failed = 0
    for line in (folder / "resources.jsonl").read_text().splitlines():
        row = json.loads(line)
        if not start <= row["timestamp"] <= end:
            continue
        if row["returncode"]:
            failed += 1
            continue
        for container in row["samples"]:
            for role in ("data-diode", "fog-receiver", "postgres"):
                if container["Name"] == meta["project"] + "-" + role + "-1":
                    samples[role].append(
                        (
                            float(container["CPUPerc"].removesuffix("%")),
                            memory_bytes(container["MemUsage"]),
                        )
                    )
    result = {"resource_failed_scrapes": failed}
    for role in ("data-diode", "fog-receiver", "postgres"):
        values = samples[role]
        prefix = role.replace("-", "_")
        result[prefix + "_resource_samples"] = len(values)
        result[prefix + "_sample_mean_cpu_percent"] = (
            fmean(v[0] for v in values) if values else None
        )
        result[prefix + "_sample_max_memory_bytes"] = (
            max(v[1] for v in values) if values else None
        )
    return result


def analyze(directory, output):
    directory, output = Path(directory), Path(output)
    if output.exists():
        raise ValueError("fresh analysis directory required")
    rows = []
    for trial in range(1, 6):
        for arm in ("rccd", "fixed_summary"):
            folder = directory / (arm + f"-{trial:02d}")
            snapshot = json.loads((folder / "postgres_receipts.json").read_text())
            row = actual_metrics(folder, snapshot, write_verdicts=False)
            row.update(resources(folder))
            diode = json.loads((folder / "diode_status.json").read_text())
            fog = json.loads((folder / "fog_status.json").read_text())
            row.update(
                diode_forward_attempts=diode["forward_attempts"],
                diode_queue_at_snapshot=diode["queue_frames"],
                fog_queue_at_snapshot=fog["queue_frames"],
                fog_partial_bytes_at_snapshot=fog["partial_bytes"],
                fog_spool_records_at_snapshot=fog["evidence_spool_records"],
                fog_udp_reply_calls=fog["socket_audit"]["udp_send_calls"],
            )
            if row["fog_udp_reply_calls"] or row["wrong_definite"]:
                raise AssertionError("actual no-reply or correctness check failed")
            rows.append(row)
    saved_path = directory / "raw_trials.csv"
    if saved_path.exists():
        with saved_path.open(newline="", encoding="utf-8") as handle:
            saved = {(r["arm"], int(r["trial"])): r for r in csv.DictReader(handle)}
        for row in rows:
            original = saved[(row["arm"], row["trial"])]
            for metric in (
                "decision_yield",
                "unknown_rate",
                "attempted_model_wire_bytes",
                "wrong_definite",
            ):
                if not math.isclose(
                    float(original[metric]), row[metric], rel_tol=1e-12
                ):
                    raise ValueError("actual receipts changed: " + metric)
    metrics = (
        "decision_yield",
        "unknown_rate",
        "raw_detail_availability",
        "critical_latency_p95_seconds",
        "attempted_model_wire_bytes",
        *(
            role + suffix
            for role in ("data_diode", "fog_receiver", "postgres")
            for suffix in ("_sample_mean_cpu_percent", "_sample_max_memory_bytes")
        ),
    )
    stats = []
    paired = []
    for arm in ("rccd", "fixed_summary"):
        selected = [r for r in rows if r["arm"] == arm]
        for metric in metrics:
            stats.append(
                {
                    "arm": arm,
                    "metric": metric,
                    "planned_trials": 5,
                    **summarize([r[metric] for r in selected if r[metric] is not None]),
                }
            )
    for metric in metrics:
        values = []
        for trial in range(1, 6):
            a = next(r for r in rows if r["arm"] == "rccd" and r["trial"] == trial)
            b = next(
                r for r in rows if r["arm"] == "fixed_summary" and r["trial"] == trial
            )
            if (a["seed"], a["paired_relative_trace_hash"]) != (
                b["seed"],
                b["paired_relative_trace_hash"],
            ):
                raise ValueError("unpaired actual original trace")
            if a[metric] is not None and b[metric] is not None:
                values.append(a[metric] - b[metric])
        paired.append(
            {
                "comparison": "rccd_minus_fixed_summary",
                "metric": metric,
                "planned_pairs": 5,
                **summarize(values),
            }
        )
    output.mkdir(parents=True)
    write_csv(output / "raw_trials.csv", rows)
    write_csv(output / "statistics.csv", stats)
    write_csv(output / "paired_differences.csv", paired)
    lines = [
        "# N10 Actual Docker/UDP Replay",
        "",
        "Five paired trials per arm. Recomputed from signed artifacts and retained PostgreSQL receipts, separately from simulation.",
        "Sender admission and schedule are precomputed using N4; only transport/receiver persistence are actual live measurements. Not native online gateway throughput.",
        "The receipt time is the stored receiver timestamp, not a database-commit completion measurement. Local send success is not receipt.",
        "Docker resource snapshots are reduced to one sample mean CPU / observed maximum memory per trial within replay time; snapshots are not independent replicates.",
        "Different aligned UTC origins and ephemeral epochs/keys are declared; relative traces are paired. No synthetic packet faults are claimed in this live matrix.",
        "",
        "| Arm | Metric | n | Mean | Median | Sample SD | 95% Student-t CI |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for row in stats:
        lines.append(
            f"| {row['arm']} | {row['metric']} | {row['n']} | {row['mean']} | {row['median']} | {row['stddev']} | [{row['ci95_low']}, {row['ci95_high']}] |"
        )
    delta = next(r for r in paired if r["metric"] == "decision_yield")
    lines += [
        "",
        "RCCD minus fixed-summary decision-yield paired mean: "
        + str(delta["mean"])
        + "; 95% CI ["
        + str(delta["ci95_low"])
        + ", "
        + str(delta["ci95_high"])
        + "].",
        "No superiority claim is implied. Attempted wire bytes add a modeled 28-byte IPv4/UDP overhead, not captured NIC traffic.",
        "Fog socket instrumentation recorded zero UDP sends; UDP/shared-host bidirectionality remains a limitation.",
    ]
    with (output / "experiment_summary.md").open("x", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    write_json(
        output / "analysis_manifest.json",
        {
            "measurement_scope": "ACTUAL_DOCKER_UDP_ARTIFACT_REPLAY_NOT_ONLINE_POLICY",
            "recomputed_from_receipts": True,
            "paired_trials": 5,
            "source_directory": str(directory),
        },
    )
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    analyze(args.directory, args.output)

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from experiments.analysis.analyze import analyze_results
from experiments.runners.benchmark import (
    environment_metadata,
    execute_trial,
    generate_workload,
    load_experiment_config,
    software_version,
)
from shared.persistence import repository_from_env


def run_benchmarks(
    config: dict[str, Any],
    output_dir: Path,
    *,
    config_path: Path,
    persist_to_database: bool = False,
) -> dict[str, Any]:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("Experiment output directory is not empty; choose a new directory to preserve raw results")
    output_dir.mkdir(parents=True, exist_ok=True)
    started_at = datetime.now(timezone.utc)
    experiment_id = str(uuid4())
    version, source_fingerprint = software_version(PROJECT_ROOT, config_path)
    trial_rows: list[dict[str, Any]] = []
    message_rows: list[dict[str, Any]] = []
    queue_rows: list[dict[str, Any]] = []
    seeds: list[int] = []
    runs = int(config["runs_per_configuration"])
    duration = float(config["duration_seconds"])
    capacity = float(config["diode_capacity_messages_per_second"])

    for workload_index, workload in enumerate(config["workloads"]):
        for trial in range(1, runs + 1):
            seed = int(config["random_seed"]) + workload_index * 10_000 + trial
            seeds.append(seed)
            arrivals = generate_workload(
                workload,
                duration=duration,
                capacity=capacity,
                seed=seed,
            )
            for configuration in config["configurations"]:
                print(
                    f"[{workload['id']}] trial={trial}/{runs} "
                    f"configuration={configuration['id']} seed={seed}"
                )
                summary, messages, queue = execute_trial(
                    workload,
                    configuration,
                    config,
                    trial=trial,
                    seed=seed,
                    arrivals=arrivals,
                    software_version=version,
                )
                trial_rows.append(summary)
                message_rows.extend(messages)
                queue_rows.extend(queue)

    completed_at = datetime.now(timezone.utc)
    raw_trials_path = output_dir / "raw_trials.csv"
    message_path = output_dir / "message_metrics.csv"
    queue_path = output_dir / "queue_timeseries.csv"
    _write_csv(raw_trials_path, trial_rows)
    _write_csv(message_path, message_rows)
    _write_csv(queue_path, queue_rows)
    (output_dir / "configuration.json").write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest = {
        "experiment_id": experiment_id,
        "experiment_name": config.get("experiment_name", "phase7"),
        "schema_version": config.get("schema_version", "1.0"),
        "software_version": version,
        "source_fingerprint_sha256": source_fingerprint,
        "random_seed": int(config["random_seed"]),
        "trial_seeds": sorted(set(seeds)),
        "runs_per_configuration": runs,
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "configuration_file": str(config_path),
        "configuration_snapshot": "configuration.json",
        "raw_files": [raw_trials_path.name, message_path.name, queue_path.name],
        "environment": environment_metadata(),
    }
    (output_dir / "experiment_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    analysis = analyze_results(output_dir, config, manifest)
    if persist_to_database:
        repository_from_env().save_experiment_metadata(
            uuid4(),
            str(config.get("experiment_name", "phase7")),
            started_at,
            completed_at,
            config,
            analysis,
        )
    return {"manifest": manifest, "analysis": analysis}


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise ValueError(f"cannot write empty experiment data: {path}")
    fieldnames = list(rows[0])
    additional = sorted({key for row in rows for key in row} - set(fieldnames))
    with path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames + additional)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Phase 7 research-grade benchmarks.")
    parser.add_argument(
        "--config",
        type=Path,
        default=PROJECT_ROOT / "experiments/workloads/phase7_workloads.json",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "experiments/results/phase7",
    )
    parser.add_argument("--runs", type=int, help="Override trials per configuration (minimum 5).")
    parser.add_argument("--seed", type=int, help="Override the base random seed.")
    parser.add_argument("--persist-to-database", action="store_true")
    args = parser.parse_args()

    config = load_experiment_config(args.config)
    if args.runs is not None:
        if args.runs < 5:
            parser.error("--runs must be at least 5")
        config["runs_per_configuration"] = args.runs
    if args.seed is not None:
        config["random_seed"] = args.seed
    if args.persist_to_database and not __import__("os").getenv("DATABASE_URL"):
        parser.error("DATABASE_URL is required with --persist-to-database")

    result = run_benchmarks(
        config,
        args.output_dir,
        config_path=args.config,
        persist_to_database=args.persist_to_database,
    )
    print(f"Completed experiment {result['manifest']['experiment_id']}")
    print(f"Raw results: {args.output_dir / 'raw_trials.csv'}")
    print(f"Report: {args.output_dir / 'experiment_summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

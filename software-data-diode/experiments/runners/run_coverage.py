"""Reproducible coverage matrix. CPU/storage figures describe this model process."""

import argparse
import hashlib
import json
import platform
import sqlite3
import sys
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from experiments.runners.benchmark import software_version
from experiments.runners.coverage_common import (
    digest,
    fault_schedule,
    generate_trace,
    read_config,
    seed_for,
    write_csv,
    write_json,
    write_jsonl,
)
from experiments.runners.coverage_simulation import replay, simulate
from shared.coverage.contracts import load_contract


def pair_trial(task):
    doc, case, trial, directory = task
    directory = Path(directory)
    directory.mkdir()
    contract = load_contract(ROOT / "config/rule_coverage.json")
    seed = seed_for(doc, case["trace_group"], trial)
    trace = generate_trace(doc, case, seed)
    faults = fault_schedule(doc, case, seed)
    write_jsonl(directory / "original_trace.jsonl.gz", trace)
    write_jsonl(directory / "fault_schedule.jsonl.gz", faults)
    rows = []
    arms = list(doc["configurations"])
    # Rotate arm order per trial; deterministic correctness is independent of timing.
    arms = arms[trial % len(arms) :] + arms[: trial % len(arms)]
    for arm in arms:
        started = datetime.now(timezone.utc).isoformat()
        result = simulate(doc, case, arm, trace, faults, contract, seed)
        metrics, verdicts = replay(result, doc, contract)
        if arm != "no_semantics" and metrics["wrong_definite"]:
            raise AssertionError("in-scope wrong definite in " + case["id"] + "/" + arm)
        write_jsonl(directory / (arm + "-accepted.jsonl.gz"), result.pop("accepted"))
        write_jsonl(directory / (arm + "-artifacts.jsonl.gz"), result.pop("artifacts"))
        write_jsonl(
            directory / (arm + "-forward.jsonl.gz"), result.pop("transmissions")
        )
        write_jsonl(directory / (arm + "-queue.jsonl.gz"), result.pop("queue"))
        write_json(directory / (arm + "-context.json"), result)
        write_csv(directory / (arm + "-verdicts.csv"), verdicts)
        row = {
            "case": case["id"],
            "trace_group": case["trace_group"],
            "trial": trial,
            "seed": seed,
            "measurement_scope": "SIMULATION",
            "trace_hash": digest(trace),
            "fault_hash": digest(faults),
            "started_at": started,
            "ended_at": datetime.now(timezone.utc).isoformat(),
            **{k: v for k, v in metrics.items() if k != "refusal_reasons"},
            "refusal_reasons": json.dumps(metrics["refusal_reasons"], sort_keys=True),
        }
        rows.append(row)
    write_csv(directory / "raw_trials.csv", rows)
    print(f"Completed {case['id']} paired trial {trial}: {len(arms)} arms", flush=True)
    return rows


def run(path, output, workers=1, no_analysis=False, cases=None, arms=None):
    doc = read_config(path)
    if cases:
        if len(set(cases)) != len(cases) or set(cases) - {
            c["id"] for c in doc["cases"]
        }:
            raise ValueError("unknown or duplicate case selection")
        doc["cases"] = [c for c in doc["cases"] if c["id"] in cases]
    if arms:
        if len(set(arms)) != len(arms) or set(arms) - set(doc["configurations"]):
            raise ValueError("unknown or duplicate arm selection")
        doc["configurations"] = [a for a in doc["configurations"] if a in arms]
    if output.exists():
        raise ValueError("choose a new no-overwrite output directory")
    if not 1 <= workers <= 4:
        raise ValueError("bounded model worker count is 1-4")
    output.mkdir(parents=True)
    (output / "pairs").mkdir()
    write_json(output / "configuration.json", doc)
    write_json(
        output / "contract.json",
        load_contract(ROOT / "config/rule_coverage.json").model_dump(mode="json"),
    )
    revision, legacy_fingerprint = software_version(ROOT, path)
    paths = [
        *sorted((ROOT / "shared").rglob("*.py")),
        *sorted((ROOT / "config").glob("*.json")),
        ROOT / "constraints.txt",
        *sorted((ROOT / "experiments/runners").glob("coverage_*.py")),
        Path(__file__),
        ROOT / "experiments/analysis/coverage_report.py",
        Path(path),
    ]
    fingerprints = {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in paths
        if p.exists()
    }
    manifest = {
        "phase": "N10",
        "measurement_scope": "SIMULATION_NOT_DOCKER_UDP",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "software_version": revision,
        "legacy_fingerprint_sha256": legacy_fingerprint,
        "source_sha256": fingerprints,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "workers": workers,
        "configuration": doc,
        "dependencies": {},
        "sqlite_version": sqlite3.sqlite_version,
        "unsafe_arms": ["no_semantics"],
        "cryptographic_keys": "public-seed synthetic test keys; never production credentials",
        "differences": "N4 chunks externally encoded with N5 signed headers; experimental signed raw ingress provenance added at serialization, not in policy stream attributes; common state export; no GatewayUDP polling or live service CPU implied",
    }
    for name in ("pydantic", "cryptography", "matplotlib"):
        try:
            manifest["dependencies"][name] = version(name)
        except PackageNotFoundError:
            manifest["dependencies"][name] = None
    write_json(output / "start-manifest.json", manifest)
    tasks = [
        (doc, c, t, str(output / "pairs" / (c["id"] + f"-{t:02d}")))
        for c in doc["cases"]
        for t in range(1, doc["runs_per_configuration"] + 1)
    ]
    rows = []
    if workers == 1:
        for task in tasks:
            rows.extend(pair_trial(task))
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            for returned in pool.map(pair_trial, tasks):
                rows.extend(returned)
    rows.sort(key=lambda r: (r["case"], r["trial"], r["arm"]))
    write_csv(output / "raw_trials.csv", rows)
    manifest.update(
        ended_at=datetime.now(timezone.utc).isoformat(),
        completed_trials=len(rows),
        result_sha256=hashlib.sha256(
            (output / "raw_trials.csv").read_bytes()
        ).hexdigest(),
    )
    write_json(output / "manifest.json", manifest)
    if not no_analysis:
        from experiments.analysis.coverage_report import analyze

        analyze(output, output / "analysis")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        type=Path,
        default=ROOT / "experiments/workloads/coverage_workloads.json",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--no-analysis", action="store_true")
    parser.add_argument(
        "--case",
        action="append",
        help="Select declared cases; retained configuration records this subset",
    )
    parser.add_argument(
        "--arm",
        action="append",
        help="Select declared arms; each still requires all repeated trials",
    )
    args = parser.parse_args()
    run(
        args.config.resolve(),
        args.output.resolve(),
        args.workers,
        args.no_analysis,
        args.case,
        args.arm,
    )

"""No-overwrite bundle of completed paired strata, with explicit source provenance."""

import argparse
import csv
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from experiments.runners.coverage_common import (
    digest,
    read_config,
    write_csv,
    write_json,
)


def bundle(config, sources, output):
    doc = read_config(config)
    sources = [Path(p).resolve() for p in sources]
    output = Path(output).resolve()
    if output.exists() or any(
        output == p or output in p.parents or p in output.parents for p in sources
    ):
        raise ValueError("new nonoverlapping bundle output required")
    contracts = []
    parents = {}
    for source in sources:
        parent = json.loads((source / "start-manifest.json").read_text())
        settings = json.loads((source / "configuration.json").read_text())
        if {
            k: v for k, v in settings.items() if k not in {"cases", "configurations"}
        } != {k: v for k, v in doc.items() if k not in {"cases", "configurations"}}:
            raise ValueError("incompatible paired configurations")
        if set(settings["configurations"]) - set(doc["configurations"]):
            raise ValueError("undeclared source arms")
        if parent["measurement_scope"] != "SIMULATION_NOT_DOCKER_UDP":
            raise ValueError("actual and model trials must never be combined")
        contracts.append(json.loads((source / "contract.json").read_text()))
        parents[str(source)] = {
            "manifest": parent,
            "declared_cases": settings["cases"],
            "arms": settings["configurations"],
        }
    if len({digest(c) for c in contracts}) != 1:
        raise ValueError("different contracts")
    chosen = []
    rows = []
    for case in doc["cases"]:
        for trial in range(1, doc["runs_per_configuration"] + 1):
            name = case["id"] + f"-{trial:02d}"
            available = [
                p for p in sources if (p / "pairs" / name / "raw_trials.csv").is_file()
            ]
            trials = []
            origins = {}
            for source in available:
                if case not in parents[str(source)]["declared_cases"]:
                    raise ValueError("stratum not declared by source")
                pair = source / "pairs" / name
                if any(p.is_symlink() for p in pair.rglob("*")):
                    raise ValueError("symlinked trial inputs are not supported")
                with (pair / "raw_trials.csv").open(
                    newline="", encoding="utf-8"
                ) as handle:
                    current = list(csv.DictReader(handle))
                if len(current) != len(parents[str(source)]["arms"]) or {
                    r["arm"] for r in current
                } != set(parents[str(source)]["arms"]):
                    raise ValueError("incomplete source comparison")
                for row in current:
                    if row["arm"] in origins:
                        raise ValueError("ambiguous repeated arm")
                    origins[row["arm"]] = pair
                trials.extend(current)
            if len(trials) != len(doc["configurations"]) or {
                r["arm"] for r in trials
            } != set(doc["configurations"]):
                raise ValueError("incomplete arm comparison")
            if (
                len({(r["seed"], r["trace_hash"], r["fault_hash"]) for r in trials})
                != 1
            ):
                raise ValueError("unpaired original or fault trace")
            if any(
                r["case"] != case["id"]
                or int(r["trial"]) != trial
                or r["measurement_scope"] != "SIMULATION"
                for r in trials
            ):
                raise ValueError("incorrect pair identity")
            chosen.append((name, origins, trials))
            rows.extend(trials)
    output.mkdir(parents=True)
    (output / "pairs").mkdir()
    for name, origins, trials in chosen:
        target = output / "pairs" / name
        target.mkdir()
        first = next(iter(origins.values()))
        for filename in ("original_trace.jsonl.gz", "fault_schedule.jsonl.gz"):
            shutil.copy2(first / filename, target / filename)
        for arm, pair in origins.items():
            files = list(pair.glob(arm + "-*"))
            if len(files) != 6:
                raise ValueError("incomplete retained artifacts")
            for path in files:
                shutil.copy2(path, target / path.name)
        write_csv(target / "raw_trials.csv", trials)
    write_json(output / "configuration.json", doc)
    write_json(output / "contract.json", contracts[0])
    rows.sort(key=lambda r: (r["case"], int(r["trial"]), r["arm"]))
    write_csv(output / "raw_trials.csv", rows)
    manifest = {
        "phase": "N10",
        "measurement_scope": "SIMULATION_NOT_DOCKER_UDP",
        "bundled_at": datetime.now(timezone.utc).isoformat(),
        "completed_trials": len(rows),
        "parents": parents,
        "pair_sources": {
            name: {arm: str(pair.parent.parent) for arm, pair in origins.items()}
            for name, origins, _ in chosen
        },
        "limits": "Completed strata retain original source/version/timing provenance. A bundle is not a new execution or a claim that all source versions are identical. Default analysis independently verifies every retained artifact and oracle verdict.",
    }
    write_json(output / "start-manifest.json", manifest)
    write_json(output / "manifest.json", manifest)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--source", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    bundle(args.config, args.source, args.output)

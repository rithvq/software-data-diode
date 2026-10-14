"""Recompute scoped answers, trial statistics and figures from retained artifacts."""

import argparse
import base64
import csv
import json
import math
import os
from collections import defaultdict
from pathlib import Path

from experiments.analysis.information_report import summary
from experiments.runners.coverage_common import (
    digest,
    read_jsonl,
    write_csv,
    write_json,
)
from experiments.runners.coverage_simulation import (
    capacity_integral,
    replay,
    transmission_finish,
)
from shared.coverage.models import RuleContract

METRICS = (
    "decision_yield",
    "unknown_rate",
    "false_false",
    "false_true",
    "wrong_definite",
    "unknown_duration_seconds",
    "decisions_per_kib",
    "incident_recall",
    "positive_rule_recall",
    "raw_detail_availability",
    "latency_p50_seconds",
    "latency_p95_seconds",
    "latency_p99_seconds",
    "critical_latency_p50_seconds",
    "critical_latency_p95_seconds",
    "critical_latency_p99_seconds",
    "decision_latency_p95_seconds",
    "wire_bytes",
    "evidence_bytes",
    "repeat_bytes",
    "framing_bytes",
    "state_bytes",
    "generated_bytes",
    "evidence_fraction",
    "queue_max_items",
    "queue_max_bytes",
    "queue_average_items",
    "outbox_final_bytes",
    "admission_refused",
    "accepted",
    "storage_bytes",
    "runner_cpu_seconds",
    "runner_cpu_percent",
    "runner_sampled_rss_bytes",
    "bandwidth_saving",
    "raw_dropped_originals",
    "raw_reduced_originals",
    "queue_wait_p50_seconds",
    "queue_wait_p95_seconds",
    "queue_wait_p99_seconds",
    *(
        f"{p}_latency_p{q}_seconds"
        for p in ("high", "medium", "low")
        for q in (50, 95, 99)
    ),
)
BASELINES = (
    "fifo_gap",
    "legacy",
    "heartbeat",
    "compact_summary",
    "fixed_summary",
    "rccd",
    "always_unknown",
)
COLORS = ("#555b63", "#247ba0", "#7a9d54", "#ba6b23", "#b02e45", "#8b7d9b", "#007f73")


def number(value):
    if value in (None, ""):
        return None
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("nonfinite results are not valid samples")
    return result


def summarize(values):
    return (
        summary(values)
        if values
        else {
            "n": 0,
            "mean": None,
            "median": None,
            "stddev": None,
            "ci95_low": None,
            "ci95_high": None,
        }
    )


def statistics(rows, doc):
    groups = defaultdict(list)
    keys = set()
    for row in rows:
        key = (row["case"], row["arm"])
        if (key, int(row["trial"])) in keys:
            raise ValueError("duplicate trial, not independent replication")
        keys.add((key, int(row["trial"])))
        groups[key].append(row)
    expected = {(c["id"], arm) for c in doc["cases"] for arm in doc["configurations"]}
    if set(groups) != expected:
        raise ValueError("missing/extra declared case or arm")
    stats = []
    paired = []
    for key, trials in sorted(groups.items()):
        if len(trials) != doc["runs_per_configuration"] or len(
            {r["seed"] for r in trials}
        ) != len(trials):
            raise ValueError(
                "at least five distinct paired trial seeds per configuration required"
            )
        for metric in METRICS:
            values = [number(r.get(metric)) for r in trials]
            values = [v for v in values if v is not None]
            stats.append(
                {
                    "case": key[0],
                    "arm": key[1],
                    "metric": metric,
                    "planned_trials": len(trials),
                    **summarize(values),
                }
            )
    indexed = {(r["case"], r["arm"], int(r["trial"])): r for r in rows}
    for case in doc["cases"]:
        if "rccd" not in doc["configurations"]:
            continue
        for arm in doc["configurations"]:
            if arm == "rccd":
                continue
            for metric in METRICS:
                differences = []
                matches = 0
                for trial in range(1, doc["runs_per_configuration"] + 1):
                    a = indexed[(case["id"], "rccd", trial)]
                    b = indexed[(case["id"], arm, trial)]
                    if (a["seed"], a["trace_hash"], a["fault_hash"]) != (
                        b["seed"],
                        b["trace_hash"],
                        b["fault_hash"],
                    ):
                        raise ValueError("unpaired original exposure or fault schedule")
                    matches += a["accepted_trace_hash"] == b["accepted_trace_hash"]
                    av, bv = number(a.get(metric)), number(b.get(metric))
                    if av is not None and bv is not None:
                        differences.append(av - bv)
                paired.append(
                    {
                        "case": case["id"],
                        "comparison": "rccd_minus_" + arm,
                        "metric": metric,
                        "accepted_scope_equal_trials": matches,
                        "planned_pairs": doc["runs_per_configuration"],
                        **summarize(differences),
                    }
                )
    return stats, paired


def recover_rows(directory, doc, contract):
    rows = []
    for case in doc["cases"]:
        for trial in range(1, doc["runs_per_configuration"] + 1):
            pair = directory / "pairs" / (case["id"] + f"-{trial:02d}")
            with (pair / "raw_trials.csv").open(newline="", encoding="utf-8") as handle:
                saved = {r["arm"]: r for r in csv.DictReader(handle)}
            trace = read_jsonl(pair / "original_trace.jsonl.gz")
            faults = read_jsonl(pair / "fault_schedule.jsonl.gz")
            for arm in doc["configurations"]:
                result = json.loads((pair / (arm + "-context.json")).read_text())
                result["accepted"] = read_jsonl(pair / (arm + "-accepted.jsonl.gz"))
                result["artifacts"] = read_jsonl(pair / (arm + "-artifacts.jsonl.gz"))
                result["transmissions"] = read_jsonl(pair / (arm + "-forward.jsonl.gz"))
                if result["static"]["accepted_trace_hash"] != digest(
                    [
                        {k: v for k, v in r.items() if k != "ledger_epoch"}
                        for r in result["accepted"]
                    ]
                ):
                    raise ValueError("accepted scope changed")
                by_source = {r["source_id"]: r for r in trace}
                for record in result["accepted"]:
                    source = by_source[record["source_id"]]
                    if (
                        not source["upstream_delivered"]
                        or source["message"] != record["message"]
                    ):
                        raise ValueError(
                            "accepted trace is not the paired original input"
                        )
                totals = defaultdict(int)
                artifacts = {a["artifact_id"]: a for a in result["artifacts"]}
                for tx in result["transmissions"]:
                    frame = base64.b64decode(
                        artifacts[tx["artifact_id"]]["frames"][tx["part"]]
                    )
                    if tx["wire_bytes"] != len(frame) + 28 or tx["udp_bytes"] != len(
                        frame
                    ):
                        raise ValueError("uncharged signature/header/part bytes")
                    if not math.isclose(
                        transmission_finish(
                            tx["start_seconds"], tx["wire_bytes"], case, doc
                        ),
                        tx["finish_seconds"],
                        abs_tol=1e-9,
                    ):
                        raise ValueError("capacity pacing changed")
                    totals["wire_bytes"] += tx["wire_bytes"]
                    totals[tx["kind"].lower() + "_bytes"] += len(frame)
                    totals["repeat_bytes"] += tx["wire_bytes"] if tx["repeat"] else 0
                    if (
                        totals["wire_bytes"]
                        > capacity_integral(tx["finish_seconds"], case, doc) + 1e-6
                    ):
                        raise ValueError("forward budget exceeded")
                    field = faults[tx["fault_slot"]]
                    drop = (
                        (
                            case["fault"] == "independent"
                            and field["uniform"] < case.get("loss", 0)
                        )
                        or (
                            case["fault"] == "evidence_only"
                            and tx["kind"] == "EVIDENCE"
                            and field["uniform"] < case.get("loss", 1)
                        )
                        or (
                            case["fault"] == "burst_loss"
                            and doc["duration_seconds"] * 0.5
                            <= tx["finish_seconds"]
                            < doc["duration_seconds"] * 0.7
                        )
                    )
                    if bool(drop) != tx["dropped"]:
                        raise ValueError("fault application changed")
                for key in (
                    "wire_bytes",
                    "raw_bytes",
                    "evidence_bytes",
                    "state_bytes",
                    "repeat_bytes",
                ):
                    if totals[key] != result["static"][key]:
                        raise ValueError("retained wire cost mismatch")
                metrics, verdicts = replay(result, doc, contract)
                original = saved[arm]
                if original["trace_hash"] != digest(trace) or original[
                    "fault_hash"
                ] != digest(faults):
                    raise ValueError("paired input hash changed")
                for name, value in metrics.items():
                    if name == "refusal_reasons":
                        continue
                    expected = (
                        number(original.get(name))
                        if isinstance(value, (int, float)) or value is None
                        else original.get(name)
                    )
                    if isinstance(value, (int, float)):
                        if expected is None or not math.isclose(
                            value, expected, rel_tol=1e-10, abs_tol=1e-10
                        ):
                            raise ValueError("recomputed metric mismatch: " + name)
                    elif value is None and original.get(name) not in (None, ""):
                        raise ValueError("missing-sample mismatch")
                if arm != "no_semantics" and metrics["wrong_definite"]:
                    raise AssertionError("wrong definite in supported baseline")
                rows.append(
                    {
                        **original,
                        **{k: v for k, v in metrics.items() if k != "refusal_reasons"},
                    }
                )
                yield_verdicts = {
                    (int(v["window_index"]), v["rule_id"]): v["truth"] for v in verdicts
                }
                with (pair / (arm + "-verdicts.csv")).open(
                    newline="", encoding="utf-8"
                ) as handle:
                    old = {
                        (int(v["window_index"]), v["rule_id"]): v["truth"]
                        for v in csv.DictReader(handle)
                    }
                if old != yield_verdicts:
                    raise ValueError("verdict replay mismatch")
    return rows


def figure(output, name, points, xlabel, ylabel, title):
    import matplotlib.pyplot as plt

    write_csv(output / (name + ".csv"), points)
    fig, ax = plt.subplots(figsize=(10.5, 5.4))
    arms = list(dict.fromkeys(p["arm"] for p in points))
    labels = list(dict.fromkeys(p["x_label"] for p in points))
    for i, arm in enumerate(arms):
        selected = [p for p in points if p["arm"] == arm and p["mean"] is not None]
        x = [labels.index(p["x_label"]) for p in selected]
        y = [p["mean"] for p in selected]
        errors = [
            (p["ci95_high"] - p["mean"]) if p["ci95_high"] is not None else 0
            for p in selected
        ]
        ax.errorbar(
            x,
            y,
            yerr=errors,
            color=COLORS[i % len(COLORS)],
            marker="o",
            linewidth=1.2,
            capsize=3,
            label=arm,
        )
    ax.set_xticks(
        range(len(labels)),
        labels,
        rotation=50 if len(labels) > 7 else 18,
        ha="right",
        fontsize=8,
    )
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontsize=11)
    ax.grid(axis="y", alpha=0.2)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1), fontsize=8)
    fig.subplots_adjust(
        left=0.10, right=0.77, bottom=0.30 if len(labels) > 7 else 0.22, top=0.90
    )
    fig.savefig(output / (name + ".png"), dpi=180)
    fig.savefig(output / (name + ".pdf"))
    plt.close(fig)


def analyze(directory, output, recompute=True):
    directory, output = Path(directory), Path(output)
    if output.exists():
        raise ValueError(
            "analysis output must be new; never replace prior figures/tables"
        )
    doc = json.loads((directory / "configuration.json").read_text())
    contract = RuleContract.model_validate(
        json.loads((directory / "contract.json").read_text())
    )
    if recompute:
        rows = recover_rows(directory, doc, contract)
    else:
        with (directory / "raw_trials.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            rows = list(csv.DictReader(handle))
    stats, paired = statistics(rows, doc)
    output.mkdir(parents=True)
    write_csv(output / "statistics.csv", stats)
    write_csv(output / "paired_differences.csv", paired)
    os.environ.setdefault("MPLCONFIGDIR", str(output / ".matplotlib-cache"))
    import matplotlib

    matplotlib.use("Agg")
    lookup = {(s["case"], s["arm"], s["metric"]): s for s in stats}
    specs = (
        (
            "01_decision_yield_budget",
            "decision_yield",
            ("moderate", "moderate_double_budget"),
            BASELINES,
            "Nominal forward capacity (B/s)",
            "Correct definite / opportunities",
        ),
        (
            "02_unknown_loss",
            "unknown_rate",
            (
                "moderate",
                "loss_10",
                "loss_25",
                "burst_loss",
                "evidence_loss",
                "reorder_delay",
            ),
            BASELINES,
            "Separate fault strata",
            "UNKNOWN / opportunities",
        ),
        (
            "03_false_definite",
            "wrong_definite",
            tuple(c["id"] for c in doc["cases"]),
            ("rccd", "fixed_summary", "no_semantics"),
            "Workload / fault stratum",
            "Wrong definite per trial (TRUE or FALSE)",
        ),
        (
            "04_evidence_overhead",
            "evidence_fraction",
            (
                "light",
                "moderate",
                "near_capacity",
                "overload",
                "burst",
                "critical_storm",
            ),
            BASELINES,
            "Workload",
            "Signed evidence bytes / UDP bytes",
        ),
        (
            "05_critical_latency",
            "critical_latency_p95_seconds",
            ("near_capacity", "overload", "burst", "critical_storm", "capacity_step"),
            BASELINES,
            "Congestion stratum",
            "Exact CRITICAL raw p95 latency (s)",
        ),
        (
            "06_reservation_recovery",
            "decision_yield",
            ("near_capacity", "overload", "evidence_loss", "recovery"),
            (
                "rccd",
                "no_semantics",
                "no_advance",
                "no_service",
                "no_repeats",
                "no_recovery",
            ),
            "Ablation stratum",
            "Correct definite / opportunities",
        ),
    )
    for name, metric, cases, arms, xlabel, ylabel in specs:
        points = []
        for case in cases:
            for arm in arms:
                if (case, arm, metric) in lookup:
                    label = (
                        str(next(c["budget"] for c in doc["cases"] if c["id"] == case))
                        if "budget" in name
                        else case
                    )
                    points.append({"x_label": label, **lookup[(case, arm, metric)]})
        if points:
            figure(
                output,
                name,
                points,
                xlabel,
                ylabel,
                "Simulation trial means and 95% Student-t intervals",
            )
            raw = [
                {
                    "case": r["case"],
                    "arm": r["arm"],
                    "trial": r["trial"],
                    "seed": r["seed"],
                    "budget": r["budget"],
                    metric: r.get(metric),
                }
                for r in rows
                if r["case"] in cases and r["arm"] in arms
            ]
            write_csv(output / (name + "-raw.csv"), raw)
    lines = [
        "# N10 Coverage Experiment Summary",
        "",
        "Measurement scope: bounded discrete-event simulation using N4 admission, N5 signing/framing and independent accepted-ingress oracle. Not measured Docker/UDP throughput.",
        f"{len(rows)} trials; {doc['runs_per_configuration']} paired seeds per arm/case. Workloads and fault strata are not pooled.",
        "CI method: two-sided Student-t interval on independent trial means or within-seed differences; conservative tabulated quantile. Packet/rule observations within one trial are not independent replicates.",
        "Small n and discrete bounded yields limit normal-mean interval accuracy; intervals are descriptive, not proofs. Missing denominators/priority samples are NA and lower metric n is shown.",
        f"Experimental service shares: evidence {doc.get('evidence_share_percent', 50)}%, protected {doc.get('protected_share_percent', 25)}%; these are not the deployment's 10% evidence default.",
        "All wire costs include signed envelopes, real signed transport parts, controls, UDP/IP model overhead and charged repeats. Common local state is charged to all transmitting arms.",
        "FIFO and heartbeat have authenticated original ingress range closures. Fixed summaries preserve original predicates and use the same codec, repeats, queues and lane service as RCCD, without advance reservation.",
        "compact_summary is the stronger low-cost ordinary summary: exact original counts, signed epoch/contract/device/window/range and limitations, encoded in N5 binary signed parts without RCC commitment/witness/chain overhead. It is a harness baseline, not a deployed Fog schema.",
        "Legacy uses the actual InformationEngine and native anomaly/correlation algorithms; exact-rule yield is a conservative original-witness projection, not a relabeling of legacy anomalies as exact coverage.",
        "no_semantics is an intentionally unsafe test-only aggregate-mean assertion. Its errors are disclosed, not deployed. Always-UNKNOWN has zero traffic and undefined decisions/KiB, not an advantage.",
        "Receiver evaluation and fault observations are performed after sender scheduling; none are policy inputs.",
        "Raw offered traces are paired. Admission scopes can diverge; paired_differences.csv records accepted-scope equality and differences are not silently described as identical admitted populations.",
        "Model CPU/RSS/storage includes common experimental ledger/bookkeeping, not native service resource performance. Subprocess contention/order/imports can affect those measurements.",
        "",
        "| Case | Arm | Correct yield mean | UNKNOWN mean | Wrong FALSE total | Wrong TRUE total | Wire bytes mean |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for c in doc["cases"]:
        for arm in doc["configurations"]:

            def mean(metric, case_id=c["id"], arm_id=arm):
                return lookup[(case_id, arm_id, metric)]["mean"]

            lines.append(
                f"| {c['id']} | {arm} | {mean('decision_yield'):.4f} | {mean('unknown_rate'):.4f} | {mean('false_false') * doc['runs_per_configuration']:.0f} | {mean('false_true') * doc['runs_per_configuration']:.0f} | {mean('wire_bytes'):.1f} |"
            )
    lines += [
        "",
        "## Fixed summaries versus coupled admission",
        "",
        "These are actual paired observations, not an automatic superiority claim:",
        "",
        "| Case | RCCD minus fixed-summary yield | Paired 95% CI | Equal accepted scopes |",
        "|---|---:|---|---:|",
    ]
    for row in paired:
        if (
            row["comparison"] == "rccd_minus_fixed_summary"
            and row["metric"] == "decision_yield"
        ):
            lines.append(
                f"| {row['case']} | {row['mean']:.4f} | [{row['ci95_low']:.4f}, {row['ci95_high']:.4f}] | {row['accepted_scope_equal_trials']}/{row['planned_pairs']} |"
            )
    matches = [
        r
        for r in paired
        if r["comparison"] == "rccd_minus_fixed_summary"
        and r["metric"] == "decision_yield"
    ]
    wins = sum(r["mean"] > 0 for r in matches)
    ties = sum(r["mean"] == 0 for r in matches)
    losses = sum(r["mean"] < 0 for r in matches)
    lines += [
        "",
        f"Across these separate case means: RCCD higher {wins}, equal {ties}, lower {losses}. Ordinary summaries that match or beat RCCD are explicitly retained.",
        "No pooled effect, patentability, universal zero-error guarantee or applicability to untested settings follows. Long-run signing-retention and N4 documentation limits remain.",
        "Real Docker/UDP replay, if run, is stored and summarized separately; simulation does not certify that implementation.",
    ]
    simple = [
        r
        for r in paired
        if r["comparison"] == "rccd_minus_compact_summary"
        and r["metric"] == "decision_yield"
    ]
    if simple:
        lines += [
            "",
            "## Compact Ordinary Summaries",
            "",
            "| Case | RCCD minus compact yield | Paired 95% CI | Equal accepted scopes |",
            "|---|---:|---|---:|",
        ]
        for r in simple:
            lines.append(
                f"| {r['case']} | {r['mean']:.4f} | [{r['ci95_low']:.4f}, {r['ci95_high']:.4f}] | {r['accepted_scope_equal_trials']}/{r['planned_pairs']} |"
            )
        lines.append(
            f"RCCD higher {sum(r['mean'] > 0 for r in simple)}, equal {sum(r['mean'] == 0 for r in simple)}, lower {sum(r['mean'] < 0 for r in simple)} separate case means than compact summaries. A richer artifact is not automatically a better byte-efficiency tradeoff."
        )
    with (output / "experiment_summary.md").open("x", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    write_json(
        output / "analysis_manifest.json",
        {
            "recomputed_from_signed_artifacts": recompute,
            "trial_rows": len(rows),
            "method": "paired-trial Student-t; no incompatible-stratum pooling",
            "source_directory": str(directory),
        },
    )
    return stats, paired


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--tables-only",
        action="store_true",
        help="Use retained trial CSV; default independently replays all signed artifacts/verdicts",
    )
    args = parser.parse_args()
    analyze(args.directory, args.output, recompute=not args.tables_only)

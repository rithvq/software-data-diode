import copy
import json
from datetime import timedelta
from pathlib import Path

import pytest

from experiments.analysis.coverage_report import (
    number,
    recover_rows,
    statistics,
    summarize,
)
from experiments.analysis.coverage_udp_report import memory_bytes
from experiments.runners.bundle_coverage import bundle
from experiments.runners.coverage_common import (
    ARMS,
    EPOCH,
    VirtualClock,
    digest,
    fault_schedule,
    generate_trace,
    read_config,
    seed_for,
    write_csv,
    write_json,
    write_jsonl,
)
from experiments.runners.coverage_simulation import (
    capacity_integral,
    replay,
    simulate,
    transmission_finish,
)
from scripts.run_n10_udp import baseline_containers
from shared.coverage.contracts import load_contract
from shared.models import EdgeTelemetryMessage

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "experiments/workloads/coverage_workloads.json"
CONTRACT = load_contract(ROOT / "config/rule_coverage.json")


def tiny_trace():
    rows = []
    for window in range(2):
        for device in range(1, 6):
            at = 1 + 10 * window + device / 10
            kind = ("environmental", "system", "network", "security", "industrial")[
                device - 1
            ]
            message = EdgeTelemetryMessage(
                device_id=f"edge-device-{device:02d}",
                timestamp=EPOCH + timedelta(seconds=at),
                telemetry_type=kind,
                status="normal",
                temperature=25,
                humidity=50,
                cpu_usage=40,
                measurements={
                    "packets_per_second": 1000,
                    "failed_logins": 0,
                    "vibration_mm_s": 2,
                },
            )
            rows.append(
                {
                    "source_id": len(rows),
                    "at_us": round(at * 1e6),
                    "upstream_delivered": True,
                    "priority": "LOW",
                    "message": message.model_dump(mode="json"),
                }
            )
    return rows


@pytest.fixture(scope="module")
def tiny_results():
    doc = read_config(CONFIG)
    case = doc["cases"][1]
    faults = fault_schedule(doc, case, 99)
    return (
        doc,
        case,
        {
            arm: simulate(doc, case, arm, tiny_trace(), faults, CONTRACT, 99)
            for arm in (
                "fifo_gap",
                "heartbeat",
                "compact_summary",
                "fixed_summary",
                "rccd",
                "always_unknown",
            )
        },
    )


def test_matrix_has_strong_baselines_independent_ablations_and_five_pairs():
    doc = read_config(CONFIG)
    assert set(doc["configurations"]) == set(ARMS)
    assert doc["runs_per_configuration"] == 5
    assert {c["id"] for c in doc["cases"]} >= {
        "light",
        "moderate",
        "near_capacity",
        "overload",
        "burst",
        "critical_storm",
        "loss_10",
        "loss_25",
        "burst_loss",
        "evidence_loss",
        "reorder_delay",
        "capacity_step",
        "recovery",
    }


def test_original_trace_and_fault_field_are_seeded_and_paired_across_budgets():
    doc = read_config(CONFIG)
    moderate = next(c for c in doc["cases"] if c["id"] == "moderate")
    double = next(c for c in doc["cases"] if c["id"] == "moderate_double_budget")
    seed = seed_for(doc, moderate["trace_group"], 1)
    assert seed == seed_for(doc, double["trace_group"], 1)
    assert generate_trace(doc, moderate, seed) == generate_trace(doc, double, seed)
    assert fault_schedule(doc, moderate, seed) == fault_schedule(doc, double, seed)
    assert digest(generate_trace(doc, moderate, seed)) != digest(
        generate_trace(doc, moderate, seed + 1)
    )


@pytest.mark.parametrize(
    "mutation",
    [
        {"runs_per_configuration": 4},
        {"duration_seconds": 11},
        {"configurations": ["rccd", "rccd"]},
        {"seed": True},
        {"reference_bytes_per_second": 0},
        {"evidence_share_percent": 10},
    ],
)
def test_invalid_or_underfunded_matrix_fails_before_running(tmp_path, mutation):
    doc = json.loads(CONFIG.read_text())
    doc.update(mutation)
    path = tmp_path / "invalid.json"
    write_json(path, doc)
    with pytest.raises(ValueError):
        read_config(path)


def test_artifact_outputs_never_overwrite_and_clock_cannot_regress(tmp_path):
    for name, writer in (("value.json", write_json), ("rows.jsonl.gz", write_jsonl)):
        path = tmp_path / name
        value = {"retained": True} if name.endswith(".json") else [{"retained": True}]
        writer(path, value)
        first = path.read_bytes()
        with pytest.raises(FileExistsError):
            writer(path, value)
        assert path.read_bytes() == first
    clock = VirtualClock()
    clock.move(10)
    with pytest.raises(ValueError):
        clock.move(9)


def test_fifo_and_signed_heartbeat_can_prove_complete_negative_windows(tiny_results):
    doc, _, results = tiny_results
    for arm in ("fifo_gap", "heartbeat"):
        metrics, verdicts = replay(results[arm], doc, CONTRACT)
        assert metrics["decision_yield"] == 1
        assert metrics["raw_detail_availability"] == 1
        assert {v["truth"] for v in verdicts} == {"FALSE"}
        assert metrics["raw_reduced_originals"] == 0
    assert (
        results["fifo_gap"]["static"]["wire_bytes"]
        == results["heartbeat"]["static"]["wire_bytes"]
    )


def test_funded_fixed_summaries_are_not_weakened_against_rccd(tiny_results):
    doc, _, results = tiny_results
    for arm in ("fixed_summary", "rccd"):
        metrics, _ = replay(results[arm], doc, CONTRACT)
        assert metrics["decision_yield"] == 1
        assert metrics["wrong_definite"] == 0
        assert metrics["repeat_bytes"] > 0
        assert metrics["incident_recall"] is None


def test_removing_support_yields_unknown_not_an_invented_negative(tiny_results):
    doc, _, results = tiny_results
    missing = copy.deepcopy(results["rccd"])
    for tx in missing["transmissions"]:
        tx["dropped"] = True
    metrics, verdicts = replay(missing, doc, CONTRACT)
    assert metrics["unknown_rate"] == 1
    assert metrics["wrong_definite"] == 0
    assert {v["truth"] for v in verdicts} == {"UNKNOWN"}
    assert metrics["unknown_duration_seconds"] == doc["deadline_seconds"]


def test_every_transmitted_signature_part_and_repeat_is_charged(tiny_results):
    import base64

    doc, case, results = tiny_results
    result = results["rccd"]
    artifacts = {a["artifact_id"]: a for a in result["artifacts"]}
    charged = 0
    for tx in result["transmissions"]:
        frame = base64.b64decode(artifacts[tx["artifact_id"]]["frames"][tx["part"]])
        assert len(frame) <= 1200
        assert tx["wire_bytes"] == len(frame) + 28
        charged += tx["wire_bytes"]
        assert charged <= capacity_integral(tx["finish_seconds"], case, doc) + 1e-6
    assert charged == result["static"]["wire_bytes"]
    step = {"budget": 1000, "capacity_multiplier": 0.5}
    assert transmission_finish(9, 2000, step, doc) == 12
    assert capacity_integral(12, step, doc) == 11000


def test_unknown_control_has_no_undefined_efficiency_or_latency_imputation(
    tiny_results,
):
    doc, _, results = tiny_results
    metrics, _ = replay(results["always_unknown"], doc, CONTRACT)
    assert metrics["decision_yield"] == 0 and metrics["unknown_rate"] == 1
    assert metrics["decisions_per_kib"] is None
    assert metrics["critical_latency_p95_seconds"] is None
    assert summarize([])["n"] == 0
    with pytest.raises(ValueError):
        number("nan")


def paired_rows():
    return [
        {
            "case": "demo",
            "arm": arm,
            "trial": trial,
            "seed": trial,
            "trace_hash": "original",
            "fault_hash": "fault",
            "accepted_trace_hash": "accepted",
            "decision_yield": trial / 10 + (0.2 if arm == "rccd" else 0),
        }
        for trial in range(1, 6)
        for arm in ("rccd", "fixed_summary")
    ]


def test_paired_intervals_use_trials_and_explicit_missing_samples():
    doc = {
        "cases": [{"id": "demo"}],
        "configurations": ["rccd", "fixed_summary"],
        "runs_per_configuration": 5,
    }
    stats, paired = statistics(paired_rows(), doc)
    yield_diff = next(r for r in paired if r["metric"] == "decision_yield")
    assert yield_diff["n"] == 5 and yield_diff["mean"] == pytest.approx(0.2)
    assert yield_diff["ci95_low"] == pytest.approx(0.2)
    assert yield_diff["accepted_scope_equal_trials"] == 5
    assert next(r for r in stats if r["metric"] == "incident_recall")["n"] == 0
    sample = summarize([1, 2, 3, 4, 5])
    assert sample["stddev"] == pytest.approx(1.58113883)
    assert sample["ci95_high"] == pytest.approx(3 + 2.776 * (2.5 / 5) ** 0.5)


@pytest.mark.parametrize("kind", ["duplicate", "unpaired", "missing"])
def test_trial_analysis_rejects_pseudoreplication_and_unpaired_exposures(kind):
    rows = paired_rows()
    if kind == "duplicate":
        rows.append(rows[0])
    if kind == "unpaired":
        rows[0]["trace_hash"] = "different"
    if kind == "missing":
        rows.pop()
    doc = {
        "cases": [{"id": "demo"}],
        "configurations": ["rccd", "fixed_summary"],
        "runs_per_configuration": 5,
    }
    with pytest.raises(ValueError):
        statistics(rows, doc)


def test_no_experimental_policy_is_imported_by_live_services():
    for service in (
        "edge-gateway",
        "data-diode",
        "fog-receiver",
        "fog-analytics",
        "monitoring-api",
    ):
        for path in (ROOT / service / "app").glob("*.py"):
            assert "experiments.runners.coverage" not in path.read_text()
    client = (ROOT / "security-test-client/app/n10.py").read_text()
    assert "sendto(" in client and "recvfrom(" not in client and "httpx" not in client
    compose = (ROOT / "docker-compose.n10.yml").read_text()
    assert "network_mode: service:edge-gateway" in compose


def test_live_baseline_audit_excludes_only_named_task_model_containers():
    model = {
        "Name": "/software-data-diode-n10-model-20261014-r2",
        "HostConfig": {"NetworkMode": "none"},
    }
    research = {"Name": "/software-data-diode-coverage-fog-receiver-1"}
    baseline = {"Name": "/software-data-diode-postgres-1"}
    unrelated = {"Name": "/software-data-diode-n10-model-user"}
    assert baseline_containers([model, research, baseline, unrelated]) == [
        model,
        research,
        baseline,
        unrelated,
    ]
    assert baseline_containers(
        [model, research, baseline, unrelated],
        ["software-data-diode-n10-model-20261014-r2"],
    ) == [
        research,
        baseline,
        unrelated,
    ]
    with pytest.raises(ValueError):
        baseline_containers([model], ["software-data-diode-postgres-1"])
    with pytest.raises(ValueError):
        baseline_containers(
            [{"Name": model["Name"], "HostConfig": {"NetworkMode": "bridge"}}],
            [model["Name"].removeprefix("/")],
        )
    assert memory_bytes("48.78MiB / 768MiB") == pytest.approx(48.78 * 1024**2)
    assert memory_bytes("0B / 0B") == 0
    with pytest.raises(ValueError):
        memory_bytes("missing")


def test_compact_original_predicate_summary_is_strong_and_cheaper(tiny_results):
    doc, _, results = tiny_results
    metrics, _ = replay(results["compact_summary"], doc, CONTRACT)
    assert metrics["wrong_definite"] == 0 and metrics["decision_yield"] == 1
    assert metrics["evidence_bytes"] > 0
    assert (
        metrics["evidence_bytes"] < results["fixed_summary"]["static"]["evidence_bytes"]
    )


def test_no_recovery_records_admission_refusal_instead_of_bypassing_safety():
    doc = read_config(CONFIG)
    case = {**doc["cases"][1], "restart_seconds": 7}
    result = simulate(
        doc,
        case,
        "no_recovery",
        tiny_trace(),
        fault_schedule(doc, case, 111),
        CONTRACT,
        111,
    )
    metrics, _ = replay(result, doc, CONTRACT)
    assert metrics["refusal_reasons"]["UNSUPPORTED_RECOVERED_FACTS"] == 5
    assert metrics["accepted"] == 5 and metrics["wrong_definite"] == 0
    assert (
        result["events"][0]["admission_unavailable_reason"]
        == "UNSUPPORTED_RECOVERED_FACTS"
    )


def test_saved_artifact_replay_rejects_uncharged_frame_bytes(tmp_path, tiny_results):
    doc, case, results = tiny_results
    doc = copy.deepcopy(doc)
    doc.update(cases=[case], configurations=["rccd"], runs_per_configuration=1)
    result = copy.deepcopy(results["rccd"])
    metrics, _ = replay(result, doc, CONTRACT)
    pair = tmp_path / "pairs" / (case["id"] + "-01")
    pair.mkdir(parents=True)
    trace = tiny_trace()
    faults = fault_schedule(doc, case, 99)
    write_jsonl(pair / "original_trace.jsonl.gz", trace)
    write_jsonl(pair / "fault_schedule.jsonl.gz", faults)
    write_csv(
        pair / "raw_trials.csv",
        [
            {
                "arm": "rccd",
                "trace_hash": digest(trace),
                "fault_hash": digest(faults),
                **metrics,
            }
        ],
    )
    result["transmissions"][0]["wire_bytes"] += 1
    for key, suffix in (
        ("accepted", "accepted"),
        ("artifacts", "artifacts"),
        ("transmissions", "forward"),
    ):
        write_jsonl(pair / ("rccd-" + suffix + ".jsonl.gz"), result.pop(key))
    write_json(pair / "rccd-context.json", result)
    with pytest.raises(ValueError, match="uncharged"):
        recover_rows(tmp_path, doc, CONTRACT)


def test_bundle_refuses_incompatible_pair_parameters(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    doc = read_config(CONFIG)
    doc["deadline_seconds"] += 1
    write_json(source / "configuration.json", doc)
    write_json(
        source / "start-manifest.json",
        {"measurement_scope": "SIMULATION_NOT_DOCKER_UDP"},
    )
    with pytest.raises(ValueError, match="incompatible paired configurations"):
        bundle(CONFIG, [source], tmp_path / "new")
    assert not (tmp_path / "new").exists()


def test_bundle_never_overwrites_existing_evidence(tmp_path):
    output = tmp_path / "retained"
    output.mkdir()
    write_json(output / "sentinel.json", {"retained": True})
    before = (output / "sentinel.json").read_bytes()
    with pytest.raises(ValueError, match="new nonoverlapping"):
        bundle(CONFIG, [], output)
    assert (output / "sentinel.json").read_bytes() == before


def test_unsafe_mean_ablation_has_a_visible_counterexample_but_rccd_does_not():
    doc = read_config(CONFIG)
    case = doc["cases"][1]
    trace = tiny_trace()
    trace[1]["message"]["cpu_usage"] = 95
    extra = copy.deepcopy(trace[1])
    extra["at_us"] = 1800000
    extra["source_id"] = 10
    extra["message"]["timestamp"] = (EPOCH + timedelta(seconds=1.8)).isoformat()
    extra["message"]["cpu_usage"] = 0
    trace.append(extra)
    trace.sort(key=lambda r: r["at_us"])
    faults = fault_schedule(doc, case, 101)
    for arm in ("no_semantics", "rccd"):
        result = simulate(doc, case, arm, trace, faults, CONTRACT, 101)
        for tx in result["transmissions"]:
            if tx["kind"] == "RAW":
                tx["dropped"] = True
        metrics, _ = replay(result, doc, CONTRACT)
        assert (
            metrics["false_false"] >= 1
            if arm == "no_semantics"
            else metrics["wrong_definite"] == 0
        )

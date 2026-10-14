"""Bounded actual Docker/UDP artifact replay, separate from model statistics."""

import argparse
import base64
import hashlib
import json
import platform
import re
import secrets
import shutil
import sys
import threading
import time
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from experiments.analysis.information_report import summary
from experiments.runners.benchmark import percentile, software_version
from experiments.runners.coverage_common import (
    normalize_original,
    read_jsonl,
    write_csv,
    write_json,
)
from experiments.runners.coverage_receiver import Observer
from scripts.run_n9_validation import (
    Campaign,
    allocate_test_subnets,
    baseline_identity,
    cached_test_images,
    protected_files,
)
from shared.coverage.models import RuleContract
from shared.coverage.oracle import trace_oracle
from shared.coverage.transport import ResearchFramer, TrustProfile

SNAPSHOT = """
import os,json,base64,psycopg
from psycopg.rows import dict_row
with psycopg.connect(os.environ['DATABASE_URL'],connect_timeout=3,row_factory=dict_row) as db:
 db.execute('SET statement_timeout=5000')
 capsules=list(db.execute("SELECT artifact_digest,received_at_us,body,verification,encode(encoded,'base64') AS encoded FROM coverage_capsules ORDER BY received_at_us LIMIT 1000"))
 parts=list(db.execute("SELECT artifact_digest,part_index,encode(encoded,'base64') AS encoded FROM coverage_parts ORDER BY artifact_digest,part_index LIMIT 10000"))
 raw=list(db.execute("SELECT message_id,device_id,received_at,payload,payload_hash,priority FROM accepted_telemetry ORDER BY received_at LIMIT 1000"))
 print(json.dumps({'capsules':capsules,'parts':parts,'raw':raw},default=str))
"""


def actual_metrics(folder, document, *, write_verdicts=True):
    sender = folder / "sender"
    context = json.loads((sender / "context.json").read_text())
    meta = json.loads((sender / "replay_metadata.json").read_text())
    doc = json.loads((sender / "configuration.json").read_text())
    contract = RuleContract.model_validate(
        json.loads((sender / "contract.json").read_text())
    )
    accepted = read_jsonl(sender / "accepted.jsonl.gz")
    artifacts = read_jsonl(sender / "artifacts.jsonl.gz")
    epoch = datetime.fromisoformat(context["epoch_utc"]).timestamp()
    profile = TrustProfile.model_validate(context["profile"])
    framer = ResearchFramer(
        profile,
        Ed25519PublicKey.from_public_bytes(base64.b64decode(context["public_key"])),
        contract,
    )
    observer = Observer(framer, meta["arm"])
    observer.base_us = round(epoch * 1e6)
    packets = []
    raw_by_id = {}
    for artifact in artifacts:
        if artifact["kind"] == "RAW":
            frames = [base64.b64decode(f) for f in artifact["frames"]]
            raw_by_id[framer.decode_binary(frames).identity] = frames
    for row in document["raw"]:
        if row["message_id"] in raw_by_id:
            at = datetime.fromisoformat(row["received_at"]).timestamp() - epoch
            packets.append((at, raw_by_id[row["message_id"]]))
    parts = {}
    for row in document["parts"]:
        parts.setdefault(row["artifact_digest"], []).append(
            base64.b64decode(row["encoded"])
        )
    for row in document["capsules"]:
        packets.append(
            (row["received_at_us"] / 1e6 - epoch, parts[row["artifact_digest"]])
        )
    opportunities = []
    pending = sorted(packets, key=lambda p: p[0])
    cursor = 0
    originals = [normalize_original(contract, r) for r in accepted]
    for w in range(doc["duration_seconds"] // 10):
        deadline = (w + 1) * 10 + doc["deadline_seconds"]
        while cursor < len(pending) and pending[cursor][0] <= deadline:
            at, frames = pending[cursor]
            for frame in frames:
                observer.receive(frame, at)
            cursor += 1
        index = round(epoch) // 10 + w
        answers = observer.verdicts(index)
        for rule in contract.rules:
            truth = answers[rule.rule_id]
            oracle = trace_oracle(
                contract,
                rule.rule_id,
                ledger_epoch=profile.ledger_epoch,
                window_index=index,
                observations=originals,
            ).value
            opportunities.append(
                {
                    "window_index": index,
                    "rule_id": rule.rule_id,
                    "truth": truth,
                    "oracle": oracle,
                    "deadline_utc": epoch + deadline,
                    "correct_definite": truth != "UNKNOWN" and truth == oracle,
                }
            )
    if write_verdicts:
        write_csv(folder / "actual_verdicts.csv", opportunities)
    n = len(opportunities)
    wrong = sum(
        v["truth"] != "UNKNOWN" and v["truth"] != v["oracle"] for v in opportunities
    )
    if wrong:
        raise AssertionError("wrong actual scoped definite")
    critical = []
    raw_keys = set()
    for row in document["raw"]:
        attrs = row["payload"]["attributes"]
        if (
            attrs.get("_n10_epoch") != profile.ledger_epoch
            or row["payload"].get("aggregation") is not None
        ):
            continue
        raw_keys.add((row["device_id"], attrs["_n10_seq"]))
        if row["priority"] == "CRITICAL":
            critical.append(
                datetime.fromisoformat(row["received_at"]).timestamp()
                - attrs["_n10_ingress_us"] / 1e6
            )
    attempts = read_jsonl(sender / "actual_attempts.jsonl.gz")
    return {
        "measurement_scope": "ACTUAL_DOCKER_UDP_ARTIFACT_REPLAY",
        "case": "near_capacity",
        "arm": meta["arm"],
        "trial": meta["trial"],
        "seed": meta["seed"],
        "paired_relative_trace_hash": meta["paired_relative_trace_hash"],
        "accepted": len(accepted),
        "opportunities": n,
        "decision_yield": sum(v["correct_definite"] for v in opportunities) / n,
        "unknown_rate": sum(v["truth"] == "UNKNOWN" for v in opportunities) / n,
        "wrong_definite": wrong,
        "raw_detail_availability": len(raw_keys) / len(accepted) if accepted else None,
        "critical_latency_p95_seconds": percentile(critical, 95) if critical else None,
        "critical_samples": len(critical),
        "attempted_udp_bytes": sum(a["udp_bytes"] for a in attempts),
        "attempted_model_wire_bytes": sum(a["udp_bytes"] + 28 for a in attempts),
        "send_errors": meta["local_send_errors"],
        "maximum_send_schedule_slip_seconds": max(
            (a["attempt_utc"] - a["planned_utc"] for a in attempts), default=None
        ),
    }


def baseline_containers(containers, model_names=()):
    """Preserve all pre-existing state except explicitly declared isolated models."""
    if any(
        not re.fullmatch(r"software-data-diode-n10-model-[a-z0-9-]{1,64}", name)
        for name in model_names
    ):
        raise ValueError("only explicitly named N10 model containers may be excluded")
    excluded = {"/" + name for name in model_names}
    for container in containers:
        if (
            container["Name"] in excluded
            and container["HostConfig"].get("NetworkMode") != "none"
        ):
            raise ValueError("excluded models must have network mode none")
    return [c for c in containers if c["Name"] not in excluded]


def run(args):
    output = args.output.resolve()
    if output.exists():
        raise ValueError("new live output directory required")
    output.mkdir(parents=True)
    docker = (
        args.docker
        or shutil.which("docker")
        or str(
            Path.home()
            / "AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe"
        )
    )
    observer = Campaign(docker, secrets.token_hex(6), output)
    original = baseline_identity(
        baseline_containers(
            observer.inspect(observer.ids()), args.concurrent_model_container
        )
    )
    files = protected_files()
    write_json(
        output / "baseline-start.json",
        {
            "containers": original,
            "protected_files": files,
            "explicit_model_exclusions": args.concurrent_model_container,
        },
    )
    revision, fingerprint = software_version(
        ROOT, ROOT / "experiments/workloads/coverage_workloads.json"
    )
    sources = [
        Path(__file__),
        ROOT / "scripts/run_n9_validation.py",
        ROOT / "security-test-client/app/n10.py",
        ROOT / "docker-compose.n10.yml",
        ROOT / "docker-compose.n9.yml",
        ROOT / "constraints.txt",
        *sorted((ROOT / "shared").rglob("*.py")),
        *sorted((ROOT / "config").glob("*.json")),
        *sorted((ROOT / "experiments/runners").glob("coverage_*.py")),
    ]
    source_hashes = {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sources
    }
    write_json(
        output / "start-manifest.json",
        {
            "measurement_scope": "ACTUAL_DOCKER_UDP_ARTIFACT_REPLAY_NOT_ONLINE_POLICY",
            "software_version": revision,
            "configuration_fingerprint": fingerprint,
            "source_sha256": source_hashes,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "host_python": platform.python_version(),
            "host_dependencies": {
                name: version(name)
                for name in ("pydantic", "cryptography", "matplotlib")
            },
            "container_versions": "actual immutable image IDs retained in each cached-images.yml; host versions are not container versions",
        },
    )
    rows = []
    failures = []
    started = datetime.now(timezone.utc).isoformat()
    trials = 1 if args.smoke else 5
    for trial in range(1, trials + 1):
        for arm in (
            ("rccd", "fixed_summary") if trial % 2 else ("fixed_summary", "rccd")
        ):
            folder = output / (arm + f"-{trial:02d}")
            folder.mkdir()
            campaign = Campaign(docker, secrets.token_hex(6), folder)
            campaign.env.update(N10_ARM=arm, N10_TRIAL=str(trial))
            campaign.command += ["-f", "docker-compose.n10.yml"]
            created = False
            stopped = threading.Event()
            sampler = None
            try:
                if args.allocate_test_subnets:
                    allocate_test_subnets(campaign)
                if args.cached_images_from:
                    cached_test_images(campaign, args.cached_images_from)
                else:
                    campaign.call(["build"], timeout=600, log="build.log")
                created = True
                campaign.call(
                    [
                        "up",
                        "-d",
                        "--no-build",
                        "--pull",
                        "never",
                        "validation-init",
                        "postgres",
                        "database-migrator",
                        "edge-gateway",
                        "data-diode",
                        "fog-receiver",
                        "event-processor",
                        "fog-analytics",
                        "alert-engine",
                    ],
                    timeout=150,
                    log="startup.log",
                )
                campaign.ready(
                    [
                        "postgres",
                        "data-diode",
                        "fog-receiver",
                        "event-processor",
                        "fog-analytics",
                        "alert-engine",
                    ]
                )
                containers = campaign.guard()
                diode = next(
                    c
                    for c in containers
                    if c["Config"]["Labels"]["com.docker.compose.service"]
                    == "data-diode"
                )
                address = diode["NetworkSettings"]["Networks"][
                    campaign.project + "_diode-network"
                ]["IPAddress"]
                write_json(
                    folder / "n10-target.json",
                    {
                        "project": campaign.project,
                        "run_id": campaign.run,
                        "targets": {
                            "data-diode": {"address": address, "ports": [9001]}
                        },
                    },
                )
                write_json(
                    folder / "memberships.json",
                    {c["Name"]: c["NetworkSettings"]["Networks"] for c in containers},
                )

                def sample(folder=folder, stopped=stopped, campaign=campaign):
                    with (folder / "resources.jsonl").open(
                        "x", encoding="utf-8"
                    ) as handle:
                        for _ in range(40):
                            if stopped.wait(2):
                                break
                            ids = campaign.ids(own=True)
                            sampled = campaign.call(
                                [
                                    "stats",
                                    "--no-stream",
                                    "--format",
                                    "{{json .}}",
                                    *ids,
                                ],
                                compose=False,
                                check=False,
                                timeout=15,
                            )
                            handle.write(
                                json.dumps(
                                    {
                                        "timestamp": time.time(),
                                        "returncode": sampled.returncode,
                                        "samples": [
                                            json.loads(line)
                                            for line in sampled.stdout.splitlines()
                                        ]
                                        if sampled.returncode == 0
                                        else [],
                                        "error": sampled.stderr
                                        if sampled.returncode
                                        else None,
                                    }
                                )
                                + "\n"
                            )
                            handle.flush()

                sampler = threading.Thread(target=sample, daemon=True)
                sampler.start()
                campaign.call(
                    [
                        "run",
                        "--rm",
                        "--no-deps",
                        "security-test-client",
                        "python",
                        "-m",
                        "app.n10",
                    ],
                    timeout=120,
                    log="sender.log",
                )
                time.sleep(8)
                snapshot = campaign.local_json("fog-receiver", SNAPSHOT)
                write_json(folder / "postgres_receipts.json", snapshot)
                write_json(folder / "fog_status.json", campaign.runtime("fog-receiver"))
                write_json(folder / "diode_status.json", campaign.runtime("data-diode"))
                rows.append(actual_metrics(folder, snapshot))
                print(f"Actual UDP {arm} paired trial {trial}/5 complete", flush=True)
            except Exception as exc:  # noqa: BLE001 - retain failed trial evidence and always clean this isolated project
                failures.append({"arm": arm, "trial": trial, "reason": str(exc)})
                campaign.call(["logs", "--tail", "60"], log="failure.log", check=False)
                break
            finally:
                stopped.set()
                if sampler:
                    sampler.join(20)
                if created:
                    campaign.guard()
                    campaign.call(
                        ["down", "--volumes", "--remove-orphans", "--timeout", "15"],
                        timeout=120,
                        log="cleanup.log",
                    )
        if failures:
            break
    preserved = (
        original == baseline_identity(observer.inspect(list(original)))
        and files == protected_files()
    )
    source_unchanged = all(
        hashlib.sha256(p.read_bytes()).hexdigest()
        == source_hashes[str(p.relative_to(ROOT))]
        for p in sources
    )
    write_json(
        output / "manifest.json",
        {
            "measurement_scope": "ACTUAL_DOCKER_UDP_ARTIFACT_REPLAY_NOT_ONLINE_POLICY",
            "started_at": started,
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "planned_pairs": trials,
            "smoke_only_not_comparative": args.smoke,
            "completed_trials": len(rows),
            "failures": failures,
            "baseline_preserved": preserved,
            "baseline_containers": len(original),
            "case": "near_capacity",
            "receiver_feedback": False,
            "software_version": revision,
            "configuration_fingerprint": fingerprint,
            "source_sha256": source_hashes,
            "source_unchanged_during_run": source_unchanged,
            "limits": "Gateway role is an idle namespace; replayed artifacts come from actual N4 model transactions. Sender policy CPU is simulation; diode/Fog CPU/RSS are separately observed. No native online admission throughput claim.",
        },
    )
    if rows:
        write_csv(output / "raw_trials.csv", rows)
    if failures or not preserved or not source_unchanged:
        raise RuntimeError(
            "live matrix incomplete or preservation failed; inspect manifest"
        )
    if args.smoke:
        return
    groups = {
        arm: [r for r in rows if r["arm"] == arm] for arm in ("rccd", "fixed_summary")
    }
    report = [
        "# N10 Actual Docker/UDP Artifact Replay",
        "",
        "Separate five paired trials per arm; not online policy performance.",
        "Gateway sender cannot resolve/query Fog; all actual frames pass the passive diode. Local send success is not receipt.",
        "",
        "| Arm | Metric | n | Mean | Median | SD | 95% CI |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for arm, trials in groups.items():
        for metric in (
            "decision_yield",
            "unknown_rate",
            "raw_detail_availability",
            "critical_latency_p95_seconds",
            "attempted_model_wire_bytes",
        ):
            values = [r[metric] for r in trials if r[metric] is not None]
            if values:
                stat = summary(values)
                report.append(
                    f"| {arm} | {metric} | {stat['n']} | {stat['mean']:.5f} | {stat['median']:.5f} | {stat['stddev']} | [{stat['ci95_low']}, {stat['ci95_high']}] |"
                )
    difference = []
    for trial in range(1, 6):
        a = next(r for r in rows if r["arm"] == "rccd" and r["trial"] == trial)
        b = next(r for r in rows if r["arm"] == "fixed_summary" and r["trial"] == trial)
        if (a["seed"], a["paired_relative_trace_hash"]) != (
            b["seed"],
            b["paired_relative_trace_hash"],
        ):
            raise ValueError("unpaired actual replay")
        difference.append(a["decision_yield"] - b["decision_yield"])
    write_json(output / "paired_yield_difference.json", summary(difference))
    report += [
        "",
        "RCCD minus fixed-summary yield paired difference: "
        + json.dumps(summary(difference)),
        "",
        "CPU/memory raw Docker time series and real PostgreSQL receipt timestamps are retained per trial. UDP/IP wire overhead is modeled, not a NIC packet-capture measurement.",
        "No superiority or patentability inference is automatic. Actual absolute UTC origins differ; aligned relative original traces are paired explicitly.",
    ]
    with (output / "experiment_summary.md").open("x", encoding="utf-8") as handle:
        handle.write("\n".join(report) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--docker")
    parser.add_argument("--cached-images-from")
    parser.add_argument("--allocate-test-subnets", action="store_true")
    parser.add_argument(
        "--concurrent-model-container",
        action="append",
        default=[],
        help="Explicit isolated network-none N10 model to exclude from baseline preservation audit",
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="One pair to verify orchestration only; never publish comparative statistics",
    )
    run(parser.parse_args())

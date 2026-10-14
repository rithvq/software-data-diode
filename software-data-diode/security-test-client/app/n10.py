"""Actual local UDP replay of precomputed N10 artifacts; never receives feedback."""

import base64
import ipaddress
import json
import math
import os
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from experiments.runners.coverage_common import (
    digest,
    fault_schedule,
    generate_trace,
    read_config,
    seed_for,
    write_json,
    write_jsonl,
)
from experiments.runners.coverage_simulation import replay, simulate
from shared.coverage.contracts import load_contract
from shared.security import load_private_key
from shared.security.n9_support import test_project


def main():
    root = Path("/reports")
    arm = os.environ["N10_ARM"]
    if arm not in {"rccd", "fixed_summary"}:
        raise ValueError("live matrix is two safe summary arms only")
    trial = int(os.environ["N10_TRIAL"])
    if trial not in range(1, 6):
        raise ValueError("five bounded live paired trials")
    target = json.loads((root / "n10-target.json").read_bytes())
    project = test_project(target["project"], target["run_id"])
    if project != os.environ["N9_PROJECT_NAME"] or set(target["targets"]) != {
        "data-diode"
    }:
        raise ValueError("foreign replay project/target")
    entry = target["targets"]["data-diode"]
    address = ipaddress.ip_address(entry["address"])
    if (
        not address.is_private
        or address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or entry["ports"] != [9001]
    ):
        raise ValueError("only the pinned disposable diode UDP port is allowed")
    if socket.gethostbyname("data-diode") != entry["address"]:
        raise ValueError("diode DNS rebinding")
    doc = read_config("/app/experiments/workloads/coverage_workloads.json")
    case = next(c for c in doc["cases"] if c["id"] == "near_capacity")
    seed = seed_for(doc, case["trace_group"], trial)
    epoch = datetime.fromtimestamp(
        math.ceil(time.time() / 10) * 10 + 20, tz=timezone.utc
    )
    profile = json.loads(Path("/run/coverage/profile.json").read_bytes())
    key = load_private_key("/state/n9-key/private.pem")
    contract = load_contract("/app/config/rule_coverage.json")
    trace = generate_trace(doc, case, seed, epoch=epoch)
    result = simulate(
        doc,
        case,
        arm,
        trace,
        fault_schedule(doc, case, seed),
        contract,
        seed,
        epoch=epoch,
        key=key,
        ledger_epoch=profile["ledger_epoch"],
    )
    modeled, _ = replay(result, doc, contract)
    folder = root / "sender"
    folder.mkdir()
    write_json(folder / "configuration.json", doc)
    write_json(folder / "contract.json", contract.model_dump(mode="json"))
    write_jsonl(folder / "original_trace.jsonl.gz", trace)
    for name in ("accepted", "artifacts", "transmissions", "queue"):
        write_jsonl(folder / (name + ".jsonl.gz"), result[name])
    context = {
        k: v
        for k, v in result.items()
        if k not in {"accepted", "artifacts", "transmissions", "queue"}
    }
    write_json(folder / "context.json", context)
    write_json(folder / "modeled_metrics.json", modeled)
    if time.time() >= epoch.timestamp():
        raise RuntimeError(
            "model preparation missed future aligned replay start; refusing stale trial"
        )
    frames = {a["artifact_id"]: a["frames"] for a in result["artifacts"]}
    attempts = []
    # Socket exposes only sends; local send completion never certifies receipt.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for tx in result["transmissions"]:
            due = epoch.timestamp() + tx["finish_seconds"]
            time.sleep(max(0, due - time.time()))
            if socket.gethostbyname("data-diode") != entry["address"]:
                raise ValueError("diode address changed during trial")
            frame = base64.b64decode(frames[tx["artifact_id"]][tx["part"]])
            if len(frame) > 1200:
                raise ValueError("datagram bound")
            at = time.time()
            try:
                ok = sender.sendto(frame, (entry["address"], 9001)) == len(frame)
            except OSError:
                ok = False
            attempts.append(
                {
                    "artifact_id": tx["artifact_id"],
                    "part": tx["part"],
                    "kind": tx["kind"],
                    "planned_utc": due,
                    "attempt_utc": at,
                    "local_send_succeeded": ok,
                    "udp_bytes": len(frame),
                }
            )
    write_jsonl(folder / "actual_attempts.jsonl.gz", attempts)
    relative = [
        {**r, "message": {k: v for k, v in r["message"].items() if k != "timestamp"}}
        for r in trace
    ]
    write_json(
        folder / "replay_metadata.json",
        {
            "measurement_scope": "ACTUAL_DOCKER_UDP_ARTIFACT_REPLAY_NOT_ONLINE_POLICY",
            "project": project,
            "arm": arm,
            "trial": trial,
            "seed": seed,
            "epoch_utc": epoch.isoformat(),
            "target": entry,
            "paired_relative_trace_hash": digest(relative),
            "receiver_feedback": False,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "attempts": len(attempts),
            "local_send_errors": sum(not r["local_send_succeeded"] for r in attempts),
        },
    )
    print("N10 actual UDP replay finished: " + arm + " trial " + str(trial), flush=True)


if __name__ == "__main__":
    main()

"""Bounded forward-only discrete events using actual N4 admission and N5 encoders."""

import base64
import hashlib
import json
import math
import tempfile
import time
import tracemalloc
from collections import Counter
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
from uuid import NAMESPACE_URL, UUID, uuid5

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from experiments.runners.benchmark import percentile
from shared.coverage.budget import AdmissionConfig, unpack_frames
from shared.coverage.ledger import LedgerRefused, ObservationLedger
from shared.coverage.oracle import trace_oracle
from shared.coverage.transport import ResearchFramer, TrustProfile
from shared.coverage.windows import utc_microseconds
from shared.models import EdgeTelemetryMessage, PriorityLevel
from shared.traffic.information import InformationPolicyConfig

from .coverage_common import (
    EPOCH,
    VirtualClock,
    digest,
    normalize_original,
    process_rss,
)
from .coverage_policy import HarnessAdmission
from .coverage_receiver import Observer


def transmission_finish(start, cost, case, doc):
    boundary = doc["duration_seconds"] * 0.5
    capacity = case["budget"]
    multiplier = case.get("capacity_multiplier", 1)
    if start >= boundary:
        return start + cost / (capacity * multiplier)
    available = (boundary - start) * capacity
    return (
        start + cost / capacity
        if cost <= available
        else boundary + (cost - available) / (capacity * multiplier)
    )


def capacity_integral(until, case, doc):
    boundary = doc["duration_seconds"] * 0.5
    return case["budget"] * (
        min(until, boundary)
        + max(0, until - boundary) * case.get("capacity_multiplier", 1)
    )


def simulate(
    doc,
    case,
    arm,
    trace,
    faults,
    contract,
    seed,
    *,
    epoch=EPOCH,
    key=None,
    ledger_epoch=None,
):
    key = key or Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(f"N10 INSECURE SYNTHETIC TEST KEY {seed}".encode()).digest()
    )
    start, cpu = time.perf_counter(), time.process_time()
    if doc.get("memory_tracing"):
        tracemalloc.start()
    rss = [process_rss()]
    clock = VirtualClock(epoch)
    admission = AdmissionConfig(
        link_bytes_per_second=case["budget"],
        evidence_repeats=1 if arm == "no_repeats" else 2,
        evidence_share_percent=doc.get("evidence_share_percent", 50),
        protected_share_percent=doc.get("protected_share_percent", 25),
    )
    policy = InformationPolicyConfig(
        max_queue_size=64,
        max_streams=64,
        strategy="fifo" if arm in {"fifo_gap", "heartbeat"} else "utility",
        reduction_enabled=arm not in {"fifo_gap", "heartbeat"},
    )
    nonce = [0]

    def identifier():
        nonce[0] += 1
        return uuid5(NAMESPACE_URL, f"N10:{seed}:{arm}:{nonce[0]}")

    store_id = uuid5(NAMESPACE_URL, f"N10:store:{seed}:{arm}")
    active_epoch = (
        UUID(ledger_epoch)
        if ledger_epoch
        else uuid5(NAMESPACE_URL, f"N10:epoch:{seed}")
    )
    artifacts, transmissions, queues, events = [], [], [], []
    artifacts_by_work = {}
    accepted = []
    refusals = Counter()
    counters = Counter()
    horizon = doc["duration_seconds"] + doc["deadline_seconds"]
    next_link, next_poll, next_state = 0.0, 0.0, 0.0
    arrival = 0
    restarted = False
    recovery_refusal = None
    unavailable_state = None
    with (
        tempfile.TemporaryDirectory(prefix="n10-ledger-") as folder,
        patch("shared.coverage.ledger.uuid4", side_effect=[store_id, active_epoch]),
        patch("shared.coverage.admission.uuid4", side_effect=identifier),
    ):
        path = Path(folder) / "observations.sqlite3"
        ledger = ObservationLedger(path, contract, create=True, clock=clock)
        controller = HarnessAdmission(ledger, key, arm, admission, policy)
        controller.install_ablation()
        encoder = controller.encoder
        profile = encoder.profile.model_dump(mode="json")
        try:
            while True:
                arrival_at = (
                    trace[arrival]["at_us"] / 1e6 if arrival < len(trace) else math.inf
                )
                restart_at = (
                    case.get("restart_seconds", math.inf) if not restarted else math.inf
                )
                now = min(arrival_at, next_poll, next_state, restart_at, horizon)
                if now >= horizon:
                    break
                clock.move(now)
                if now == restart_at:
                    if arm == "no_recovery":
                        controller.volatile_restart()
                        unavailable_state = controller.status()
                    ledger.close()
                    ledger = ObservationLedger(path, contract, clock=clock)
                    try:
                        controller = HarnessAdmission(
                            ledger, key, arm, admission, policy
                        )
                        controller.install_ablation()
                        controller.retire_uncertain_lease()
                    except LedgerRefused as exc:
                        if (
                            arm != "no_recovery"
                            or exc.reason != "UNSUPPORTED_RECOVERED_FACTS"
                        ):
                            raise
                        recovery_refusal = exc.reason
                        next_poll = next_state = horizon
                    restarted = True
                    events.append(
                        {
                            "kind": "restart",
                            "at_seconds": now,
                            "durable": arm != "no_recovery",
                            "admission_unavailable_reason": recovery_refusal,
                        }
                    )
                if now == next_state:
                    controller.common_state()
                    next_state += 10
                if now == arrival_at:
                    source = trace[arrival]
                    if source["upstream_delivered"]:
                        try:
                            if recovery_refusal:
                                raise LedgerRefused(recovery_refusal)
                            receipt = controller.admit(
                                EdgeTelemetryMessage.model_validate(source["message"]),
                                expected_epoch=ledger.epoch,
                                retry_sequence=source["source_id"] + 1,
                                priority=PriorityLevel(source["priority"]),
                            )
                            accepted.append(
                                {
                                    "source_id": source["source_id"],
                                    "device_id": receipt.device_id,
                                    "ledger_epoch": ledger.epoch,
                                    "ingress_sequence": receipt.ingress_sequence,
                                    "ingress_utc_us": utc_microseconds(clock.utc_now()),
                                    "message": source["message"],
                                    "priority": source["priority"],
                                }
                            )
                            if arm == "always_unknown":
                                with ledger._transaction():
                                    ledger.db.execute("DELETE FROM n4_outbox")
                                    ledger.db.execute(
                                        "UPDATE observations SET disposition='DROPPED_RAW'"
                                    )
                                    controller.engine.queue.clear()
                                    from shared.coverage.policy_state import checkpoint

                                    controller._set_state(
                                        "engine", checkpoint(controller.engine)
                                    )
                            next_poll = min(next_poll, max(now, next_link))
                        except LedgerRefused as exc:
                            refusals[exc.reason] += 1
                    arrival += 1
                if now == next_poll:
                    if now >= next_link:
                        lease = (
                            controller.lease_frame()
                            if arm != "always_unknown"
                            else None
                        )
                        if lease:
                            row = ledger.db.execute(
                                "SELECT * FROM n4_outbox WHERE id=?", (lease.work_id,)
                            ).fetchone()
                            if lease.work_id not in artifacts_by_work:
                                pieces = unpack_frames(row["body"])
                                frames = (
                                    encoder.raw_frames(b"".join(pieces))
                                    if row["kind"] == "RAW"
                                    else pieces
                                )
                                artifact = {
                                    "artifact_id": len(artifacts),
                                    "kind": row["kind"],
                                    "frames": [
                                        base64.b64encode(f).decode() for f in frames
                                    ],
                                }
                                if (
                                    arm == "compact_summary"
                                    and row["kind"] == "STATE"
                                    and "n10_predicate_summary"
                                    in json.loads(
                                        encoder.decode_binary(frames).encoded
                                    )["metrics"]
                                ):
                                    artifact["kind"] = "EVIDENCE"
                                artifacts_by_work[lease.work_id] = artifact
                                artifacts.append(artifact)
                            artifact = artifacts_by_work[lease.work_id]
                            logical_kind = artifact["kind"]
                            count = len(artifact["frames"])
                            part = row["cursor"] % count
                            frame = base64.b64decode(artifact["frames"][part])
                            cost = len(frame) + 28
                            if cost != lease.modeled_wire_bytes:
                                raise AssertionError(
                                    "signed framing cost not matched to charged N4 bytes"
                                )
                            finished = transmission_finish(now, cost, case, doc)
                            if finished <= horizon:
                                slot = min(round(finished * 1000), len(faults) - 1)
                                fault = faults[slot]
                                drop = (
                                    (
                                        case["fault"] == "independent"
                                        and fault["uniform"] < case.get("loss", 0)
                                    )
                                    or (
                                        case["fault"] == "evidence_only"
                                        and logical_kind == "EVIDENCE"
                                        and fault["uniform"] < case.get("loss", 1)
                                    )
                                    or (
                                        case["fault"] == "burst_loss"
                                        and doc["duration_seconds"] * 0.5
                                        <= finished
                                        < doc["duration_seconds"] * 0.7
                                    )
                                )
                                delay = (
                                    case.get("max_delay_seconds", 0)
                                    * fault["delay_uniform"]
                                    if case["fault"] == "delay"
                                    else 0
                                )
                                transmissions.append(
                                    {
                                        "artifact_id": artifact["artifact_id"],
                                        "part": part,
                                        "start_seconds": now,
                                        "finish_seconds": finished,
                                        "arrival_seconds": finished + delay,
                                        "dropped": bool(drop),
                                        "fault_slot": slot,
                                        "kind": logical_kind,
                                        "udp_bytes": len(frame),
                                        "wire_bytes": cost,
                                        "repeat": row["cursor"] >= count,
                                    }
                                )
                                counters["wire_bytes"] += cost
                                counters[logical_kind.lower() + "_bytes"] += len(frame)
                                counters["repeat_bytes"] += (
                                    cost if row["cursor"] >= count else 0
                                )
                                counters["lost_frames"] += int(drop)
                                counters["framing_bytes"] += (
                                    128
                                    if frame.startswith((b"RCS1", b"RCR1"))
                                    else len(frame)
                                    - len(
                                        base64.b64decode(
                                            json.loads(frame)["body"]["chunk"]
                                        )
                                    )
                                )
                                if (
                                    counters["wire_bytes"]
                                    > capacity_integral(finished, case, doc) + 1e-6
                                ):
                                    raise AssertionError(
                                        "total forward budget exceeded"
                                    )
                            else:
                                counters["cancelled_charged_grants"] += 1
                            next_link = finished
                            controller.complete_local_attempt(
                                lease.lease_id, uncertain=finished > horizon
                            )
                        # Short virtual polling is bounded; no sleeping or receiver feedback.
                    if lease:
                        next_poll = next_link
                    else:
                        ready = controller._service().next_us / 1e6
                        has_work = ledger.db.execute(
                            "SELECT 1 FROM n4_outbox"
                        ).fetchone()
                        if not has_work:
                            next_arrival = (
                                trace[arrival]["at_us"] / 1e6
                                if arrival < len(trace)
                                else math.inf
                            )
                            next_poll = min(
                                next_arrival,
                                next_state,
                                (math.floor(now / 10) + 1) * 10,
                                horizon,
                            )
                        elif ready > now:
                            next_poll = ready + 1e-6
                        else:
                            next_poll = (math.floor(now / 10) + 1) * 10
                    state = controller.status()
                    queues.append(
                        {
                            "at_seconds": now,
                            "queue_items": state["outbox_items"],
                            "queue_bytes": state["outbox_bytes"],
                            "reserved_bytes": state["reserved_wire_bytes"],
                            "pending_obligations": state[
                                "pending_evidence_obligations"
                            ],
                        }
                    )
                    if len(queues) % 32 == 0:
                        rss.append(process_rss())
            clock.move(horizon)
            ledger.tick()
            final = unavailable_state if recovery_refusal else controller.status()
            storage = ledger.status()["database_bytes"]
            generated_bytes = sum(
                len(
                    json.dumps(
                        r["message"], sort_keys=True, separators=(",", ":")
                    ).encode()
                )
                for r in trace
            )
            static = {
                "arm": arm,
                "budget": case["budget"],
                "generated": len(trace),
                "upstream_lost": sum(not r["upstream_delivered"] for r in trace),
                "accepted": len(accepted),
                "admission_refused": sum(refusals.values()),
                "refusal_reasons": dict(refusals),
                "accepted_trace_hash": digest(
                    [
                        {k: v for k, v in r.items() if k != "ledger_epoch"}
                        for r in accepted
                    ]
                ),
                "generated_bytes": generated_bytes,
                "modeled_capacity_bytes": capacity_integral(horizon, case, doc),
                "storage_bytes": storage,
                "outbox_final_bytes": final["outbox_bytes"],
                "unsupported_scopes": final["unsupported_scopes"],
                "raw_dropped_originals": ledger.db.execute(
                    "SELECT COUNT(*) FROM observations WHERE disposition='DROPPED_RAW'"
                ).fetchone()[0],
                "raw_reduced_originals": ledger.db.execute(
                    "SELECT COUNT(*) FROM observations WHERE disposition='REDUCED_RAW'"
                ).fetchone()[0],
                "queue_max_items": max((q["queue_items"] for q in queues), default=0),
                "queue_max_bytes": max((q["queue_bytes"] for q in queues), default=0),
                "queue_average_items": sum(q["queue_items"] for q in queues)
                / len(queues)
                if queues
                else 0,
                "charged_local_bytes": final["modeled_scheduled_bytes"],
                **dict(counters),
            }
        finally:
            ledger.close()
    cpu_seconds = time.process_time() - cpu
    wall_seconds = time.perf_counter() - start
    memory = None
    if doc.get("memory_tracing"):
        _, memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    rss.append(process_rss())
    static.update(
        runner_cpu_seconds=cpu_seconds,
        runner_wall_seconds=wall_seconds,
        runner_cpu_percent=100 * cpu_seconds / wall_seconds if wall_seconds else None,
        runner_peak_python_bytes=memory,
        runner_sampled_rss_bytes=max((v for v in rss if v is not None), default=None),
    )
    for name in (
        "wire_bytes",
        "raw_bytes",
        "evidence_bytes",
        "state_bytes",
        "repeat_bytes",
        "framing_bytes",
        "lost_frames",
        "cancelled_charged_grants",
    ):
        static.setdefault(name, 0)
    return {
        "static": static,
        "accepted": accepted,
        "artifacts": artifacts,
        "transmissions": transmissions,
        "queue": queues,
        "events": events,
        "profile": profile,
        "public_key": base64.b64encode(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode(),
        "epoch_utc": epoch.isoformat(),
    }


def replay(result, doc, contract):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    profile = TrustProfile.model_validate(result["profile"])
    framer = ResearchFramer(
        profile,
        Ed25519PublicKey.from_public_bytes(base64.b64decode(result["public_key"])),
        contract,
    )
    observer = Observer(framer, result["static"]["arm"])
    epoch_us = utc_microseconds(datetime.fromisoformat(result["epoch_utc"]))
    observer.base_us = epoch_us
    indices = [epoch_us // 10000000 + i for i in range(doc["duration_seconds"] // 10)]
    originals = [normalize_original(contract, r) for r in result["accepted"]]
    oracle = {
        (idx, r.rule_id): trace_oracle(
            contract,
            r.rule_id,
            ledger_epoch=profile.ledger_epoch,
            window_index=idx,
            observations=originals,
        ).value
        for idx in indices
        for r in contract.rules
    }
    deadlines = {
        idx: 10 * (i + 1) + doc["deadline_seconds"] for i, idx in enumerate(indices)
    }
    truth = {(idx, r.rule_id): "UNKNOWN" for idx in indices for r in contract.rules}
    unknown_duration = {k: 0.0 for k in truth}
    previous = {idx: 10 * (i + 1) for i, idx in enumerate(indices)}
    first_definite = {}
    verdicts = []
    timeline = []
    for index, t in enumerate(result["transmissions"]):
        if not t["dropped"] and t["arrival_seconds"] <= max(deadlines.values()):
            timeline.append((t["arrival_seconds"], 1, index))
    timeline += [(at, 2, idx) for idx, at in deadlines.items()]
    timeline += [(e["at_seconds"], 0, e) for e in result["events"]]
    by_artifact = {a["artifact_id"]: a for a in result["artifacts"]}
    for at, kind, data in sorted(timeline, key=lambda x: (x[0], x[1])):
        for idx in indices:
            upper = min(at, deadlines[idx])
            if upper > previous[idx]:
                for rule in contract.rules:
                    k = (idx, rule.rule_id)
                    unknown_duration[k] += (
                        upper - previous[idx] if truth[k] == "UNKNOWN" else 0
                    )
                previous[idx] = upper
        if kind == 0:
            observer.now = at
            observer.restart(data["durable"])
        if kind == 1:
            t = result["transmissions"][data]
            observer.receive(
                base64.b64decode(by_artifact[t["artifact_id"]]["frames"][t["part"]]), at
            )
        for idx in indices:
            if at <= deadlines[idx]:
                now = observer.verdicts(idx)
                for rule, value in now.items():
                    truth[(idx, rule)] = value
                    if value != "UNKNOWN":
                        first_definite.setdefault((idx, rule), at)
        if kind == 2:
            idx = data
            for rule in contract.rules:
                k = (idx, rule.rule_id)
                verdicts.append(
                    {
                        "window_index": idx,
                        "rule_id": rule.rule_id,
                        "truth": truth[k],
                        "oracle": oracle[k],
                        "deadline_seconds": deadlines[idx],
                        "first_definite_seconds": first_definite.get(k),
                        "unknown_duration_seconds": unknown_duration[k],
                        "correct_definite": truth[k] != "UNKNOWN"
                        and truth[k] == oracle[k],
                    }
                )
    n = len(verdicts)
    hits = sum(v["correct_definite"] for v in verdicts)
    false_false = sum(v["truth"] == "FALSE" and v["oracle"] == "TRUE" for v in verdicts)
    false_true = sum(v["truth"] == "TRUE" and v["oracle"] == "FALSE" for v in verdicts)
    wrong = sum(v["truth"] != "UNKNOWN" and v["truth"] != v["oracle"] for v in verdicts)
    definite = [
        max(
            0,
            v["first_definite_seconds"]
            - (v["deadline_seconds"] - doc["deadline_seconds"]),
        )
        for v in verdicts
        if v["first_definite_seconds"] is not None
    ]
    positive = sum(v["oracle"] == "TRUE" for v in verdicts)
    recall = (
        sum(v["oracle"] == v["truth"] == "TRUE" for v in verdicts) / positive
        if positive
        else None
    )
    incidents = [
        v
        for v in verdicts
        if v["rule_id"] == "incident-correlation" and v["oracle"] == "TRUE"
    ]
    raw = [r for r in observer.raw_receipts if r["exact"]]
    accepted_keys = {
        (r["device_id"], r["ingress_sequence"]) for r in result["accepted"]
    }
    receipt_keys = {(r["device_id"], r["ingress_sequence"]) for r in raw}
    latencies = [r["at_seconds"] - (r["ingress_utc_us"] - epoch_us) / 1e6 for r in raw]
    critical = [
        r["at_seconds"] - (r["ingress_utc_us"] - epoch_us) / 1e6
        for r in raw
        if r["priority"] == "CRITICAL"
    ]
    queue_wait = []
    for artifact in result["artifacts"]:
        if artifact["kind"] != "RAW":
            continue
        decoded = framer.decode_binary(
            [base64.b64decode(f) for f in artifact["frames"]]
        )
        attrs = json.loads(decoded.encoded)["payload"]["attributes"]
        starts = [
            t["start_seconds"]
            for t in result["transmissions"]
            if t["artifact_id"] == artifact["artifact_id"]
        ]
        if starts:
            queue_wait.append(min(starts) - (attrs["_n10_ingress_us"] - epoch_us) / 1e6)
    static = result["static"]
    metrics = {
        **static,
        "opportunities": n,
        "correct_definite": hits,
        "decision_yield": hits / n if n else None,
        "false_false": false_false,
        "false_true": false_true,
        "wrong_definite": wrong,
        "unknown_rate": sum(v["truth"] == "UNKNOWN" for v in verdicts) / n
        if n
        else None,
        "unknown_duration_seconds": sum(unknown_duration.values()) / n if n else None,
        "decisions_per_kib": hits / (static["wire_bytes"] / 1024)
        if static["wire_bytes"]
        else None,
        "positive_rule_recall": recall,
        "positive_opportunities": positive,
        "incident_recall": sum(v["truth"] == "TRUE" for v in incidents) / len(incidents)
        if incidents
        else None,
        "incident_opportunities": len(incidents),
        "raw_detail_availability": len(receipt_keys & accepted_keys)
        / len(accepted_keys)
        if accepted_keys
        else None,
        "raw_receipts": len(receipt_keys & accepted_keys),
        "receiver_rejections": observer.rejections,
        "deadline_misses": sum(v["truth"] == "UNKNOWN" for v in verdicts),
        "native_legacy_anomalies": observer.native_anomalies,
        "native_legacy_alerts": observer.native_alerts,
        "evidence_fraction": static["evidence_bytes"]
        / (static["wire_bytes"] - 28 * len(result["transmissions"]))
        if static["wire_bytes"]
        else None,
        "bandwidth_saving": (static["generated_bytes"] - static["wire_bytes"])
        / static["generated_bytes"]
        if static["generated_bytes"]
        else None,
        "critical_samples": len(critical),
    }
    for label, samples in (
        ("latency", latencies),
        ("critical_latency", critical),
        ("decision_latency", definite),
        ("queue_wait", queue_wait),
    ):
        for q in (50, 95, 99):
            metrics[f"{label}_p{q}_seconds"] = (
                percentile(samples, q) if samples else None
            )
    for priority in PriorityLevel:
        samples = [
            r["at_seconds"] - (r["ingress_utc_us"] - epoch_us) / 1e6
            for r in raw
            if r["priority"] == priority.value
        ]
        metrics[f"{priority.value.lower()}_samples"] = len(samples)
        for q in (50, 95, 99):
            metrics[f"{priority.value.lower()}_latency_p{q}_seconds"] = (
                percentile(samples, q) if samples else None
            )
    return metrics, verdicts

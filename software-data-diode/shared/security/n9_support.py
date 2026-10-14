"""Test-only scope guards, ephemeral fixtures and explicit result semantics."""
from __future__ import annotations

import csv
import hashlib
import json
import re
import socket
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from shared.coverage.capsules import InputRecord, build_capsule, sign_artifact, artifact_digest
from shared.coverage.contracts import contract_hash
from shared.coverage.models import WindowIdentity, IngressObservation, MetricReading
from shared.coverage.parts import split_artifact
from shared.coverage.rules import VerifiedScope
from shared.coverage.transport import ResearchFramer, TrustProfile
from shared.coverage.verification import FogEvidenceVerifier
from shared.models import EdgeTelemetryMessage
from shared.security.crypto import canonical_bytes


PROJECT_PREFIX = "software-data-diode-n9-"


def test_project(project, run_id):
    if not re.fullmatch(r"[a-f0-9]{12}", run_id or "") or project != PROJECT_PREFIX+run_id:
        raise ValueError("unique isolated N9 project/run identity required")
    return project


class TargetAllowlist:
    """Only exact provisioned service/IP/port tuples; no URL or host fallback."""
    def __init__(self, document, resolver=socket.gethostbyname):
        self.project = test_project(document["project"], document["run_id"])
        self.targets = document["targets"]
        self.resolve = resolver
        if set(self.targets) != {"edge-gateway", "fog-receiver"}:
            raise ValueError("unexpected N9 target set")
        for name, target in self.targets.items():
            import ipaddress
            address = ipaddress.ip_address(target["address"])
            if not address.is_private or address.is_loopback or address.is_unspecified or address.is_multicast:
                raise ValueError("target must be an isolated container address")
            if target["ports"] != ([8000] if name == "edge-gateway" else [9002]):
                raise ValueError("unexpected target ports")

    def endpoint(self, service, port):
        target = self.targets.get(service)
        if target is None or port not in target["ports"] or self.resolve(service) != target["address"]:
            raise ValueError("target absent from this project's pinned allowlist")
        return target["address"], port

    def gateway_url(self, route):
        if route not in {"/telemetry", "/metrics/runtime", "/ready"}:
            raise ValueError("unlisted gateway route")
        address, port = self.endpoint("edge-gateway", 8000)
        return f"http://{address}:{port}{route}"


@dataclass
class Result:
    scenario: str
    attack_type: str
    expected_result: str
    actual_result: str
    passed: bool
    detected: bool | None
    scope: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    latency_seconds: float | None = None
    queue_data: dict = field(default_factory=dict)
    resource_data: dict = field(default_factory=dict)
    reason: str = ""


def export_results(directory, results, metadata):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    if any((directory/name).exists() for name in ("results.json", "results.csv")):
        raise ValueError("refusing to overwrite prior N9 results")
    rows = [asdict(r) for r in results]
    document = {"metadata": metadata, "results": rows, "passed": all(r.passed for r in results),
        "detected_in_scope": sum(r.detected is True for r in results if r.scope == "IN_SCOPE_ATTACK"),
        "in_scope_attack_cases": sum(r.scope == "IN_SCOPE_ATTACK" for r in results),
        "out_of_scope_cases": sum(r.scope.startswith("OUT_OF_SCOPE") for r in results)}
    (directory/"results.json").write_text(json.dumps(document, indent=2), encoding="utf-8")
    fields = list(Result.__dataclass_fields__)
    with (directory/"results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            for name in ("queue_data", "resource_data"):
                row[name] = json.dumps(row[name], sort_keys=True)
            row["detected"] = "NOT_APPLICABLE" if row["detected"] is None else str(row["detected"]).lower()
            writer.writerow(row)
    return document


class TestClock:
    def __init__(self, seconds=0):
        self.utc = datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(seconds=seconds)
        self.ns = 0
    def utc_now(self): return self.utc
    def monotonic_ns(self): return self.ns
    def advance(self, seconds, wall=None):
        self.ns += int(seconds*1e9)
        self.utc += timedelta(seconds=seconds if wall is None else wall)


def fixture_framer(contract, key, epoch="n9-ephemeral-epoch", config=None):
    profile = TrustProfile(gateway_id="coverage-gateway",signing_key_id="coverage-key",ledger_epoch=epoch,
        contract_hash=contract_hash(contract),public_key_sha256=hashlib.sha256(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).hexdigest())
    return ResearchFramer(profile,key.public_key(),contract,private_key=key,config=config)


def scope_fixture(framer, device, values, index=100, *, complete=True, limitations=(), previous=None):
    window = WindowIdentity(ledger_epoch=framer.profile.ledger_epoch,device_id=device,
                            contract_hash=framer.profile.contract_hash,window_index=index)
    definition = next(d for d in framer.contract.devices if d.device_id == device)
    path, originals = definition.metrics[0].path, []
    for seq, value in enumerate(values, 1):
        values_dict = {"device_id":device,"timestamp":datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(microseconds=window.start_utc_us+seq),
            "telemetry_type":definition.telemetry_type,"temperature":25,"humidity":50,"status":"normal"}
        if path.startswith("measurements."):
            values_dict["measurements"] = {} if value is None else {path[len("measurements."):]:value}
        else:
            values_dict[path] = value
        message = EdgeTelemetryMessage(**values_dict)
        encoded = canonical_bytes(message.model_dump(mode="json"))
        originals.append(InputRecord(ledger_epoch=window.ledger_epoch,device_id=device,ingress_sequence=index*1000+seq,
            ingress_utc_us=window.start_utc_us+seq,canonical_input=encoded,input_hash=hashlib.sha256(encoded).hexdigest()))
    body = build_capsule(contract=framer.contract,window=window,records=originals,gateway_id=framer.profile.gateway_id,
        signing_key_id=framer.profile.signing_key_id,created_at_utc_us=window.end_utc_us,population_complete=complete,
        limitations=limitations,previous_digest=previous,
        closure_reason="CLOCK_DISCONTINUITY" if "CLOCK_DISCONTINUITY" in limitations else "WINDOW_END")
    encoded = sign_artifact(body,framer.private_key)
    frames = split_artifact(encoded,framer.private_key)
    record = FogEvidenceVerifier(framer).verify(encoded,received_us=window.end_utc_us,frames=frames)
    return VerifiedScope(body,artifact_digest(encoded),record),tuple(originals),encoded,frames


def oracle_original(record, contract):
    """Normalize full canonical ingress independently of production fact helpers."""
    document = json.loads(record.canonical_input)
    device = next(d for d in contract.devices if d.device_id == record.device_id)
    readings = []
    for metric in device.metrics:
        value = document.get("measurements", {}).get(metric.path[len("measurements."):]) if metric.path.startswith("measurements.") else document.get(metric.path)
        readings.append(MetricReading(path=metric.path,value=value))
    return IngressObservation(ledger_epoch=record.ledger_epoch,device_id=record.device_id,
        ingress_sequence=record.ingress_sequence,ingress_utc_us=record.ingress_utc_us,
        telemetry_type=document["telemetry_type"],metrics=tuple(readings))


def resource_sample():
    rss = None
    if Path("/proc/self/status").exists():
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                rss = int(line.split()[1])*1024
    return {"process_cpu_seconds": time.process_time(), "rss_bytes": rss,
            "measurement_scope": "CAMPAIGN_PROCESS_NOT_ALL_CONTAINERS"}

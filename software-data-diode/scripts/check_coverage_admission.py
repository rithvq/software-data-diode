"""Small N4 paired accounting check; not an N10 performance benchmark."""
import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shared.coverage.admission import CoupledAdmission, MODES
from shared.coverage.budget import AdmissionConfig
from shared.coverage.contracts import load_contract
from shared.coverage.ledger import LedgerRefused, ObservationLedger
from shared.models import EdgeTelemetryMessage
from shared.security.crypto import canonical_bytes
from shared.traffic.information import InformationPolicyConfig


class Clock:
    def __init__(self):
        self.us = 0
    def monotonic_ns(self):
        return self.us*1000
    def utc_now(self):
        return datetime(2026, 1, 1, tzinfo=timezone.utc)+timedelta(microseconds=self.us)


def run_case(mode, *, service_available, windows=12):
    contract = load_contract(ROOT / "config/rule_coverage.json")
    config = AdmissionConfig(link_bytes_per_second=65536, max_evidence_debt_cycles=1)
    policy = InformationPolicyConfig(max_queue_size=8, prediction_enabled=False)
    # Published fixture seed is deliberately not a deployment credential.
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"N4-local-accounting-fixture-only").digest())
    clock, offered, refused, grants, trace = Clock(), 0, 0, [], []
    with TemporaryDirectory(prefix="rccd-n4-") as directory:
        ledger = ObservationLedger(Path(directory)/"ledger.db", contract, create=True, clock=clock)
        try:
            controller = CoupledAdmission(ledger, "coverage-gateway", "coverage-key", key,
                                          config=config, policy=policy, mode=mode)
            for window in range(windows):
                for device in contract.devices:
                    payload = EdgeTelemetryMessage(device_id=device.device_id, telemetry_type=device.telemetry_type,
                        timestamp=clock.utc_now(), temperature=42, humidity=50, status="normal", cpu_usage=95,
                        measurements={"packets_per_second": 10000, "failed_logins": 7, "vibration_mm_s": 9})
                    trace.append(payload.model_dump(mode="json"))
                    offered += 1
                    try:
                        controller.admit(payload, expected_epoch=ledger.epoch, retry_sequence=window+1)
                    except LedgerRefused as exc:
                        if exc.reason != "EVIDENCE_FORWARD_BUDGET_UNSUPPORTED":
                            raise
                        refused += 1
                end = (window+1)*10_000_000
                if service_available:
                    while clock.us < end:
                        grant = controller.lease_frame()
                        if grant:
                            grants.append((clock.us, grant.lane, grant.kind, grant.modeled_wire_bytes))
                            controller.complete_local_attempt(grant.lease_id)
                        clock.us = min(end, max(clock.us+1, controller._service().next_us)) if grant else min(end, clock.us+100_000)
                else:
                    clock.us = end
                ledger.tick()
            if service_available:
                deadline = clock.us+10_000_000
                while clock.us < deadline and controller.status()["outbox_items"]:
                    grant = controller.lease_frame()
                    if grant:
                        grants.append((clock.us, grant.lane, grant.kind, grant.modeled_wire_bytes))
                        controller.complete_local_attempt(grant.lease_id)
                    clock.us = max(clock.us+1, controller._service().next_us) if grant else clock.us+100_000
            counts = {row[0]: row[1] for row in ledger.db.execute("SELECT obligation,COUNT(*) FROM windows GROUP BY obligation")}
            return {"mode": mode, "service_available": service_available, "windows": windows,
                "config": config.model_dump(mode="json"), "contract_hash": ledger.digest,
                "trace_sha256": hashlib.sha256(canonical_bytes(trace)).hexdigest(),
                "offered": offered, "accepted": len(ledger.records()), "refused_unaccepted": refused,
                "unsupported_scopes": counts.get("UNSUPPORTED", 0),
                "evidence_locally_attempted_scopes": counts.get("LOCAL_ATTEMPTED", 0),
                "modeled_bytes": sum(x[3] for x in grants),
                "evidence_modeled_bytes": sum(x[3] for x in grants if x[2] == "EVIDENCE"),
                "raw_modeled_bytes": sum(x[3] for x in grants if x[2] == "RAW"),
                "outbox_items": controller.status()["outbox_items"],
                "reserved_wire_bytes": controller.status()["reserved_wire_bytes"],
                "frame_grants": grants,
                "service_state": asdict(controller._service()),
                "assurance": "LOCAL_BYTE_MODEL_NOT_NETWORK_MEASUREMENT"}
        finally:
            ledger.close()


def comparison():
    return {"schema_version": 1, "fixture_seed_name": "N4-local-accounting-fixture-only",
            "purpose": "deterministic N4 accounting checks, not a repeated-trial benchmark",
            "cases": [run_case(mode, service_available=available) for available in (True, False) for mode in MODES]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(comparison(), sort_keys=True, indent=2)+"\n"
    if args.output:
        # Refuse overwriting earlier experiment evidence.
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(encoded)
        print("N4 paired local accounting evidence: " + str(args.output))
    else:
        print(encoded)


if __name__ == "__main__":
    main()

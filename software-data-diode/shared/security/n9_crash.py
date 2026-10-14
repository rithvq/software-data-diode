"""Real process termination at existing durable transaction boundaries; test only."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from shared.coverage.admission import CoupledAdmission
from shared.coverage.contracts import load_contract
from shared.coverage.fog_store import FogEvidenceStore
from shared.coverage.ledger import ObservationLedger
from shared.coverage.transport import PartAssembler
from shared.models import EdgeTelemetryMessage
from shared.traffic.information import InformationPolicyConfig
from .n9_support import Result, TestClock, fixture_framer, scope_fixture


ADMISSION = ("before_identity", "after_observation", "after_facts", "after_reservation",
             "after_reduction", "after_obligation", "before_commit", "after_commit")
CLOSURE = ("before_capsule_commit", "after_capsule_commit", "after_evidence_stage")
GRANT = ("before_service_commit", "after_service_commit")
ATTEMPT = ("before_attempt_commit", "after_attempt_commit")
RECEIVER = ("after_receiver_insert", "after_receiver_head", "before_receiver_commit", "after_receiver_commit")


class CrashConnection:
    def __init__(self, connection, stage): self.connection, self.stage = connection, stage
    def __getattr__(self, name): return getattr(self.connection, name)
    def execute(self, statement, *args):
        normalized = statement.strip().upper()
        if self.stage == "before_receiver_commit" and normalized == "COMMIT": os._exit(77)
        result = self.connection.execute(statement, *args)
        if ((self.stage == "after_receiver_insert" and normalized.startswith("INSERT INTO EVIDENCE_WORK"))
            or (self.stage == "after_receiver_head" and normalized.startswith("INSERT INTO HEADS"))
            or (self.stage == "after_receiver_commit" and normalized == "COMMIT")):
            os._exit(77)
        return result


def worker(spec):
    contract = load_contract(spec["contract"])
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(spec["key"]))
    stage, path = spec["stage"], Path(spec["directory"])/"state.sqlite3"
    if stage in RECEIVER:
        framer = fixture_framer(contract,key)
        scope, _, _, frames = scope_fixture(framer,"edge-device-02",(95,))
        store = FogEvidenceStore(path,framer,now_us=lambda:scope.body.window_end_utc_us)
        store.db = CrashConnection(store.db,stage)
        assembler, artifact = PartAssembler(framer), None
        for frame in frames: artifact = assembler.add(frame) or artifact
        store.accept(artifact)
    else:
        clock = TestClock()
        ledger = ObservationLedger(path,contract,create=True,clock=clock)
        policy = InformationPolicyConfig(max_message_bytes=1) if stage in ADMISSION else InformationPolicyConfig()
        controller = CoupledAdmission(ledger,"coverage-gateway","coverage-key",key,policy=policy)
        def fail(point, db):
            if point == stage: os._exit(77)
        message = EdgeTelemetryMessage(device_id="edge-device-01",timestamp=clock.utc_now(),
                                       temperature=25,humidity=50,status="normal")
        if stage in ADMISSION:
            ledger.fault = fail
            controller.admit(message,expected_epoch=ledger.epoch,retry_sequence=1)
        elif stage in CLOSURE:
            controller.admit(message,expected_epoch=ledger.epoch,retry_sequence=1)
            ledger.fault = fail
            clock.advance(11)
            ledger.tick()
        else:
            controller.admit(message,expected_epoch=ledger.epoch,retry_sequence=1,priority="CRITICAL")
            clock.advance(11)
            ledger.tick()
            if stage in GRANT:
                ledger.fault = fail
                controller.lease_frame()
            else:
                lease = controller.lease_frame()
                if not lease: raise RuntimeError("fixture did not grant work")
                ledger.fault = fail
                controller.complete_local_attempt(lease.lease_id)
    raise RuntimeError("crash boundary was not exercised")


def crash_campaign(root, contract_path):
    root = Path(root)
    root.mkdir(parents=True,exist_ok=True)
    results = []
    for stage in (*ADMISSION,*CLOSURE,*GRANT,*ATTEMPT,*RECEIVER):
        folder = root/stage
        folder.mkdir()
        key = Ed25519PrivateKey.generate()
        spec = {"stage":stage,"directory":str(folder),"contract":str(Path(contract_path).absolute()),
                "key":key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()).hex()}
        start = time.perf_counter()
        child = subprocess.run([sys.executable,"-m","shared.security.n9_crash","--worker",json.dumps(spec)],
                               capture_output=True,text=True,timeout=20)
        if child.returncode != 77: raise AssertionError(stage+": "+child.stderr[-1200:])
        contract = load_contract(contract_path)
        path = folder/"state.sqlite3"
        if stage in RECEIVER:
            framer = fixture_framer(contract,key)
            store = FogEvidenceStore(path,framer,now_us=lambda:1_010_000_000)
            try:
                count = store.db.execute("SELECT COUNT(*) FROM evidence_work").fetchone()[0]
                heads = store.db.execute("SELECT COUNT(*) FROM heads").fetchone()[0]
                expected = int(stage == "after_receiver_commit")
                good = count == heads == expected
                data = {"spooled_records":count,"durable_heads":heads,"expected":expected}
            finally: store.close()
        else:
            clock = TestClock(20)
            ledger = ObservationLedger(path,contract,clock=clock)
            policy = InformationPolicyConfig(max_message_bytes=1) if stage in ADMISSION else InformationPolicyConfig()
            try:
                controller = CoupledAdmission(ledger,"coverage-gateway","coverage-key",key,policy=policy)
                expected = int(stage not in ADMISSION or stage == "after_commit")
                count = len(ledger.records())
                good = count == expected and all(f.accepted_count == expected for f in ledger.facts() if f.accepted_count)
                data = {"original_records":count,"expected":expected,"outbox":controller.status()}
                if stage in GRANT:
                    charged = controller.status()["modeled_scheduled_bytes"]
                    good = good and (charged>0) == (stage == "after_service_commit")
                    controller.retire_uncertain_lease()
                    good = good and charged == controller.status()["modeled_scheduled_bytes"]
                if stage in ATTEMPT:
                    lease = bool(ledger.db.execute("SELECT 1 FROM n4_inflight").fetchone())
                    good = good and lease == (stage == "before_attempt_commit")
                    before = controller.status()["modeled_scheduled_bytes"]
                    controller.retire_uncertain_lease()
                    good = good and before == controller.status()["modeled_scheduled_bytes"]
            finally: ledger.close()
        results.append(Result("crash-"+stage,"PROCESS_EXIT_AT_TRANSACTION_BOUNDARY","ATOMIC_RECOVERY",
            "ATOMIC_RECOVERY" if good else "PARTIAL_OR_LOST_STATE",good,None,"IN_SCOPE_FAILURE",
            latency_seconds=time.perf_counter()-start,queue_data=data,
            reason="os._exit(77), not an exception caught by the transaction manager"))
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker",required=True)
    worker(json.loads(parser.parse_args().worker))

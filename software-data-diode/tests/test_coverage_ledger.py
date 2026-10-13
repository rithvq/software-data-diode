import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from threading import Event
from unittest.mock import Mock

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

from shared.coverage import load_contract, trace_oracle, evaluate_rule
from shared.coverage.ledger import LedgerLimits, LedgerRefused, ObservationLedger
from shared.coverage.runtime_state import initialize
from shared.edge import DeviceRegistry
from shared.models import EdgeTelemetryMessage
from tests.conftest import load_service_module


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = load_contract(ROOT / "config/rule_coverage.json")
EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)


class FakeClock:
    def __init__(self, seconds=0):
        self.utc = EPOCH + timedelta(seconds=seconds)
        self.ns = 0
    def utc_now(self): return self.utc
    def monotonic_ns(self): return self.ns
    def advance(self, seconds, wall=None):
        self.ns += int(seconds*1000000000)
        self.utc += timedelta(seconds=seconds if wall is None else wall)


def message(device="edge-device-01", **values):
    return EdgeTelemetryMessage(device_id=device, timestamp=EPOCH,
        temperature=values.pop("temperature", 25), humidity=50, status="normal", **values)


@pytest.fixture
def ledger(tmp_path):
    directory = tmp_path/"state"
    directory.mkdir()
    store = ObservationLedger(directory/"ledger.sqlite3", CONTRACT, create=True, clock=FakeClock())
    try:
        yield store
    finally:
        store.close()


def admit(store, payload=None, retry=1):
    return store.admit(payload or message(), expected_epoch=store.epoch, retry_sequence=retry)


def test_durable_original_input_facts_obligation_and_namespaces(ledger):
    outgoing = DeviceRegistry()
    outgoing.next_sequence("edge-device-01")
    receipt = admit(ledger, message(temperature=45))
    records = ledger.records()
    assert len(records) == 1 and records[0]["body"] == json.dumps(message(temperature=45).model_dump(mode="json"),
        sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert records[0]["input_hash"] == hashlib.sha256(records[0]["body"]).hexdigest()
    assert receipt.ingress_sequence == 1
    assert outgoing.snapshot("edge-device-01").last_sequence_number == 1
    fact = ledger.facts()[0]
    assert fact.accepted_count == fact.matching_count == 1 and not fact.closed
    row = ledger.db.execute("SELECT * FROM windows").fetchone()
    assert row["obligation"] == "UNSIZED" and row["reserved_bytes"] == 0
    assert records[0]["disposition"] == "PENDING_POLICY"


def test_duplicate_local_retry_conflict_and_order(ledger):
    first = admit(ledger, retry=10)
    second = admit(ledger, retry=10)
    assert first.ingress_sequence == second.ingress_sequence == 1
    assert second.duplicate and not first.duplicate
    assert len(ledger.records()) == 1 and ledger.facts()[0].accepted_count == 1
    with pytest.raises(LedgerRefused, match="CONFLICT"):
        admit(ledger, message(temperature=99), retry=10)
    with pytest.raises(LedgerRefused, match="OLD_RETRY"):
        admit(ledger, retry=9)
    assert admit(ledger, retry=11).ingress_sequence == 2


@pytest.mark.parametrize("stage", ["before_identity", "after_observation", "after_facts", "after_obligation", "before_commit"])
def test_transaction_fault_rolls_back_whole_admission_and_counter(ledger, stage):
    def fail(point, db):
        if point == stage:
            with sqlite3.connect(ledger.path) as reader:
                assert reader.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == 0
            raise RuntimeError("injected transaction interruption")
    ledger.fault = fail
    with pytest.raises(RuntimeError, match="interruption"):
        admit(ledger)
    assert not ledger.records() and not ledger.facts()
    assert ledger.status()["unsized_obligations"] == 0
    ledger.fault = lambda *args: None
    assert admit(ledger).ingress_sequence == 1


def test_lost_reply_after_commit_is_recovered_without_double_accounting(ledger):
    def fail(stage, db):
        if stage == "after_commit":
            raise RuntimeError("lost response")
    ledger.fault = fail
    with pytest.raises(RuntimeError, match="lost response"):
        admit(ledger)
    assert len(ledger.records()) == 1
    receipt = admit(ledger)
    assert receipt.duplicate and receipt.ingress_sequence == 1
    assert ledger.facts()[0].accepted_count == 1


@pytest.mark.parametrize("stage,expected", [("before_commit", 0), ("after_commit", 1)])
def test_real_process_death_around_sqlite_commit(tmp_path, stage, expected):
    path = tmp_path/"ledger.sqlite3"
    created = ObservationLedger(path, CONTRACT, create=True, clock=FakeClock())
    epoch = created.epoch
    created.close()
    program = """
import os, sys
from datetime import datetime, timezone
from shared.coverage import load_contract
from shared.coverage.ledger import ObservationLedger
from shared.models import EdgeTelemetryMessage
class Clock:
    def utc_now(self): return datetime(2026,1,1,tzinfo=timezone.utc)
    def monotonic_ns(self): return 0
def fault(stage, db):
    if stage == sys.argv[3]: os._exit(77)
s=ObservationLedger(sys.argv[1],load_contract(sys.argv[2]),clock=Clock(),fault=fault)
m=EdgeTelemetryMessage(device_id='edge-device-01',timestamp=Clock().utc_now(),temperature=25,humidity=50,status='normal')
s.admit(m,expected_epoch=s.epoch,retry_sequence=1)
"""
    result = subprocess.run([sys.executable,"-c",program,str(path),str(ROOT/"config/rule_coverage.json"),stage],
                            cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert result.returncode == 77, result.stderr
    recovered = ObservationLedger(path, CONTRACT, clock=FakeClock(20))
    try:
        assert recovered.epoch == epoch and len(recovered.records()) == expected
        if expected:
            assert admit(recovered).duplicate
            assert recovered.facts()[0].accepted_count == 1
            assert "INTERRUPTED" in recovered.facts()[0].limitations
        else:
            assert admit(recovered).ingress_sequence == 1
    finally:
        recovered.close()


def test_five_devices_concurrent_and_independent_sequences(ledger):
    def run(device):
        payload = message(device.device_id, telemetry_type=device.telemetry_type,
                          measurements={"failed_logins":7, "packets_per_second":10000, "vibration_mm_s":9}, cpu_usage=95)
        return [admit(ledger, payload, retry=sequence) for sequence in range(1,11)]
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(run, CONTRACT.devices))
    assert all([receipt.ingress_sequence for receipt in batch] == list(range(1,11)) for batch in results)
    assert len(ledger.records()) == 50
    assert len({(row["epoch"],row["device"],row["seq"]) for row in ledger.records()}) == 50
    assert all(fact.accepted_count == 10 for fact in ledger.facts())


def test_recovered_facts_match_independent_original_trace_oracle(ledger):
    for device in CONTRACT.devices:
        payload = message(device.device_id, telemetry_type=device.telemetry_type, temperature=45, cpu_usage=95,
                          measurements={"failed_logins":7,"packets_per_second":10000,"vibration_mm_s":9})
        admit(ledger, payload)
    ledger.clock.advance(10)
    ledger.tick()
    originals = [ledger._observation(EdgeTelemetryMessage.model_validate_json(row["body"]),
                 row["epoch"],row["seq"],row["ingress_us"]) for row in ledger.records()]
    for rule in CONTRACT.rules:
        actual = evaluate_rule(CONTRACT, rule.rule_id, ledger_epoch=ledger.epoch,
                               window_index=originals[0].ingress_utc_us//10000000, facts=ledger.facts())
        expected = trace_oracle(CONTRACT, rule.rule_id, ledger_epoch=ledger.epoch,
                                window_index=actual.window_index, observations=originals)
        assert actual.truth == expected


def test_missing_metric_and_wrong_telemetry_type_are_unresolved(ledger):
    admit(ledger, message("edge-device-04",telemetry_type="security"))
    admit(ledger, message("edge-device-02",telemetry_type="network",cpu_usage=95))
    assert all(f.unresolved_count == 1 and f.accepted_count == 1 for f in ledger.facts())


@pytest.mark.parametrize("retry", [None, True, 0, -1, 2**63])
def test_bad_local_retry_identity_is_not_accepted(ledger, retry):
    with pytest.raises(LedgerRefused, match="RETRY_SEQUENCE"):
        admit(ledger, retry=retry)
    assert not ledger.records()


def test_unknown_device_old_epoch_and_expired_new_input_are_not_accepted(ledger):
    with pytest.raises(LedgerRefused, match="UNREGISTERED"):
        admit(ledger, message("unregistered"))
    with pytest.raises(LedgerRefused, match="EPOCH_MISMATCH"):
        ledger.admit(message(),expected_epoch="wrong",retry_sequence=1)
    ledger.clock.advance(1000)
    with pytest.raises(LedgerRefused, match="EXPIRED"):
        ledger.admit(message(),expected_epoch=ledger.epoch,retry_sequence=1,freshness_seconds=300)
    assert not ledger.records()


@pytest.mark.parametrize("limit", ["max_retained_records", "max_pending_outbox_bytes", "max_retained_windows", "max_active_windows"])
def test_capacity_refuses_before_durable_acceptance(tmp_path, limit):
    setting = 1 if limit != "max_pending_outbox_bytes" else len(json.dumps(message().model_dump(mode="json"),sort_keys=True,separators=(",", ":")).encode())
    store = ObservationLedger(tmp_path/"ledger.db",CONTRACT,create=True,clock=FakeClock(),limits=LedgerLimits(**{limit:setting}))
    try:
        admit(store)
        with pytest.raises(LedgerRefused, match="CAPACITY"):
            admit(store, message("edge-device-02",telemetry_type="system"), retry=1)
        assert len(store.records()) == 1
        assert store.db.execute("SELECT ingress FROM devices WHERE device='edge-device-02'").fetchone()[0] == 0
        assert store.status()["unsized_obligations"] == 1
    finally:
        store.close()


def test_input_limit_actual_sqlite_full_and_restart(tmp_path):
    path = tmp_path/"full.db"
    limits = LedgerLimits(max_database_bytes=128*1024)
    store = ObservationLedger(path,CONTRACT,create=True,clock=FakeClock(),limits=limits)
    acknowledged = 0
    payload = message(attributes={"large":"x"*5000})
    try:
        for retry in range(1,100):
            try:
                admit(store,payload,retry)
                acknowledged += 1
            except LedgerRefused as exc:
                assert exc.reason == "STORAGE_UNAVAILABLE"
                break
        else:
            pytest.fail("actual max_page_count exhaustion was not exercised")
        assert acknowledged > 0 and len(store.records()) == acknowledged
        assert store.facts()[0].accepted_count == acknowledged
        assert path.stat().st_size <= limits.max_database_bytes
    finally:
        store.close()
    recovered = ObservationLedger(path,CONTRACT,clock=FakeClock(20),limits=limits)
    try:
        assert len(recovered.records()) == acknowledged
        assert admit(recovered,payload,acknowledged).duplicate
    finally:
        recovered.close()
    tiny = ObservationLedger(tmp_path/"small.db",CONTRACT,create=True,clock=FakeClock(),limits=LedgerLimits(max_input_bytes=256))
    try:
        with pytest.raises(LedgerRefused, match="INPUT_TOO_LARGE"):
            admit(tiny)
        assert not tiny.records()
    finally:
        tiny.close()


def test_injected_storage_error_after_facts_leaves_no_ack_or_partial_state(ledger):
    def unavailable(stage, db):
        if stage == "after_facts":
            raise sqlite3.OperationalError("disk I/O error")
    ledger.fault = unavailable
    with pytest.raises(LedgerRefused, match="STORAGE_UNAVAILABLE"):
        admit(ledger)
    assert not ledger.records() and not ledger.facts()
    with pytest.raises(LedgerRefused, match="REOPEN_REQUIRED"):
        admit(ledger)


def test_compaction_requires_real_closed_archive_and_preserves_retry_protection(ledger,tmp_path):
    first = admit(ledger)
    assert ledger.compact() == 0
    parameters = {"epoch":ledger.epoch,"device_id":first.device_id,"window_index":first.window_index}
    archive = tmp_path/"archive.json"
    with pytest.raises(LedgerRefused, match="OPEN"):
        ledger.export_closed_window(**parameters,path=archive)
    ledger.clock.advance(10)
    ledger.tick()
    digest = ledger.export_closed_window(**parameters,path=archive)
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == digest
    with pytest.raises(FileExistsError):
        ledger.export_closed_window(**parameters,path=archive)
    damaged = tmp_path/"damaged.json"
    damaged.write_bytes(b"{}")
    with pytest.raises(LedgerRefused, match="CHECKPOINT"):
        ledger.archive_closed_window(**parameters,archive_path=damaged)
    assert ledger.compact() == 0
    ledger.archive_closed_window(**parameters,archive_path=archive)
    original_archive = archive.read_bytes()
    archive.write_bytes(b"{}")
    with pytest.raises(LedgerRefused, match="CHECKPOINT"):
        ledger.compact()
    assert len(ledger.records()) == 1
    archive.write_bytes(original_archive)
    assert ledger.compact() == 1 and not ledger.records() and not ledger.facts()
    assert json.loads(archive.read_bytes())["observations"][0]["seq"] == 1
    with pytest.raises(LedgerRefused, match="OLD_RETRY"):
        admit(ledger)
    assert admit(ledger,retry=2).ingress_sequence == 2


def test_many_retention_cycles_stay_bounded_without_reusing_identity(ledger,tmp_path):
    hashes = []
    for retry in range(1,26):
        receipt = admit(ledger,retry=retry)
        assert receipt.ingress_sequence == retry
        ledger.clock.advance(10)
        ledger.tick()
        scope = {"epoch":ledger.epoch,"device_id":receipt.device_id,"window_index":receipt.window_index}
        archive = tmp_path/f"archive-{retry}.json"
        hashes.append(ledger.export_closed_window(**scope,path=archive))
        ledger.archive_closed_window(**scope,archive_path=archive)
        assert ledger.compact() == 1 and not ledger.records()
        assert ledger.status()["pending_outbox_bytes"] == 0
    assert len(set(hashes)) == 25 and ledger.status()["database_bytes"] <= ledger.limits.max_database_bytes
    with pytest.raises(LedgerRefused,match="OLD_RETRY"):
        admit(ledger,retry=1)


def test_changed_page_size_and_in_volume_archive_are_refused(tmp_path,ledger):
    path = tmp_path/"page-size.db"
    store = ObservationLedger(path,CONTRACT,create=True,clock=FakeClock())
    store.close()
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA page_size=8192")
        db.execute("VACUUM")
    with pytest.raises(LedgerRefused,match="PAGE_SIZE"):
        ObservationLedger(path,CONTRACT,clock=FakeClock())
    receipt = admit(ledger)
    ledger.clock.advance(10)
    ledger.tick()
    with pytest.raises(LedgerRefused,match="ARCHIVE_MUST_BE_EXTERNAL"):
        ledger.export_closed_window(epoch=ledger.epoch,device_id=receipt.device_id,
                                    window_index=receipt.window_index,path=ledger.path.parent/"archive.json")


def test_controlled_epoch_retirement_does_not_reset_counters(ledger,tmp_path):
    first = admit(ledger)
    with pytest.raises(LedgerRefused, match="QUIESCENT"):
        ledger.retire_epoch(expected_epoch=ledger.epoch,checkpoint_hash="a"*64)
    ledger.clock.advance(10)
    ledger.tick()
    archive = tmp_path/"archive.json"
    scope = {"epoch":ledger.epoch,"device_id":first.device_id,"window_index":first.window_index}
    checkpoint = ledger.export_closed_window(**scope,path=archive)
    ledger.archive_closed_window(**scope,archive_path=archive)
    ledger.compact()
    old_epoch = ledger.epoch
    new_epoch = ledger.retire_epoch(expected_epoch=old_epoch,checkpoint_hash=checkpoint)
    assert new_epoch != old_epoch and ledger.status()["generation"] == 1
    with pytest.raises(LedgerRefused, match="EPOCH_MISMATCH"):
        ledger.admit(message(),expected_epoch=old_epoch,retry_sequence=2)
    with pytest.raises(LedgerRefused, match="OLD_RETRY"):
        admit(ledger,retry=1)
    assert admit(ledger,retry=2).ingress_sequence == 2


def test_restart_before_next_boundary_refuses_reopening_sealed_population(tmp_path):
    path = tmp_path/"restart.db"
    store = ObservationLedger(path,CONTRACT,create=True,clock=FakeClock())
    first = admit(store)
    epoch = store.epoch
    store.close()
    clock = FakeClock(1)
    reopened = ObservationLedger(path,CONTRACT,clock=clock)
    try:
        assert reopened.epoch == epoch
        assert reopened.status()["admission_blocked"]
        assert admit(reopened).duplicate
        with pytest.raises(LedgerRefused,match="CLOSED_WINDOW"):
            admit(reopened,retry=2)
        assert reopened.facts()[0].closed and "INTERRUPTED" in reopened.facts()[0].limitations
        clock.advance(9)
        assert admit(reopened,retry=2).ingress_sequence == 2
    finally:
        reopened.close()


@pytest.mark.parametrize("wall", [21, -1])
def test_clock_jump_seals_limits_and_refuses_current_admission(ledger,wall):
    admit(ledger)
    ledger.clock.advance(1,wall=wall)
    with pytest.raises(LedgerRefused,match="CLOCK_DISCONTINUITY"):
        admit(ledger,retry=2)
    assert len(ledger.records()) == 1 and ledger.status()["clock_halted"]
    assert ledger.facts()[0].closed and "CLOCK_DISCONTINUITY" in ledger.facts()[0].limitations
    assert admit(ledger).duplicate


def test_skipped_windows_are_not_synthesized_and_transaction_clock_rolls_back(ledger):
    admit(ledger)
    ledger.clock.advance(30)
    def fail(stage,db):
        if stage == "after_facts": raise RuntimeError("interrupted closure/admission")
    ledger.fault = fail
    with pytest.raises(RuntimeError): admit(ledger,retry=2)
    assert len(ledger.facts()) == 1 and not ledger.facts()[0].closed
    ledger.fault = lambda *args:None
    admit(ledger,retry=2)
    assert len(ledger.facts()) == 2
    assert ledger.facts()[0].closed and "INTERRUPTED" in ledger.facts()[0].limitations


def test_missing_foreign_corrupt_and_second_writer_state_are_refused(ledger,tmp_path):
    with pytest.raises(LedgerRefused,match="WRITER"):
        ObservationLedger(ledger.path,CONTRACT,clock=FakeClock())
    with pytest.raises(LedgerRefused,match="MISSING"):
        ObservationLedger(tmp_path/"missing.db",CONTRACT)
    with pytest.raises(LedgerRefused,match="RESEARCH_PROJECT"):
        ObservationLedger(tmp_path/"wrong.db",CONTRACT,create=True,project_name="software-data-diode")
    orphan = tmp_path/"orphan.db"
    Path(str(orphan)+".anchor.json").write_text("{}")
    with pytest.raises(LedgerRefused,match="EXISTING_IDENTITY"):
        ObservationLedger(orphan,CONTRACT,create=True)
    corrupt = tmp_path/"corrupt.db"
    store = ObservationLedger(corrupt,CONTRACT,create=True,clock=FakeClock())
    admit(store)
    store.close()
    with sqlite3.connect(corrupt) as db:
        db.execute("UPDATE facts SET matches=100")
    with pytest.raises(LedgerRefused,match="RECOVERED_FACTS"):
        ObservationLedger(corrupt,CONTRACT,clock=FakeClock(10))


def test_initializer_preserves_identity_and_refuses_missing_anchored_store(tmp_path):
    folder = tmp_path/"isolated-edge-state"
    first = initialize(folder,ROOT/"config/rule_coverage.json","software-data-diode-coverage")
    second = initialize(folder,ROOT/"config/rule_coverage.json","software-data-diode-coverage")
    assert first["epoch"] == second["epoch"]
    (folder/"observations.sqlite3").unlink()
    with pytest.raises(LedgerRefused,match="EXISTING_IDENTITY"):
        initialize(folder,ROOT/"config/rule_coverage.json","software-data-diode-coverage")


def test_gateway_only_acknowledges_commits_and_never_calls_policy(ledger,monkeypatch):
    gateway = load_service_module("edge-gateway")
    monkeypatch.setattr(gateway,"RULE_COVERAGE_ENABLED",True)
    monkeypatch.setattr(gateway,"_coverage_ledger",ledger)
    policy = Mock(side_effect=AssertionError("N2 must not filter"))
    monkeypatch.setattr(gateway.information_engine,"submit",policy)
    client = TestClient(gateway.app)
    headers = {"X-Coverage-Epoch":ledger.epoch,"X-Coverage-Retry-Sequence":"1"}
    payload = message().model_dump(mode="json")
    response = client.post("/telemetry",json=payload,headers=headers)
    assert response.status_code == 200 and response.json()["status"] == "accepted"
    assert response.json()["ingress_sequence"] == 1 and len(ledger.records()) == 1
    duplicate = client.post("/telemetry",json=payload,headers=headers)
    assert duplicate.json()["duplicate"] and len(ledger.records()) == 1
    assert client.post("/telemetry",json={"wrong":"schema"},headers=headers).status_code == 422
    assert client.post("/telemetry",json=payload).status_code != 200
    assert client.post("/telemetry",content=b"x"*9000).status_code == 413
    assert len(ledger.records()) == 1
    assert client.get("/ready").json()["mode"] == "ledger-only"
    policy.assert_not_called()


def test_gateway_cancelled_waiters_do_not_release_unfinished_storage_slots(ledger,monkeypatch):
    gateway = load_service_module("edge-gateway")
    monkeypatch.setattr(gateway,"_coverage_ledger",ledger)
    entered, release = Event(), Event()
    def pause(stage,db):
        if stage == "before_commit":
            entered.set()
            assert release.wait(5)
    ledger.fault = pause
    async def exercise():
        request = asyncio.create_task(gateway._receive_coverage(message(),ledger.epoch,1))
        assert await asyncio.to_thread(entered.wait,2)
        request.cancel()
        with pytest.raises(asyncio.CancelledError): await request
        assert len(gateway._coverage_admissions) == 1
        release.set()
        await asyncio.gather(*tuple(gateway._coverage_admissions))
        await asyncio.sleep(0)
        assert not gateway._coverage_admissions
        result = await gateway._receive_coverage(message(),ledger.epoch,1)
        assert result["duplicate"]
    try:
        asyncio.run(exercise())
    finally:
        release.set()


def test_gateway_bounded_inflight_requests(ledger,monkeypatch):
    gateway = load_service_module("edge-gateway")
    monkeypatch.setattr(gateway,"_coverage_ledger",ledger)
    monkeypatch.setattr(gateway,"_coverage_admissions",set(range(8)))
    with pytest.raises(HTTPException) as result:
        asyncio.run(gateway._receive_coverage(message(),ledger.epoch,1))
    assert result.value.status_code == 429 and not ledger.records()


def test_enabled_gateway_lifespan_opens_only_preprovisioned_local_state(tmp_path,monkeypatch):
    directory = tmp_path/"new-research-state"
    provisioned = initialize(directory,ROOT/"config/rule_coverage.json","software-data-diode-coverage")
    monkeypatch.setenv("RULE_COVERAGE_ENABLED","true")
    monkeypatch.setenv("COVERAGE_PROJECT_NAME","software-data-diode-coverage")
    monkeypatch.setenv("COVERAGE_LEDGER_PATH",str(directory/"observations.sqlite3"))
    monkeypatch.setenv("COVERAGE_CONTRACT_PATH",str(ROOT/"config/rule_coverage.json"))
    gateway = load_service_module("edge-gateway")
    monkeypatch.setattr(gateway.httpx,"AsyncClient",Mock(side_effect=AssertionError("ledger-only mode must not query Fog")))
    payload = message().model_copy(update={"timestamp":datetime.now(timezone.utc)}).model_dump(mode="json")
    headers = {"X-Coverage-Epoch":provisioned["epoch"],"X-Coverage-Retry-Sequence":"1"}
    with TestClient(gateway.app) as client:
        assert client.get("/ready").status_code == 200
        assert client.post("/telemetry",json=payload,headers=headers).status_code == 200
        assert gateway._policy_task is None and gateway._observability_task is None
    assert gateway._coverage_ledger is None
    reopened = ObservationLedger(directory/"observations.sqlite3",CONTRACT)
    try:
        assert reopened.epoch == provisioned["epoch"] and len(reopened.records()) == 1
        assert reopened.status()["unsized_obligations"] == 1
    finally:
        reopened.close()


def test_gateway_storage_failure_and_after_commit_reply_loss_are_not_false_acknowledgments(ledger,monkeypatch):
    gateway = load_service_module("edge-gateway")
    monkeypatch.setattr(gateway,"RULE_COVERAGE_ENABLED",True)
    monkeypatch.setattr(gateway,"_coverage_ledger",ledger)
    client = TestClient(gateway.app)
    payload = message().model_dump(mode="json")
    headers = {"X-Coverage-Epoch":ledger.epoch,"X-Coverage-Retry-Sequence":"1"}
    def fault(stage,db):
        if stage == "before_commit": raise RuntimeError("admission failed before commit")
    ledger.fault = fault
    assert client.post("/telemetry",json=payload,headers=headers).status_code == 503
    assert not ledger.records()
    def lost_response(stage,db):
        if stage == "after_commit": raise RuntimeError("reply lost after commit")
    ledger.fault = lost_response
    assert client.post("/telemetry",json=payload,headers=headers).status_code == 503
    assert len(ledger.records()) == 1
    retry = client.post("/telemetry",json=payload,headers=headers)
    assert retry.status_code == 200 and retry.json()["duplicate"]
    assert len(ledger.records()) == 1

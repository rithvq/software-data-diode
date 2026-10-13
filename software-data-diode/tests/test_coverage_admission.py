from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import json
import subprocess
import sys
from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
from fastapi.testclient import TestClient

from shared.coverage.admission import CoupledAdmission
from shared.coverage.budget import AdmissionConfig, LANES, unpack_frames, validate_budget, worst_evidence_cost
from shared.coverage.capsules import authenticated_facts, parse_artifact
from shared.coverage.models import RuleContract
from shared.coverage.runtime_state import initialize
from shared.coverage.ledger import LedgerLimits, LedgerRefused, ObservationLedger
from shared.coverage.service import ByteService
from shared.security.crypto import canonical_bytes
from shared.traffic.information import InformationPolicyConfig
from tests.conftest import load_service_module
from tests.test_coverage_ledger import CONTRACT, ROOT, FakeClock, message


@pytest.fixture
def factory(tmp_path):
    stores = []
    key = Ed25519PrivateKey.generate()
    def create(config=None, policy=None, mode="coupled", limits=None, path=None, clock=None):
        path = path or tmp_path / ("ledger-" + str(len(stores)) + ".sqlite3")
        store = ObservationLedger(path, CONTRACT, create=not path.exists(), clock=clock or FakeClock(), limits=limits)
        stores.append(store)
        controller = CoupledAdmission(store, "coverage-gateway", "coverage-key", key,
                                      config=config, policy=policy, mode=mode)
        return controller
    yield create
    for store in stores:
        store.close()


def admit(controller, retry=1, payload=None, priority="LOW"):
    return controller.admit(payload or message(), expected_epoch=controller.ledger.epoch,
                            retry_sequence=retry, priority=priority)


def drain(controller, duration=30, step=.05):
    result = []
    for _ in range(int(duration / step)):
        lease = controller.lease_frame()
        if lease:
            result.append(lease)
            controller.complete_local_attempt(lease.lease_id)
        controller.ledger.clock.advance(step)
    return result


def test_original_facts_reservation_and_outbox_commit_together(factory):
    c = factory()
    receipt = admit(c, payload=message(temperature=45))
    assert receipt.disposition == "SELECTED_RAW"
    assert c.ledger.facts()[0].matching_count == 1
    row = c.ledger.db.execute("SELECT * FROM windows").fetchone()
    assert row["obligation"] == "RESERVED"
    assert row["reserved_bytes"] == c.costs["edge-device-01"].wire_bytes
    assert c.status()["outbox_items"] == 1
    assert admit(c, payload=message(temperature=45)).duplicate
    assert c.status()["outbox_items"] == 1
    assert not c.ledger.db.execute("SELECT 1 FROM n4_state WHERE key LIKE 'outgoing_%'").fetchone()


@pytest.mark.parametrize("stage", ["after_reservation", "after_reduction", "before_commit"])
def test_admission_fault_rolls_back_facts_policy_reservation_and_counters(factory, stage):
    c = factory(policy=InformationPolicyConfig(max_message_bytes=1))
    def fault(point, db):
        if point == stage:
            raise RuntimeError("injected")
    c.ledger.fault = fault
    with pytest.raises(RuntimeError, match="injected"):
        admit(c)
    assert not c.ledger.records() and not c.ledger.facts()
    assert c.status()["outbox_items"] == 0
    assert c.status()["reserved_wire_bytes"] == 0
    assert not c.engine.action_counts
    c.ledger.fault = lambda *args: None
    assert admit(c).ingress_sequence == 1


def test_committed_but_lost_reply_is_idempotent(factory):
    c = factory()
    c.ledger.fault = lambda point, db: (_ for _ in ()).throw(RuntimeError("lost reply")) if point == "after_commit" else None
    with pytest.raises(RuntimeError, match="lost reply"):
        admit(c)
    receipt = admit(c)
    assert receipt.duplicate and receipt.ingress_sequence == 1
    assert c.engine.action_counts == {"DELAY": 1}


def test_restart_restores_reservations_queue_and_recovery_capsule(factory):
    c = factory()
    admit(c)
    path, epoch = c.ledger.path, c.ledger.epoch
    c.ledger.close()
    recovered = factory(path=path, clock=FakeClock(20))
    assert recovered.ledger.epoch == epoch
    assert len(recovered.engine.queue) == 1
    row = recovered.ledger.db.execute("SELECT * FROM windows").fetchone()
    assert row["obligation"] == "EVIDENCE_READY"
    body = parse_artifact(recovered.sealer.seal(device_id=row["device"], window_index=row["idx"])).body
    assert body.closure_reason == "RECOVERY" and "INTERRUPTED" in body.coverage_limitations
    assert admit(recovered).duplicate


@pytest.mark.parametrize("stage", ["before_capsule_commit", "after_capsule_commit", "after_evidence_stage"])
def test_closure_fault_is_atomic_even_with_nested_sealer(factory, stage):
    c = factory()
    admit(c)
    c.ledger.clock.advance(10)
    def fault(point, db):
        if point == stage:
            raise RuntimeError("injected")
    c.ledger.fault = fault
    with pytest.raises(RuntimeError, match="injected"):
        c.ledger.tick()
    assert c.ledger.db.execute("SELECT closed FROM windows").fetchone()[0] == 0
    assert c.ledger.db.execute("SELECT COUNT(*) FROM sealed_capsules").fetchone()[0] == 0
    c.ledger.fault = lambda *args: None
    c.ledger.tick()
    assert c.ledger.db.execute("SELECT obligation FROM windows").fetchone()[0] == "EVIDENCE_READY"


def test_actual_signed_parts_repeats_and_headers_are_charged(factory):
    c = factory()
    admit(c)
    frames = drain(c, duration=12)
    evidence = [lease for lease in frames if lease.kind == "EVIDENCE"]
    assert evidence and all(len(x.payload) <= 1200 for x in evidence)
    counts = Counter(x.payload for x in evidence)
    assert set(counts.values()) == {c.config.evidence_repeats}
    assert sum(x.modeled_wire_bytes for x in frames) == c.status()["modeled_scheduled_bytes"]
    assert all(x.modeled_wire_bytes == len(x.payload) + x.framing_header_bytes + 28 for x in frames)
    row = c.ledger.db.execute("SELECT * FROM n4_intents").fetchone()
    assert sum(x.modeled_wire_bytes for x in evidence) == row["actual_wire"] <= row["wire"]
    assert c.status()["reserved_wire_bytes"] == 0
    assert c.status()["confirmed_receipt"] == "NOT_OBSERVED"


@pytest.mark.parametrize("stage,charged", [("before_service_commit", False), ("after_service_commit", True)])
def test_frame_grant_commit_and_unknown_local_attempt_fail_closed(factory, stage, charged):
    c = factory()
    admit(c)
    def fault(point, db):
        if point == stage:
            raise RuntimeError("lost grant")
    c.ledger.fault = fault
    with pytest.raises(RuntimeError, match="lost grant"):
        c.lease_frame()
    assert c.status()["local_lease_unresolved"] is charged
    assert bool(c.status()["modeled_scheduled_bytes"]) is charged
    path = c.ledger.path
    c.ledger.close()
    c = factory(path=path, clock=FakeClock(20))
    if charged:
        with pytest.raises(LedgerRefused, match="LOCAL_LEASE_UNRESOLVED"):
            c.lease_frame()
        row = c.ledger.db.execute("SELECT * FROM n4_inflight").fetchone()
        c.complete_local_attempt(row["lease"])
    else:
        assert c.lease_frame() is not None


@pytest.mark.parametrize("stage,retained", [("before_attempt_commit", True), ("after_attempt_commit", False)])
def test_local_attempt_commit_does_not_double_charge(factory, stage, retained):
    c = factory()
    admit(c)
    lease = c.lease_frame()
    charged = c.status()["modeled_scheduled_bytes"]
    c.ledger.fault = lambda point, db: (_ for _ in ()).throw(RuntimeError("lost completion")) if point == stage else None
    with pytest.raises(RuntimeError, match="lost completion"):
        c.complete_local_attempt(lease.lease_id)
    assert c.status()["local_lease_unresolved"] is retained
    assert c.status()["modeled_scheduled_bytes"] == charged


def test_concurrent_devices_and_critical_only_overflow_are_bounded(factory):
    c = factory(policy=InformationPolicyConfig(max_queue_size=4), config=AdmissionConfig(max_journal_records=24))
    def device_run(device):
        return [admit(c, retry=i, payload=message(device.device_id, telemetry_type=device.telemetry_type), priority="CRITICAL")
                for i in range(1, 21)]
    with ThreadPoolExecutor(max_workers=5) as workers:
        results = list(workers.map(device_run, CONTRACT.devices))
    assert all([r.ingress_sequence for r in rows] == list(range(1, 21)) for rows in results)
    assert len(c.ledger.records()) == 100 and len(c.engine.queue) == 4
    assert c.engine.action_counts["DROP"] == 96
    assert c.ledger.db.execute("SELECT SUM(overflow) FROM n4_scope_stats").fetchone()[0] == 96
    assert c.ledger.db.execute("SELECT COUNT(*) FROM n4_events").fetchone()[0] <= 24
    assert sum(f.accepted_count for f in c.ledger.facts()) >= 100
    assert any(x.kind == "RAW" for x in drain(c, duration=12))


def test_scope_limit_refuses_unaccepted_input_and_preserves_committed_facts(factory):
    c = factory(config=AdmissionConfig(max_observations_per_scope=2))
    admit(c, retry=1)
    admit(c, retry=2)
    with pytest.raises(LedgerRefused, match="SCOPE_OBSERVATION_CAPACITY"):
        admit(c, retry=3)
    assert len(c.ledger.records()) == 2
    assert c.ledger.facts()[0].accepted_count == 2
    assert c.status()["refused_unaccepted"] == 1


@pytest.mark.parametrize("config,error", [
    (AdmissionConfig(link_bytes_per_second=60000), "UNDERFUNDED_CONTRACT"),
    (AdmissionConfig(max_outbox_items=4), "UNDERFUNDED_STORAGE"),
    (AdmissionConfig(max_outbox_bytes=2048), "UNDERFUNDED_STORAGE"),
    (AdmissionConfig(service_cycle_seconds=5), "aligned 10-second"),
    (AdmissionConfig(datagram_payload_bytes=512), "UNDERFUNDED_CONTRACT"),
])
def test_impossible_configuration_fails_before_admission(config, error):
    with pytest.raises(ValueError, match=error):
        validate_budget(CONTRACT, "coverage-gateway", "coverage-key", config)


@pytest.mark.parametrize("traffic", ["critical", "mixed", "routine"])
def test_byte_quota_pacing_and_conditional_lane_progress(traffic):
    config = AdmissionConfig(link_bytes_per_second=65536)
    service = ByteService()
    lanes = {"critical": ("protected",), "routine": ("routine",), "mixed": LANES}[traffic]
    heads = {lane: 1000 for lane in lanes}
    grants = Counter()
    cycles = Counter()
    now = 0
    while now < 31_000_000:
        lane = service.choose(now, heads, config)
        if lane:
            grants[lane] += 1000
            cycles[now // 10_000_000] += 1000
            assert service.total_bytes <= config.link_bytes_per_second * now / 1_000_000 + config.max_wire_frame
        now = service.next_us if lane else (now // 10_000_000 + 1) * 10_000_000
    assert max(cycles.values()) <= config.cycle_bytes
    if traffic == "mixed":
        assert all(grants[lane] >= 3 * (config.quotas[lane] - config.max_wire_frame) for lane in lanes)
    else:
        assert grants[lanes[0]] > 3 * config.quotas[lanes[0]]


def test_idle_borrowing_returns_service_to_new_evidence_next_cycle():
    config, service = AdmissionConfig(link_bytes_per_second=65536), ByteService()
    evidence_remaining, started, finished = 50000, None, None
    for now in range(0, 41_000_000, 5000):
        heads = {"protected": 1000}
        if now >= 9_000_000 and evidence_remaining:
            started = started or now
            heads["evidence"] = 1000
        lane = service.choose(now, heads, config)
        if lane == "evidence":
            evidence_remaining -= 1000
            if not evidence_remaining:
                finished = now
    bound = ByteService.conditional_wait_bound(50000, "evidence", config)
    assert finished is not None and (finished - started) / 1_000_000 <= bound


@pytest.mark.parametrize("mutate", ["reservation", "policy", "outbox", "service"])
def test_corruption_refuses_recovery(factory, mutate):
    c = factory()
    admit(c)
    db = c.ledger.db
    if mutate == "reservation":
        db.execute("UPDATE n4_intents SET wire=wire-1")
    elif mutate == "policy":
        db.execute("UPDATE n4_state SET value='{}' WHERE key='engine'")
    elif mutate == "outbox":
        db.execute("UPDATE n4_outbox SET digest=?", ("0"*64,))
    else:
        state = asdict(ByteService())
        state["spent"]["evidence"] = 10**12
        db.execute("UPDATE n4_state SET value=? WHERE key='service'", (canonical_bytes(state),))
    path = c.ledger.path
    c.ledger.close()
    with pytest.raises((LedgerRefused, ValueError), match="CORRUPT"):
        factory(path=path, clock=FakeClock(20))


def test_retained_record_capacity_is_hard_even_for_critical_inputs(factory):
    c = factory(limits=LedgerLimits(max_retained_records=2))
    admit(c, retry=1, priority="CRITICAL")
    admit(c, retry=2, priority="CRITICAL")
    with pytest.raises(LedgerRefused):
        admit(c, retry=3, priority="CRITICAL")
    assert len(c.ledger.records()) == 2


def test_fixed_summaries_charge_same_actual_bytes_but_lack_advance_reservations(factory):
    coupled, fixed = factory(), factory(mode="fixed_summary_no_reservation")
    for controller in (coupled, fixed):
        for retry in range(1, 4):
            admit(controller, retry=retry, payload=message(temperature=45))
    assert coupled.status()["reserved_wire_bytes"] > 0 == fixed.status()["reserved_wire_bytes"]
    for controller in (coupled, fixed):
        frames = drain(controller, duration=12)
        assert controller.status()["modeled_scheduled_bytes"] == sum(x.modeled_wire_bytes for x in frames)
        row = controller.ledger.db.execute("SELECT * FROM n4_intents").fetchone()
        assert row["actual_wire"] > 0
    assert coupled.status()["modeled_scheduled_bytes"] == fixed.status()["modeled_scheduled_bytes"]


def test_fixed_summary_exposes_unsupported_scope_when_late_budget_is_exhausted(factory):
    config = AdmissionConfig(link_bytes_per_second=65536, max_evidence_debt_cycles=1)
    c = factory(config=config, mode="fixed_summary_no_reservation")
    for window in range(15):
        for device in CONTRACT.devices:
            admit(c, retry=window+1, payload=message(device.device_id, telemetry_type=device.telemetry_type))
        c.ledger.clock.advance(10)
        c.ledger.tick()
    assert c.status()["unsupported_scopes"] > 0
    assert c.ledger.db.execute("SELECT COUNT(*) FROM n4_events WHERE kind='UNSUPPORTED_FACTS'").fetchone()[0] > 0


def warm_congested(factory, **overrides):
    policy = InformationPolicyConfig(**{"prediction_enabled": False, "max_queue_size": 10,
        "elevated_threshold": .05, "congested_threshold": .1, "critical_threshold": .9, **overrides})
    c = factory(policy=policy)
    admit(c)
    lease = c.lease_frame()
    c.complete_local_attempt(lease.lease_id)
    c.ledger.clock.advance(1)
    admit(c, payload=message("edge-device-04", telemetry_type="security", event_type="INTRUSION_DETECTED"), priority="CRITICAL")
    c.ledger.clock.advance(1)
    return c


@pytest.mark.parametrize("action", ["SAMPLE", "AGGREGATE", "SUPERSEDE", "DROP"])
def test_every_irreversible_action_has_committed_original_facts_and_reservation(factory, action):
    c = warm_congested(factory, **({"critical_threshold": .2} if action == "SAMPLE" else {}))
    admit(c, retry=2, payload=message(temperature=26 if action == "SUPERSEDE" else 25.1))
    c.ledger.clock.advance(1)
    admit(c, retry=3, payload=message(temperature=27 if action == "SUPERSEDE" else 25.2))
    if action == "SAMPLE":
        c.ledger.clock.advance(1)
        admit(c, retry=4)
    elif action == "DROP":
        # Hard-capacity admission keeps predicate facts even when all queued work is protected.
        for retry in range(4, 18):
            admit(c, retry=retry, priority="CRITICAL")
    records = [json.loads(row[0]) for row in c.ledger.db.execute("SELECT body FROM n4_events WHERE kind='REDUCTION'")]
    assert any(record["action"] == action for record in records)
    assert c.ledger.facts()[0].accepted_count == len([r for r in c.ledger.records() if r["device"] == "edge-device-01"])
    assert all(r[0] in {"RESERVED", "EVIDENCE_READY"} for r in c.ledger.db.execute("SELECT obligation FROM windows"))
    assert c.status()["reserved_wire_bytes"] > 0


def test_aggregate_mean_cannot_replace_original_threshold_evidence(factory):
    policy = InformationPolicyConfig().model_dump()
    policy["novelty_scales"]["environmental"]["temperature"] = 200
    c = warm_congested(factory, novelty_scales=policy["novelty_scales"])
    admit(c, retry=2, payload=message(temperature=45))
    c.ledger.clock.advance(1)
    admit(c, retry=3, payload=message(temperature=25))
    aggregate = next(x for x in c.engine.queue if x.message.aggregation)
    assert aggregate.message.temperature == 35 < 38
    c.ledger.clock.advance(7)
    c.ledger.tick()
    row = c.ledger.db.execute("SELECT body FROM sealed_capsules WHERE device='edge-device-01'").fetchone()
    body = parse_artifact(row[0]).body
    assert body.per_condition_facts[0].matching_count == 1
    assert body.reduction_accounting.reduced_raw == 2
    facts = authenticated_facts(row[0], c.sealer._public_keys(), {c.ledger.digest: CONTRACT})
    assert facts[0].matching_count == 1 and facts[0].accepted_count == 3


def test_unfunded_next_window_rolls_back_reduction_instead_of_silently_accepting(factory):
    c = factory(config=AdmissionConfig(link_bytes_per_second=65536, max_evidence_debt_cycles=1),
                policy=InformationPolicyConfig(max_queue_size=3))
    for device in CONTRACT.devices:
        admit(c, payload=message(device.device_id, telemetry_type=device.telemetry_type), priority="CRITICAL")
    c.ledger.clock.advance(10)
    c.ledger.tick()
    # This fit at startup, but another full set without any service eventually cannot be admitted.
    refused = 0
    for window in range(1, 10):
        for device in CONTRACT.devices:
            try:
                admit(c, retry=window+1, payload=message(device.device_id, telemetry_type=device.telemetry_type))
            except LedgerRefused as exc:
                assert exc.reason == "EVIDENCE_FORWARD_BUDGET_UNSUPPORTED"
                refused += 1
        c.ledger.clock.advance(10)
        c.ledger.tick()
    assert refused and c.status()["unsupported_scopes"] == 0
    assert len(c.ledger.records()) + refused == 50
    assert c.status()["outbox_items"] <= c.config.max_outbox_items


@pytest.mark.parametrize("repeat", [1, 2, 8])
def test_dense_contract_cost_bound_includes_two_witnesses_and_worst_identifiers(repeat):
    from tests.test_coverage_capsules import KEY, InputRecord, build_capsule, record, sign_artifact, split_artifact
    from shared.coverage.contracts import contract_hash
    from shared.coverage.models import WindowIdentity
    data = CONTRACT.model_dump(mode="json")
    data["conditions"] = [{**data["conditions"][0], "condition_id": "c" + str(i).zfill(63)} for i in range(64)]
    data["rules"] = [{"rule_id": "one", "expression": {"kind": "ATOM", "condition_id": data["conditions"][0]["condition_id"]}}]
    contract = RuleContract.model_validate(data)
    config = AdmissionConfig(evidence_repeats=repeat)
    cost = worst_evidence_cost(contract, "edge-device-01", "g"*64, "k"*64, config)
    scope = WindowIdentity(ledger_epoch="e"*64, device_id="edge-device-01", window_index=0, contract_hash=contract_hash(contract))
    originals = [InputRecord.model_validate({**record(45, sequence=i+1).model_dump(), "ledger_epoch": scope.ledger_epoch}) for i in range(2)]
    encoded = sign_artifact(build_capsule(contract=contract, window=scope, records=originals, gateway_id="g"*64,
        signing_key_id="k"*64, created_at_utc_us=10000000), KEY)
    parts = split_artifact(encoded, KEY)
    assert len(encoded) <= cost.logical_bytes and len(parts) <= cost.frames
    assert sum(len(x)+28 for x in parts)*repeat <= cost.wire_bytes
    assert max(map(len, parts)) <= cost.frame_bytes


def test_reduction_fault_restores_existing_candidate_not_just_empty_state(factory):
    c = warm_congested(factory)
    admit(c, retry=2)
    queue = canonical_bytes([x.message.model_dump(mode="json") for x in c.engine.queue])
    count = len(c.ledger.records())
    c.ledger.fault = lambda point, db: (_ for _ in ()).throw(RuntimeError("failed aggregate")) if point == "after_reduction" else None
    with pytest.raises(RuntimeError, match="failed aggregate"):
        admit(c, retry=3)
    assert len(c.ledger.records()) == count
    assert canonical_bytes([x.message.model_dump(mode="json") for x in c.engine.queue]) == queue
    c.ledger.fault = lambda *args: None
    assert admit(c, retry=3).ingress_sequence == 3


def test_outgoing_sequence_and_signed_raw_work_survive_restart(factory):
    c = factory()
    admit(c)
    lease = c.lease_frame()
    state = json.loads(c._state("outgoing_edge-device-01"))
    encoded = bytes(c.ledger.db.execute("SELECT body FROM n4_outbox WHERE kind='RAW'").fetchone()[0])
    c.complete_local_attempt(lease.lease_id)
    path = c.ledger.path
    c.ledger.close()
    c = factory(path=path, clock=FakeClock(20))
    admit(c, retry=2)
    for lease in drain(c, duration=1):
        if lease.kind == "RAW":
            assert json.loads(lease.payload)["sequence_number"] == state["sequence"] + 1
    assert json.loads(c._state("outgoing_edge-device-01"))["sequence"] == 2
    assert json.loads(b"".join(unpack_frames(encoded)))["sequence_number"] == 1


def test_compaction_waits_for_both_raw_work_and_evidence(factory, tmp_path):
    directory = tmp_path / "edge-state"
    directory.mkdir()
    c = factory(path=directory / "ledger.db")
    receipt = admit(c)
    c.ledger.clock.advance(10)
    c.ledger.tick()
    scope = {"epoch": c.ledger.epoch, "device_id": receipt.device_id, "window_index": receipt.window_index}
    archive = tmp_path / "raw-archive.json"
    c.ledger.export_closed_window(**scope, path=archive)
    with pytest.raises(LedgerRefused, match="UNFULFILLED"):
        c.ledger.archive_closed_window(**scope, archive_path=archive)
    drain(c, duration=2)
    c.ledger.archive_closed_window(**scope, archive_path=archive)
    assert c.ledger.compact() == 1
    assert c.ledger.db.execute("SELECT COUNT(*) FROM n4_sources").fetchone()[0] == 0
    with pytest.raises(LedgerRefused, match="OLD_RETRY"):
        admit(c)
    admit(c, retry=2)


def test_disk_full_after_reservation_cannot_acknowledge_admission(factory):
    c = factory()
    def full(point, db):
        if point == "after_reservation":
            current = db.execute("PRAGMA page_count").fetchone()[0]
            db.execute("PRAGMA max_page_count="+str(current))
            db.execute("INSERT INTO n4_events(kind,body) VALUES ('FILL',zeroblob(1000000))")
    c.ledger.fault = full
    with pytest.raises(LedgerRefused, match="STORAGE_UNAVAILABLE"):
        admit(c)
    assert not c.ledger.records()
    assert c.ledger.db.execute("SELECT COUNT(*) FROM n4_intents").fetchone()[0] == 0
    with pytest.raises(LedgerRefused, match="LEDGER_REOPEN_REQUIRED"):
        admit(c)


@pytest.mark.parametrize("mutation", ["negative-counter", "missing-source", "refs", "lease-cost", "window-reservation"])
def test_recovery_rejects_inconsistent_accounting_and_original_bindings(factory, mutation):
    c = factory()
    admit(c)
    db = c.ledger.db
    if mutation == "negative-counter":
        state = json.loads(c._state("engine"))
        state["generated"] = -1
        db.execute("UPDATE n4_state SET value=? WHERE key='engine'", (canonical_bytes(state),))
    elif mutation == "missing-source":
        db.execute("DELETE FROM n4_sources")
    elif mutation == "refs":
        db.execute("UPDATE n4_outbox SET refs='[]'")
    elif mutation == "window-reservation":
        db.execute("UPDATE windows SET reserved_bytes=reserved_bytes-1")
    else:
        c.lease_frame()
        db.execute("UPDATE n4_inflight SET cost=cost-1")
    path = c.ledger.path
    c.ledger.close()
    with pytest.raises(LedgerRefused, match="CORRUPT"):
        factory(path=path, clock=FakeClock(20))


@pytest.mark.parametrize("stage,accepted", [("after_reservation", False), ("after_reduction", False), ("after_commit", True)])
def test_real_process_termination_preserves_atomic_obligation(tmp_path, stage, accepted):
    path = tmp_path / "crash.db"
    key = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    program = """
import os, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shared.coverage.admission import CoupledAdmission
from shared.coverage.ledger import ObservationLedger
from shared.traffic.information import InformationPolicyConfig
from tests.test_coverage_ledger import CONTRACT, FakeClock, message
s=ObservationLedger(Path(sys.argv[1]), CONTRACT, create=True, clock=FakeClock())
c=CoupledAdmission(s,'coverage-gateway','coverage-key',Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sys.argv[2])),
    policy=InformationPolicyConfig(max_message_bytes=1))
def fault(point,db):
    if point==sys.argv[3]: os._exit(77)
s.fault=fault
c.admit(message(),expected_epoch=s.epoch,retry_sequence=1)
"""
    result = subprocess.run([sys.executable, "-c", program, str(path), seed, stage], cwd=ROOT,
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 77, result.stderr
    s = ObservationLedger(path, CONTRACT, clock=FakeClock(20))
    try:
        c = CoupledAdmission(s, "coverage-gateway", "coverage-key", key, policy=InformationPolicyConfig(max_message_bytes=1))
        assert len(s.records()) == int(accepted)
        assert c.status()["outbox_items"] == int(accepted)
        if accepted:
            assert admit(c).duplicate and s.facts()[0].accepted_count == 1
        else:
            assert admit(c).ingress_sequence == 1
    finally:
        s.close()


def test_gateway_opt_in_uses_coupled_local_path_and_no_http_feedback(tmp_path, monkeypatch):
    folder = tmp_path / "research"
    provisioned = initialize(folder, ROOT / "config/rule_coverage.json", "software-data-diode-coverage")
    monkeypatch.setenv("RULE_COVERAGE_ENABLED", "true")
    monkeypatch.setenv("COVERAGE_ADMISSION_MODE", "coupled")
    monkeypatch.setenv("COVERAGE_PROJECT_NAME", "software-data-diode-coverage")
    monkeypatch.setenv("COVERAGE_LEDGER_PATH", str(folder / "observations.sqlite3"))
    monkeypatch.setenv("COVERAGE_CONTRACT_PATH", str(ROOT / "config/rule_coverage.json"))
    monkeypatch.setenv("COVERAGE_ADMISSION_CONFIG", str(ROOT / "config/rule_coverage_admission.json"))
    gateway = load_service_module("edge-gateway")
    monkeypatch.setattr(gateway, "_get_private_key", lambda: Ed25519PrivateKey.generate())
    monkeypatch.setattr(gateway.httpx, "AsyncClient", Mock(side_effect=AssertionError("no Fog feedback")))
    from datetime import datetime, timezone
    payload = message().model_copy(update={"timestamp": datetime.now(timezone.utc)}).model_dump(mode="json")
    headers = {"X-Coverage-Epoch": provisioned["epoch"], "X-Coverage-Retry-Sequence": "1"}
    with TestClient(gateway.app) as client:
        assert client.get("/ready").json()["mode"] == "coupled"
        response = client.post("/telemetry", json=payload, headers=headers)
        assert response.status_code == 200 and response.json()["disposition"] == "SELECTED_RAW"
        assert gateway._policy_task is None and gateway._observability_task is None
        assert client.get("/metrics/runtime").json()["coverage_admission"]["reserved_wire_bytes"] > 0
    assert gateway._coverage_controller is None


@pytest.mark.parametrize("capacity", [65536, 131072, 10**9])
def test_pacing_keeps_fractional_credit_without_creating_free_bytes(capacity):
    config, service = AdmissionConfig(link_bytes_per_second=capacity), ByteService()
    now, total = 0, 0
    for index in range(3000):
        cost = 28 + index % 1100
        lane = service.choose(now, {"protected": cost}, config)
        if lane:
            total += cost
            assert total <= capacity*now/1_000_000+config.max_wire_frame
            now = service.next_us
        else:
            now = max(service.next_us, (now//10_000_000+1)*10_000_000)
        service.validate(config)
    assert service.total_bytes == total


def test_mixed_flood_preserves_evidence_progress_with_finite_raw_evictions(factory):
    c = factory(policy=InformationPolicyConfig(max_queue_size=8, prediction_enabled=False))
    for retry in range(1, 41):
        for index, device in enumerate(CONTRACT.devices):
            admit(c, retry=retry, payload=message(device.device_id, telemetry_type=device.telemetry_type),
                  priority="CRITICAL" if index % 2 == 0 else "LOW")
    assert len(c.engine.queue) <= 8 and c.engine.action_counts["DROP"] > 0
    c.ledger.clock.advance(10)
    c.ledger.tick()
    leases = drain(c, duration=10, step=.02)
    assert {lease.kind for lease in leases} == {"RAW", "EVIDENCE"}
    assert c.ledger.db.execute("SELECT COUNT(*) FROM windows WHERE obligation='LOCAL_ATTEMPTED'").fetchone()[0] == 5
    assert c.status()["modeled_scheduled_bytes"] <= c.config.cycle_bytes
    assert len(c.ledger.records()) == 200


def test_small_trace_comparator_has_matched_scope_config_and_actual_byte_budget():
    from scripts.check_coverage_admission import run_case
    coupled = run_case("coupled", service_available=True, windows=2)
    fixed = run_case("fixed_summary_no_reservation", service_available=True, windows=2)
    assert coupled["trace_sha256"] == fixed["trace_sha256"]
    assert coupled["config"] == fixed["config"]
    for metric in ("accepted", "modeled_bytes", "evidence_modeled_bytes", "raw_modeled_bytes"):
        assert coupled[metric] == fixed[metric]
    assert coupled["offered"] == coupled["accepted"] == 10
    assert coupled["unsupported_scopes"] == fixed["unsupported_scopes"] == 0

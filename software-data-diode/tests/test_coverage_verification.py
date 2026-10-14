import asyncio
from dataclasses import replace
import json
import time
from unittest.mock import Mock

import pytest

from scripts.verify_n6_persistence import fixture_artifact
from shared.coverage.capsules import EvidenceError, sign_artifact, build_transition
from shared.coverage.fog_store import FogEvidenceStore
from shared.coverage.research_replay import ResearchReplayStore
from shared.coverage.transport import PartAssembler
from shared.coverage.udp_runtime import FogUDP
from shared.coverage.verification import FogEvidenceVerifier
from shared.security.crypto import canonical_bytes
from tests.test_coverage_transport import framer as framer
from tests.conftest import load_service_module
from fastapi.testclient import TestClient


@pytest.fixture
def now():
    return time.time_ns()//1000


def evidence(framer, now, **kwargs):
    return fixture_artifact(framer, now//10000000-1, **kwargs)


def test_typed_scope_assurance_parts_and_minimal_facts(framer, now):
    artifact = evidence(framer, now)
    result = FogEvidenceVerifier(framer).verify(artifact.encoded, received_us=now, frames=artifact.frames)
    assert result.status == "VALID" and result.assurance_level == "AUTHENTICATED_SUMMARY"
    assert "HIDDEN_INPUTS_NOT_RECOMPUTED" in result.reason_codes
    assert result.part_count == len(artifact.frames) and result.part_completion == "COMPLETE"
    assert result.observation_scope == "accepted_normalized_gateway_ingress"
    assert result.continuity_status == "UNASSESSED"


@pytest.mark.parametrize("mutation", ["signature", "schema", "noncanonical", "counts", "identity", "epoch", "contract", "device"])
def test_invalid_assertions_never_change_valid_spooled_evidence(tmp_path, framer, now, mutation):
    a = evidence(framer, now)
    document = json.loads(a.encoded)
    body = document["body"]
    if mutation == "signature":
        document["signature"] = "A"*88
    elif mutation == "schema":
        del body["time_basis"]
    elif mutation == "counts":
        body["per_condition_facts"][0]["matching_count"] += 1
    elif mutation == "identity":
        body["capsule_id"] = "f"*64
    elif mutation == "epoch":
        body["ledger_epoch"] = "not-approved"
    elif mutation == "contract":
        body["contract_hash"] = "e"*64
    elif mutation == "device":
        body["device_id"] = "wrong-device"
    bad = json.dumps(document, indent=2).encode() if mutation == "noncanonical" else canonical_bytes(document)
    store = FogEvidenceStore(tmp_path/"replay.db", framer, now_us=lambda: now)
    try:
        assert store.accept(a)
        with pytest.raises(EvidenceError):
            store.accept(replace(a, encoded=bad))
        assert store.status()["pending_evidence"] == 1
        assert bytes(store.evidence_pending()["body"]) == a.encoded
    finally:
        store.close()


def test_freshness_window_and_part_completion_checked(framer, now):
    a = evidence(framer, now)
    verifier = FogEvidenceVerifier(framer)
    with pytest.raises(EvidenceError, match="EXPIRED"):
        verifier.verify(a.encoded, received_us=now+301000000, frames=a.frames)
    with pytest.raises(EvidenceError, match="PART"):
        verifier.verify(a.encoded, received_us=now)
    with pytest.raises(EvidenceError):
        verifier.verify(a.encoded, received_us=now, frames=a.frames[:-1])
    with pytest.raises(EvidenceError, match="DUPLICATE"):
        verifier.verify(a.encoded, received_us=now, frames=(*a.frames, a.frames[0]))
    old = fixture_artifact(framer, now//10000000-40, created=now)
    with pytest.raises(EvidenceError, match="EXPIRED_EVIDENCE_WINDOW"):
        verifier.verify(old.encoded, received_us=now, frames=old.frames)


def test_valid_scope_forks_are_durably_retained_for_pg_quarantine(tmp_path, framer, now):
    path = tmp_path/"replay.db"
    a, fork = evidence(framer, now), evidence(framer, now, value=15)
    assert a.identity == fork.identity and a.encoded != fork.encoded
    store = FogEvidenceStore(path, framer, now_us=lambda: now)
    assert store.accept(a) and not store.accept(a) and store.accept(fork)
    store.close()
    store = FogEvidenceStore(path, framer, now_us=lambda: now)
    try:
        assert store.status()["pending_evidence"] == 2
        repository = Mock()
        repository.save_coverage_evidence.side_effect = ["ACCEPTED", "CONFLICT"]
        assert store.publish_one(repository) == "ACCEPTED"
        assert store.publish_one(repository) == "CONFLICT"
        assert store.status()["pending_evidence"] == 0
    finally:
        store.close()


def test_db_outage_and_lost_completion_recover_without_refreshing_receipt(tmp_path, framer, now):
    path = tmp_path/"replay.db"
    a = evidence(framer, now)
    store = FogEvidenceStore(path, framer, now_us=lambda: now)
    assert store.accept(a)
    repository = Mock()
    repository.save_coverage_evidence.side_effect = OSError("database down")
    with pytest.raises(OSError):
        store.publish_one(repository)
    assert store.status()["pending_evidence"] == 1
    # Lost completion after the PG transaction commits must not change signed
    # bytes or the original successful Fog receipt's freshness assessment.
    repository.save_coverage_evidence.side_effect = None
    repository.save_coverage_evidence.return_value = "ACCEPTED"
    store.evidence_completed = Mock(side_effect=OSError("crash after PG commit"))
    with pytest.raises(OSError):
        store.publish_one(repository)
    store.close()
    store = FogEvidenceStore(path, framer, now_us=lambda: now+400000000)
    repository.save_coverage_evidence.return_value = "DUPLICATE"
    try:
        assert store.publish_one(repository) == "DUPLICATE"
        assert repository.save_coverage_evidence.call_args.args[1].received_at_utc_us == now
        assert not store.status()["pending_evidence"]
        with pytest.raises(EvidenceError, match="EXPIRED"):
            store.accept(a)
    finally:
        store.close()


def test_n5_rows_imported_without_inventing_part_or_receipt_verification(tmp_path, framer, now):
    path = tmp_path/"replay.db"
    a = evidence(framer, now)
    old = ResearchReplayStore(path, framer, now_us=lambda: now)
    assert old.accept(a)
    old.close()
    store = FogEvidenceStore(path, framer, now_us=lambda: now+400000000)
    try:
        repository = Mock()
        repository.save_coverage_evidence.return_value = "ACCEPTED"
        assert store.publish_one(repository) == "ACCEPTED"
        record = repository.save_coverage_evidence.call_args.args[1]
        assert record.status == "LIMITED" and record.part_completion == "LEGACY_RETAINED_BODY"
        assert "HISTORICAL_N5_RECEIPT_TIME_UNAVAILABLE" in record.limitations
        assert store.db.execute("SELECT COUNT(*) FROM records WHERE kind='EVIDENCE'").fetchone()[0] == 1
    finally:
        store.close()
    store = FogEvidenceStore(path, framer, now_us=lambda: now+410000000)
    assert store.status()["pending_evidence"] == 0
    store.close()


def test_spool_limits_atomic_rollback_and_persisted_window_floor(tmp_path, framer, now):
    framer.config = framer.config.model_copy(update={"replay_records": 32})
    store = FogEvidenceStore(tmp_path/"replay.db", framer, now_us=lambda: now)
    try:
        a = evidence(framer, now)
        for i in range(32):
            assert store.accept(evidence(framer, now, value=40+i*.01))
        with pytest.raises(EvidenceError, match="CAPACITY"):
            store.accept(evidence(framer, now, value=70))
        assert store.status()["pending_evidence"] == 32
        repository = Mock()
        repository.save_coverage_evidence.return_value = "ACCEPTED"
        for _ in range(32):
            store.publish_one(repository)
        store.db.execute("DELETE FROM evidence_work WHERE pending=0")
        stale = fixture_artifact(framer, a.sequence-31, created=now)
        with pytest.raises(EvidenceError, match="EXPIRED_EVIDENCE_WINDOW"):
            store.accept(stale)
        store.retire_epoch()
        with pytest.raises(EvidenceError, match="RETIRED"):
            store.accept(a)
    finally:
        store.close()


def test_reassembly_expiry_is_bounded_persistable_outcome(tmp_path, framer, now):
    ticks = [0]
    assembler = PartAssembler(framer, monotonic=lambda: ticks[0])
    a = evidence(framer, now)
    assert assembler.add(a.frames[0]) is None
    ticks[0] = 6
    assembler.expire()
    assert assembler.expiry_events[0]["received_parts"] == 1
    assert assembler.expiry_events[0]["expected_parts"] == len(a.frames)
    store = FogEvidenceStore(tmp_path/"replay.db", framer, now_us=lambda: now)
    try:
        store.record_outcome("REASSEMBLY_EXPIRED", details=assembler.expiry_events[0])
        store.record_outcome("REASSEMBLY_EXPIRED", details=assembler.expiry_events[0])
        assert store.status()["pending_verification_outcomes"] == 1
        repository = Mock()
        assert store.publish_one(repository) == "OUTCOME_COMMITTED"
        assert repository.save_coverage_outcome.call_args.args[0]["reason_code"] == "REASSEMBLY_EXPIRED"
    finally:
        store.close()


def test_signed_transition_does_not_change_pinned_contract(framer, now):
    body = build_transition(gateway_id=framer.profile.gateway_id, signing_key_id=framer.profile.signing_key_id,
        ledger_epoch=framer.profile.ledger_epoch, previous_contract_hash=framer.profile.contract_hash,
        next_contract_hash="f"*64, effective_window_index=now//10000000+1, created_at_utc_us=now)
    with pytest.raises(EvidenceError, match="UNPROVISIONED_CONTRACT"):
        FogEvidenceVerifier(framer).verify(sign_artifact(body, framer.private_key), received_us=now)
    from shared.coverage.contracts import contract_hash
    next_contract = framer.contract.model_copy(update={"contract_id": "operator-next-test"})
    next_hash = contract_hash(next_contract)
    framer.contracts[next_hash] = next_contract
    body = build_transition(gateway_id=framer.profile.gateway_id, signing_key_id=framer.profile.signing_key_id,
        ledger_epoch=framer.profile.ledger_epoch, previous_contract_hash=framer.profile.contract_hash,
        next_contract_hash=next_hash, effective_window_index=now//10000000+1, created_at_utc_us=now)
    with pytest.raises(EvidenceError, match="OPERATOR_CONTRACT_TRANSITION_REQUIRED"):
        FogEvidenceVerifier(framer).verify(sign_artifact(body, framer.private_key), received_us=now)
    assert framer.profile.contract_hash != next_hash


def test_async_shutdown_waits_for_uncancellable_storage(tmp_path, framer, now):
    async def run():
        store = FogEvidenceStore(tmp_path/"replay.db", framer, now_us=lambda: now)
        runtime = FogUDP(framer, store, Mock(), "")
        completed = []
        def slow_commit():
            time.sleep(.06)
            store.record_outcome("SHUTDOWN_CHECK")
            completed.append(True)
        task = asyncio.create_task(runtime._offload(slow_commit))
        runtime.tasks.append(task)
        await asyncio.sleep(.01)
        await runtime.close()
        assert completed == [True]
        assert store.status()["pending_verification_outcomes"] == 1
        store.close()
    asyncio.run(run())


def test_sqlite_failure_after_body_insert_rolls_back_all_acceptance(tmp_path, framer, now):
    import sqlite3
    store = FogEvidenceStore(tmp_path/"fog.db", framer, now_us=lambda: now)
    try:
        store.db.execute("""CREATE TRIGGER fail_head BEFORE INSERT ON heads WHEN NEW.kind='EVIDENCE'
            BEGIN SELECT RAISE(ABORT,'injected storage failure after evidence insertion'); END""")
        with pytest.raises(sqlite3.Error):
            store.accept(evidence(framer, now))
        assert store.db.execute("SELECT COUNT(*) FROM evidence_work").fetchone()[0] == 0
        assert store.db.execute("SELECT COUNT(*) FROM heads").fetchone()[0] == 0
        store.db.execute("DROP TRIGGER fail_head")
        assert store.accept(evidence(framer, now))
    finally:
        store.close()


def test_recovered_scope_cannot_reset_spool_floor_after_cache_eviction(tmp_path, framer, now):
    from shared.coverage.models import CoverageLimitation
    store = FogEvidenceStore(tmp_path/"fog.db", framer, now_us=lambda: now)
    a = evidence(framer, now)
    assert store.accept(a)
    store.evidence_completed(store.evidence_pending()["digest"])
    store.db.execute("DELETE FROM evidence_work WHERE pending=0")
    store.close()
    store = FogEvidenceStore(tmp_path/"fog.db", framer, now_us=lambda: now)
    try:
        stale = fixture_artifact(framer, a.sequence-40, created=now, closure_reason="RECOVERY", limitations=(CoverageLimitation.INTERRUPTED,))
        with pytest.raises(EvidenceError, match="STALE_RESEARCH"):
            store.accept(stale)
        assert store.status()["pending_evidence"] == 0
    finally:
        store.close()


def test_outcome_queue_is_bounded_and_cannot_starve_evidence(tmp_path, framer, now):
    framer.config = framer.config.model_copy(update={"replay_records": 32})
    store = FogEvidenceStore(tmp_path/"fog.db", framer, now_us=lambda: now)
    try:
        for i in range(8):
            store.record_outcome("INVALID_SCHEMA", str(i).encode())
        with pytest.raises(EvidenceError, match="OUTCOME_SPOOL_CAPACITY"):
            store.record_outcome("INVALID_SCHEMA", b"excess")
        assert store.accept(evidence(framer, now))
        repository = Mock()
        repository.save_coverage_evidence.return_value = "ACCEPTED"
        assert store.publish_one(repository) == "ACCEPTED"
        assert store.publish_one(repository) == "OUTCOME_COMMITTED"
        assert store.status()["pending_verification_outcomes"] == 7
    finally:
        store.close()


def test_n6_readiness_is_local_capacity_not_database_feedback(monkeypatch):
    service = load_service_module("fog-receiver")
    monkeypatch.setattr(service, "research_udp_enabled", lambda: True)
    state = {"live": True, "local_admission_available": True, "evidence_database_available": False}
    monkeypatch.setattr(service, "_research_udp", Mock(status=lambda: state))
    monkeypatch.setattr(service.httpx, "AsyncClient", Mock(side_effect=AssertionError("no reverse readiness")))
    client = TestClient(service.app)
    assert client.get("/ready").status_code == 200
    state["local_admission_available"] = False
    assert client.get("/ready").status_code == 503


def test_insufficient_spool_config_fails_before_creating_state(tmp_path, framer):
    framer.config = framer.config.model_copy(update={"replay_bytes": 128*1024})
    with pytest.raises(ValueError, match="spool budget"):
        FogEvidenceStore(tmp_path/"never-created.db", framer)
    assert not list(tmp_path.iterdir())


def test_spool_at_rest_mutation_refused_on_restart(tmp_path, framer, now):
    path = tmp_path/"fog.db"
    store = FogEvidenceStore(path, framer, now_us=lambda: now)
    assert store.accept(evidence(framer, now))
    store.db.execute("UPDATE evidence_work SET body=?", (b"{}",))
    store.close()
    with pytest.raises(EvidenceError):
        FogEvidenceStore(path, framer, now_us=lambda: now)


def test_runtime_window_zero_is_not_a_replay_reset(framer, now):
    from shared.coverage.models import CoverageLimitation
    a = fixture_artifact(framer, 0, created=now, closure_reason="RECOVERY", limitations=(CoverageLimitation.INTERRUPTED,))
    with pytest.raises(EvidenceError, match="UNSUPPORTED_RESEARCH_WINDOW_INDEX"):
        FogEvidenceVerifier(framer).verify(a.encoded, received_us=now, frames=a.frames)


@pytest.mark.parametrize("device", ["edge-device-01", "edge-device-02", "edge-device-03", "edge-device-04", "edge-device-05"])
def test_condition_set_metric_compatibility_and_missing_metrics_all_devices(framer, now, device):
    a = evidence(framer, now, device=device)
    record = FogEvidenceVerifier(framer).verify(a.encoded, received_us=now, frames=a.frames)
    assert record.device_id == device
    facts = json.loads(a.encoded)["body"]["per_condition_facts"]
    expected = {c.condition_id for c in framer.contract.conditions if c.device_id == device}
    assert {f["condition_id"] for f in facts} == expected
    if device in {"edge-device-02", "edge-device-03", "edge-device-04"}:
        assert all(f["unresolved_count"] == 1 for f in facts)


def test_no_input_authentication_does_not_issue_a_false_verdict(framer, now):
    a = evidence(framer, now, empty=True)
    record = FogEvidenceVerifier(framer).verify(a.encoded, received_us=now, frames=a.frames)
    assert record.status == "VALID" and "verdict" not in record.model_dump()
    assert json.loads(a.encoded)["body"]["scope_kind"] == "NO_INPUT"


def test_evidence_query_is_fog_only_bounded_and_unavailable_database_is_visible(monkeypatch):
    service = load_service_module("fog-receiver")
    monkeypatch.setattr(service, "_research_udp", None)
    client = TestClient(service.app)
    assert client.get("/research/evidence").status_code == 404
    monkeypatch.setattr(service, "_research_udp", Mock())
    repository = Mock()
    repository.coverage_evidence.return_value = []
    monkeypatch.setattr(service, "repository", repository)
    assert client.get("/research/evidence?limit=101").status_code == 422
    response = client.get("/research/evidence?limit=5")
    assert response.json() == {"evidence": [], "rule_evaluation": "NOT_IMPLEMENTED_N6"}
    repository.coverage_evidence.assert_called_once_with(5)
    repository.coverage_evidence.side_effect = OSError("database down")
    assert client.get("/research/evidence").status_code == 503

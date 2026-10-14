import asyncio
from collections import Counter
from dataclasses import replace
import hashlib
import socket
from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest
from fastapi.testclient import TestClient

from shared.coverage.admission import CoupledAdmission
from shared.coverage.budget import AdmissionConfig, unpack_frames
from shared.coverage.capsules import EvidenceError
from shared.coverage.contracts import contract_hash
from shared.coverage.ledger import ObservationLedger
from shared.coverage.research_replay import ResearchReplayStore
from shared.coverage.transport import (HEADER, PartAssembler, ResearchFramer, SeededFaultAdapter, TrustProfile)
from shared.coverage.udp_runtime import ReceiveOnlyUDP, SendOnlyUDP
from shared.security.crypto import canonical_bytes
from tests.conftest import load_service_module, make_signed_envelope
from tests.test_coverage_ledger import CONTRACT, EPOCH, FakeClock, message


@pytest.fixture
def framer():
    key = Ed25519PrivateKey.generate()
    public = key.public_key()
    profile = TrustProfile(gateway_id="coverage-gateway", signing_key_id="coverage-key", ledger_epoch="test-epoch",
        contract_hash=contract_hash(CONTRACT), public_key_sha256=hashlib.sha256(public.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest())
    return ResearchFramer(profile, public, CONTRACT, private_key=key)


def raw(framer, sequence=1, **values):
    encoded = canonical_bytes(make_signed_envelope(framer.private_key, device_id="edge-device-01", sequence_number=sequence,
        created_at=EPOCH, **values).model_dump(mode="json"))
    return framer.raw_frames(encoded)


def test_binary_frame_header_exact_cost_and_reverse_reassembly(framer):
    assert HEADER.size == 128
    frames = raw(framer, measurements={"x"+str(i): float(i) for i in range(70)})
    assert len(frames) > 1 and all(len(frame) <= 1200 for frame in frames)
    receiver = PartAssembler(framer)
    artifact = None
    for frame in reversed(frames):
        artifact = receiver.add(frame) or artifact
    assert artifact.kind == "RAW" and artifact.device == "edge-device-01"
    assert not receiver.pending
    assert framer.raw_frames(artifact.encoded) == frames


@pytest.mark.parametrize("offset", [0, 4, 20, 52, 54, 56, 60, 64, 127, 128, -1])
def test_all_header_meaning_signature_and_chunk_mutations_rejected(framer, offset):
    wire = bytearray(raw(framer)[0])
    wire[offset] ^= 1
    with pytest.raises(EvidenceError):
        PartAssembler(framer).add(bytes(wire))


def test_epoch_signature_binding_prevents_unapproved_epoch(framer):
    profile = framer.profile.model_copy(update={"ledger_epoch": "future-unapproved-epoch"})
    other = ResearchFramer(profile, framer.public_key, CONTRACT, private_key=framer.private_key)
    with pytest.raises(EvidenceError, match="SCOPE"):
        PartAssembler(framer).add(raw(other)[0])


def test_partial_expiry_capacity_and_oversize_never_request_missing_parts(framer):
    clock = [0]
    config = framer.config.model_copy(update={"partial_artifacts": 1})
    framer.config = config
    assembler = PartAssembler(framer, monotonic=lambda: clock[0])
    frames = raw(framer, measurements={"x"+str(i): float(i) for i in range(100)})
    assert assembler.add(frames[0]) is None
    other = raw(framer, sequence=2, measurements={"x"+str(i): float(i) for i in range(100)})
    with pytest.raises(EvidenceError, match="CAPACITY"):
        assembler.add(other[0])
    clock[0] = 6
    assembler.expire()
    assert assembler.expired == 1 and not assembler.pending
    with pytest.raises(EvidenceError, match="OVERSIZED"):
        assembler.add(b"x"*1201)
    assert assembler.add(frames[-1]) is None


def test_seeded_faults_reproducible_bounded_and_missing_parts_stay_missing(framer):
    frames = raw(framer, measurements={"x"+str(i): float(i) for i in range(100)})
    def trace():
        adapter = SeededFaultAdapter(93, drop=.1, duplicate=.8, max_delay_steps=5, max_pending=8)
        output = []
        for _ in range(15):
            for frame in frames:
                output.extend(adapter.feed(frame))
                assert len(adapter.pending) <= 8
        return output
    assert trace() == trace()
    assembler = PartAssembler(framer)
    assert assembler.add(frames[0]) is None
    assert assembler.add(frames[0]) is None
    assert len(assembler.pending) == 1


def test_reorder_duplicates_restart_stale_window_and_retired_epoch(tmp_path, framer):
    now = int(EPOCH.timestamp()*1000000)
    framer.config = framer.config.model_copy(update={"replay_width": 8})
    path = tmp_path/"replay.db"
    store = ResearchReplayStore(path, framer, now_us=lambda: now)
    try:
        a10, a8 = framer.decode_binary(raw(framer, 10)), framer.decode_binary(raw(framer, 8))
        assert store.accept(a10) and store.accept(a8)
        assert not store.accept(a8)
        store.close()
        store = ResearchReplayStore(path, framer, now_us=lambda: now)
        assert not store.accept(a10)
        with pytest.raises(EvidenceError, match="STALE"):
            store.accept(framer.decode_binary(raw(framer, 1)))
        with pytest.raises(EvidenceError, match="FORK"):
            store.accept(framer.decode_binary(raw(framer, 8)))
        with pytest.raises(EvidenceError, match="EXPIRED"):
            store.accept(replace(a10, identity="new", stamp_us=now-301000000))
        store.retire_epoch()
        with pytest.raises(EvidenceError, match="RETIRED"):
            store.accept(framer.decode_binary(raw(framer, 11)))
    finally:
        store.close()


def test_replay_capacity_rolls_back_highwater_and_no_reset_of_anchored_store(tmp_path, framer):
    framer.config = framer.config.model_copy(update={"replay_records": 32})
    path = tmp_path/"replay.db"
    store = ResearchReplayStore(path, framer, now_us=lambda: int(EPOCH.timestamp()*1000000))
    try:
        for seq in range(1, 33):
            store.accept(framer.decode_binary(raw(framer, seq)))
        with pytest.raises(EvidenceError, match="CAPACITY"):
            store.accept(framer.decode_binary(raw(framer, 33)))
        assert store.db.execute("SELECT high FROM heads").fetchone()[0] == 32
        assert store.status()["received_artifacts"] == 32
    finally:
        store.close()
    path.unlink()
    with pytest.raises(ValueError, match="anchored"):
        ResearchReplayStore(path, framer)


def test_empty_or_aging_forward_state_does_not_certify_rule_coverage(tmp_path, framer):
    now = [int(EPOCH.timestamp()*1000000)]
    store = ResearchReplayStore(tmp_path/"receiver.db", framer, now_us=lambda: now[0])
    try:
        assert store.status()["edge_state_stale"] and store.status()["coverage_evidence_stale_or_missing"]
        body = canonical_bytes({"protocol": "rccd-state-v1", "kind": "EDGE_STATE", "profile": framer.profile.model_dump(mode="json"),
            "sequence": 1, "timestamp_us": now[0], "metrics": {"accepted_observations": 0}})
        artifact = framer.decode_binary(framer.frames(body, framer.state_identity(1), b"RCS1"))
        assert store.accept(artifact)
        assert not store.status()["edge_state_stale"]
        assert store.status()["coverage_evidence_stale_or_missing"] and store.status()["coverage"] == "NOT_EVALUATED_N5"
        now[0] += 31_000_000
        assert store.status()["edge_state_stale"]
    finally:
        store.close()


@pytest.mark.parametrize("early", [True, False])
def test_sequential_clock_sampling_at_boundary_defers_not_halts(early):
    from shared.coverage.windows import WindowSchedule
    from datetime import datetime, timezone, timedelta
    clock = FakeClock()
    clock.utc = datetime(1970, 1, 1, tzinfo=timezone.utc)+timedelta(microseconds=9999000)
    schedule = WindowSchedule(clock)
    clock.utc = datetime(1970, 1, 1, tzinfo=timezone.utc)+timedelta(microseconds=10000000 if early else 9999999)
    clock.ns = schedule.deadline_ns-1 if early else schedule.deadline_ns+1
    assert schedule.poll().closed_window is None and not schedule.halted
    clock.utc = datetime(1970, 1, 1, tzinfo=timezone.utc)+timedelta(microseconds=10000001)
    clock.ns = schedule.deadline_ns+2000
    update = schedule.poll()
    assert update.closed_window.window_index == 0 and update.active_window_index == 1


def coupled(tmp_path, framer):
    store = ObservationLedger(tmp_path/"edge.db", CONTRACT, create=True, clock=FakeClock())
    profile = framer.profile.model_copy(update={"ledger_epoch": store.epoch})
    framer = ResearchFramer(profile, framer.public_key, CONTRACT, private_key=framer.private_key)
    return CoupledAdmission(store, profile.gateway_id, profile.signing_key_id, framer.private_key, framer=framer)


def test_budgeted_immutable_raw_state_capsules_and_recovery(tmp_path, framer):
    c = coupled(tmp_path, framer)
    try:
        c.admit(message(), expected_epoch=c.ledger.epoch, retry_sequence=1)
        assert c.publish_forward_state() and not c.publish_forward_state()
        assembled, grants = PartAssembler(c.framer), []
        for _ in range(1300):
            lease = c.lease_frame()
            if lease:
                grants.append(lease)
                assembled.add(lease.payload)
                assert lease.modeled_wire_bytes == len(lease.payload)+28 and not lease.framing_header_bytes
                c.complete_local_attempt(lease.lease_id)
            c.ledger.clock.advance(.01)
        assert {lease.kind for lease in grants} == {"RAW", "STATE", "EVIDENCE"}
        assert sum(lease.modeled_wire_bytes for lease in grants) == c.status()["modeled_scheduled_bytes"]
        assert c.status()["confirmed_receipt"] == "NOT_OBSERVED"
        assert c.publish_forward_state()
        lease = c.lease_frame()
        if lease is None:
            c.ledger.clock.advance(1)
            lease = c.lease_frame()
        assert lease
        encoded = c.ledger.db.execute("SELECT body FROM n4_outbox WHERE id=?", (lease.work_id,)).fetchone()[0]
        charged = c.status()["modeled_scheduled_bytes"]
        path, profile, key = c.ledger.path, c.framer.profile, c.key
        c.ledger.close()
        store = ObservationLedger(path, CONTRACT, clock=FakeClock(20))
        framer = ResearchFramer(profile, key.public_key(), CONTRACT, private_key=key)
        c = CoupledAdmission(store, profile.gateway_id, profile.signing_key_id, key, framer=framer)
        assert c.status()["modeled_scheduled_bytes"] == charged
        assert c.retire_uncertain_lease()
        assert not c.retire_uncertain_lease()
        assert c.status()["modeled_scheduled_bytes"] == charged
        assert any(row[0] == "LOCAL_ATTEMPT_UNCERTAIN" for row in store.db.execute("SELECT kind FROM n4_events"))
        assert all(len(x) <= 1200 for x in unpack_frames(encoded))
    finally:
        c.ledger.close()


def test_extra_state_cost_rejects_underfunded_research_startup(tmp_path, framer):
    store = ObservationLedger(tmp_path/"edge.db", CONTRACT, create=True, clock=FakeClock())
    framer.profile = framer.profile.model_copy(update={"ledger_epoch": store.epoch})
    try:
        with pytest.raises(ValueError, match="UNDERFUNDED"):
            CoupledAdmission(store, framer.profile.gateway_id, framer.profile.signing_key_id, framer.private_key,
                framer=framer, config=AdmissionConfig(link_bytes_per_second=65536))
    finally:
        store.close()


def test_receive_queue_is_bounded_and_has_no_reply_api():
    async def run():
        queue, counts = asyncio.Queue(maxsize=1), Counter()
        protocol = ReceiveOnlyUDP(queue, 1200, counts, {"127.0.0.1"})
        protocol.datagram_received(b"first", ("127.0.0.1", 1))
        protocol.datagram_received(b"second", ("127.0.0.1", 1))
        protocol.datagram_received(b"unauthorized", ("10.0.0.1", 1))
        protocol.datagram_received(b"x"*1201, ("127.0.0.1", 1))
        assert counts["queue_overflow_drops"] == 1 and counts["size_or_source_drops"] == 2
        assert await queue.get() == b"first"
        assert not hasattr(protocol, "sendto")
    asyncio.run(run())


def test_real_loopback_receiver_emits_no_udp_application_response(framer):
    async def run():
        queue, counts = asyncio.Queue(maxsize=4), Counter()
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: ReceiveOnlyUDP(queue, 1200, counts, {"127.0.0.1"}), local_addr=("127.0.0.1", 0))
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.setblocking(False)
        try:
            sender.sendto(raw(framer)[0], transport.get_extra_info("sockname"))
            assert await asyncio.wait_for(queue.get(), 1)
            await asyncio.sleep(.05)
            with pytest.raises(BlockingIOError):
                sender.recvfrom(1200)
        finally:
            sender.close()
            transport.close()
    asyncio.run(run())


def test_udp_sender_unavailable_destination_attempts_do_not_wait_or_receive():
    async def run():
        sender = SendOnlyUDP("127.0.0.1", 9)
        try:
            sender.address = None
            sender.attempt(b"one")
            sender.attempt(b"two")
            assert sender.counts["attempts"] == sender.counts["local_send_errors"] == 2
            assert not hasattr(sender, "receive")
        finally:
            await sender.close()
    asyncio.run(run())


def test_diode_udp_readiness_never_queries_fog_http(monkeypatch):
    for name in ("data-diode", "fog-receiver"):
        service = load_service_module(name)
        monkeypatch.setattr(service, "research_udp_enabled", lambda: True)
        monkeypatch.setattr(service, "_research_udp", Mock(status=lambda: {"live": True}))
        monkeypatch.setattr(service.httpx, "AsyncClient", Mock(side_effect=AssertionError("no cross-boundary readiness")))
        client = TestClient(service.app)
        assert client.get("/ready").status_code == 200
        path = "/ingest" if name == "data-diode" else "/receive"
        assert client.post(path, json={}).status_code == 404


def test_profile_provisioning_preserves_epoch_and_device_counters(tmp_path, private_key, monkeypatch):
    from shared.coverage.provisioning import provision
    from shared.edge.coverage_client import research_headers
    public = tmp_path/"public.pem"
    # Write a test public key only; deployment credentials are untouched.
    public.write_bytes(private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    profile = provision(tmp_path/"edge", tmp_path/"trust", CONTRACT_PATH, public, "software-data-diode-coverage")
    assert provision(tmp_path/"edge", tmp_path/"trust", CONTRACT_PATH, public, "software-data-diode-coverage") == profile
    ledger = ObservationLedger(tmp_path/"edge/observations.sqlite3", CONTRACT, clock=FakeClock())
    try:
        assert provision(tmp_path/"edge", tmp_path/"trust", CONTRACT_PATH, public, "software-data-diode-coverage") == profile
        assert ledger.epoch == profile.ledger_epoch
    finally:
        ledger.close()
    monkeypatch.setenv("COVERAGE_TRUST_PATH", str(tmp_path/"trust/profile.json"))
    monkeypatch.setenv("COVERAGE_DEVICE_STATE_PATH", str(tmp_path/"counter.db"))
    assert research_headers("edge-device-01")["X-Coverage-Retry-Sequence"] == "1"
    assert research_headers("edge-device-01")["X-Coverage-Retry-Sequence"] == "2"


from pathlib import Path
CONTRACT_PATH = Path(__file__).resolve().parents[1]/"config/rule_coverage.json"


def test_research_compose_keeps_ledger_private_and_control_paths_disabled():
    import yaml
    class Loader(yaml.SafeLoader):
        pass
    def override(loader, node):
        return loader.construct_sequence(node) if isinstance(node, yaml.SequenceNode) else loader.construct_mapping(node)
    Loader.add_constructor("!override", override)
    doc = yaml.load((CONTRACT_PATH.parents[1]/"docker-compose.coverage.yml").read_text(), Loader=Loader)
    services = doc["services"]
    assert doc["name"] == "software-data-diode-coverage"
    assert services["edge-gateway"]["ports"] == ["127.0.0.1:38000:8000"]
    assert services["dashboard"]["ports"] == ["127.0.0.1:38501:8501"]
    assert "fog-receiver" not in services["data-diode"]["depends_on"]
    assert "127.0.0.1" in services["data-diode"]["command"]
    assert not any("coverage-ledger" in mount for mount in services["fog-receiver"]["volumes"])
    assert services["prometheus-edge"]["networks"] == ["diode-network", "edge-host-network"]
    assert services["grafana"]["profiles"] == ["coverage-disabled"]

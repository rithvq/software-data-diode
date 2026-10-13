"""Atomic Edge-local reduction/reservation and a bounded outbox. No sockets."""
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sqlite3
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from pydantic import Field

from shared.http import strict_json
from shared.models import PriorityLevel, SecureTelemetryEnvelope, TelemetryPayload
from shared.security.crypto import (canonical_bytes, compute_payload_hash, sign_envelope,
                                    verify_envelope_signature)
from shared.traffic.information import InformationEngine, InformationPolicyConfig, PolicyAction

from .budget import (AdmissionConfig, LANES, pack_frames, unpack_frames, validate_budget)
from .capsules import MAX_INPUT_SCOPE_BYTES, RawAccounting, artifact_digest, parse_artifact
from .ledger import LedgerRefused
from .models import FrozenModel
from .parts import assemble_parts, split_artifact
from .policy_state import candidate_document, checkpoint, restore
from .sealing import CapsuleSealer
from .service import ByteService
from .windows import utc_microseconds


MODES = ("coupled", "fixed_summary_no_reservation")


class FrameLease(FrozenModel):
    lease_id: str
    work_id: str
    lane: str
    kind: str
    payload: bytes = Field(repr=False)
    modeled_wire_bytes: int
    framing_header_bytes: int
    grant_utc_us: int
    assurance: str = "LOCAL_SERVICE_MODEL_NOT_RECEIPT"


def policy_identity(epoch, device, sequence):
    return str(uuid5(NAMESPACE_URL, canonical_bytes([epoch, device, sequence]).decode("utf-8")))


class CoupledAdmission:
    def __init__(self, ledger, gateway_id, key_id, private_key, *, config=None, policy=None, mode="coupled"):
        if mode not in MODES:
            raise ValueError("unknown coverage admission mode")
        self.ledger, self.config, self.mode = ledger, config or AdmissionConfig(), mode
        self.costs = validate_budget(ledger.contract, gateway_id, key_id, self.config, coupled=mode == "coupled")
        policy = policy or InformationPolicyConfig()
        if policy.window_seconds != 10:
            raise ValueError("research policy requires 10-second local state")
        document = policy.model_dump(mode="json")
        document["link_bytes_per_second"] = self.config.link_bytes_per_second
        document["max_streams"] = min(policy.max_streams, self.config.max_policy_streams)
        document["max_queue_size"] = min(policy.max_queue_size, self.config.max_raw_candidates)
        self.policy = InformationPolicyConfig.model_validate(document)
        self.guard = lambda action, item, related: self._guard(action, item, related)
        self._working = None
        with ledger._mutex:
            ledger._ensure_open()
            if ledger.admission_hook is not None:
                raise LedgerRefused("COUPLED_WRITER_ALREADY_ATTACHED")
            present = ledger.db.execute("SELECT value FROM metadata WHERE key='coupled_schema_version'").fetchone()
            if not present and ledger.db.execute("SELECT COUNT(*) FROM observations").fetchone()[0]:
                raise LedgerRefused("FRESH_COUPLED_STORE_REQUIRED")
            self.sealer = CapsuleSealer(ledger, gateway_id, key_id, private_key)
            self.key = private_key
            binding = hashlib.sha256(canonical_bytes({"mode": mode, "admission": self.config.model_dump(mode="json"),
                                                      "policy": self.policy.model_dump(mode="json")})).hexdigest()
            with ledger._transaction():
                if not present:
                    self._initialize(binding)
                elif ledger._meta("coupled_config_hash") != binding:
                    raise LedgerRefused("COUPLED_CONFIGURATION_MISMATCH")
                self.engine = self._load_engine()
                self._anchor_us = int(self._state("logical_us"))
                self._start_ns = ledger.clock.monotonic_ns()
                self._last_ns = self._start_ns
                self._verify_recovery()
                for row in ledger.db.execute("SELECT epoch,device,idx FROM windows WHERE closed=1 AND obligation IN ('RESERVED','UNSIZED') ORDER BY idx,device").fetchall():
                    self._stage_scope(tuple(row))
                self._assert_bounds()
            ledger._coupled = True
            ledger.admission_hook = self._on_admission
            ledger.closure_hook = self._stage_scope
            ledger.retirement_hook = self._retirement_guard

    def _initialize(self, binding):
        db = self.ledger.db
        definitions = (
            "CREATE TABLE n4_state (key TEXT PRIMARY KEY,value BLOB NOT NULL)",
            "CREATE TABLE n4_intents (epoch TEXT,device TEXT,idx INTEGER,wire INTEGER,packed INTEGER,logical INTEGER,actual_wire INTEGER DEFAULT 0,actual_logical INTEGER DEFAULT 0,PRIMARY KEY(epoch,device,idx),FOREIGN KEY(epoch,device,idx) REFERENCES windows(epoch,device,idx) ON DELETE CASCADE)",
            "CREATE TABLE n4_sources (id TEXT PRIMARY KEY,epoch TEXT,device TEXT,seq INTEGER,FOREIGN KEY(epoch,device,seq) REFERENCES observations(epoch,device,seq) ON DELETE CASCADE)",
            "CREATE TABLE n4_scope_stats (epoch TEXT,device TEXT,idx INTEGER,overflow INTEGER DEFAULT 0,dispatch INTEGER DEFAULT 0,PRIMARY KEY(epoch,device,idx),FOREIGN KEY(epoch,device,idx) REFERENCES windows(epoch,device,idx) ON DELETE CASCADE)",
            "CREATE TABLE n4_outbox (id TEXT PRIMARY KEY,kind TEXT,lane TEXT,body BLOB,digest TEXT,cursor INTEGER,repeats INTEGER,header INTEGER,refs TEXT,created INTEGER)",
            "CREATE TABLE n4_inflight (slot INTEGER PRIMARY KEY CHECK(slot=1),lease TEXT,work TEXT,cursor INTEGER,cost INTEGER,FOREIGN KEY(work) REFERENCES n4_outbox(id))",
            "CREATE TABLE n4_events (number INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,body BLOB)")
        for definition in definitions:
            db.execute(definition)
        db.execute("INSERT INTO metadata VALUES ('coupled_schema_version','1')")
        db.execute("INSERT INTO metadata VALUES ('coupled_config_hash',?)", (binding,))
        engine = InformationEngine(self.policy)
        entries = {"engine": checkpoint(engine), "service": canonical_bytes(asdict(ByteService())),
                   "logical_us": b"0", "refused": b"0"}
        db.executemany("INSERT INTO n4_state VALUES (?,?)", entries.items())

    def _state(self, key):
        row = self.ledger.db.execute("SELECT value FROM n4_state WHERE key=?", (key,)).fetchone()
        if row is None:
            raise LedgerRefused("CORRUPT_COUPLED_STATE")
        return row[0]

    def _set_state(self, key, value):
        self.ledger.db.execute("UPDATE n4_state SET value=? WHERE key=?", (value, key))

    def _load_engine(self):
        encoded = self._state("engine")
        if len(encoded) > self.config.max_policy_state_bytes:
            raise LedgerRefused("POLICY_STATE_CAPACITY")
        try:
            return restore(encoded, self.policy, self.guard)
        except (ValueError, TypeError, KeyError) as exc:
            raise LedgerRefused("CORRUPT_POLICY_STATE") from exc

    def _now(self):
        current = self.ledger.clock.monotonic_ns()
        if current < self._last_ns:
            raise LedgerRefused("LOCAL_SERVICE_CLOCK_DISCONTINUITY")
        self._last_ns = current
        return self._anchor_us+(current-self._start_ns)//1000

    def _event(self, kind, body):
        db = self.ledger.db
        db.execute("INSERT INTO n4_events(kind,body) VALUES (?,?)", (kind, canonical_bytes(body)))
        db.execute("DELETE FROM n4_events WHERE number NOT IN (SELECT number FROM n4_events ORDER BY number DESC LIMIT ?)",
                   (self.config.max_journal_records,))

    def _sources(self, item):
        result = []
        for identifier in item.source_ids:
            row = self.ledger.db.execute("SELECT o.*,w.obligation,w.reserved_bytes FROM n4_sources s JOIN observations o USING(epoch,device,seq) JOIN windows w USING(epoch,device,idx) WHERE s.id=?",
                                         (identifier,)).fetchone()
            if row is None:
                raise LedgerRefused("ORIGINAL_FACT_SCOPE_MISSING")
            result.append(row)
        return result

    def _guard(self, action, item, related):
        if not self.ledger.db.in_transaction:
            raise LedgerRefused("ATOMIC_POLICY_BOUNDARY_REQUIRED")
        rows = self._sources(item)
        if self.mode == "coupled":
            for row in rows:
                if row["obligation"] not in {"RESERVED", "EVIDENCE_READY", "LOCAL_ATTEMPTED"}:
                    raise LedgerRefused("UNSUPPORTED_EVIDENCE_OBLIGATION")
        disposition = "DROPPED_RAW" if action == PolicyAction.DROP else "REDUCED_RAW"
        for row in rows:
            self.ledger.db.execute("UPDATE observations SET disposition=? WHERE epoch=? AND device=? AND seq=?",
                                   (disposition, row["epoch"], row["device"], row["seq"]))
        self._event("REDUCTION", {"action": action.value, "sources": list(item.source_ids),
                                 "related": [value.message_id for value in related]})
        self.ledger.fault("after_reduction", self.ledger.db)

    def _on_admission(self, receipt, message):
        db = self.ledger.db
        key = (receipt.ledger_epoch, receipt.device_id, receipt.window_index)
        window = db.execute("SELECT * FROM windows WHERE epoch=? AND device=? AND idx=?", key).fetchone()
        if window["accepted"] > self.config.max_observations_per_scope:
            raise LedgerRefused("SCOPE_OBSERVATION_CAPACITY", 429)
        input_bytes = db.execute("SELECT SUM(size) FROM observations WHERE epoch=? AND device=? AND idx=?", key).fetchone()[0]
        if input_bytes > MAX_INPUT_SCOPE_BYTES:
            raise LedgerRefused("SCOPE_INPUT_BYTE_CAPACITY", 429)
        if not db.execute("SELECT 1 FROM n4_intents WHERE epoch=? AND device=? AND idx=?", key).fetchone():
            cost = self.costs[receipt.device_id]
            wire, packed, logical = (cost.wire_bytes, cost.packed_bytes, cost.logical_bytes) if self.mode == "coupled" else (0, 0, 0)
            db.execute("INSERT INTO n4_intents(epoch,device,idx,wire,packed,logical) VALUES (?,?,?,?,?,?)",
                       (*key, wire, packed, logical))
            db.execute("INSERT INTO n4_scope_stats(epoch,device,idx) VALUES (?,?,?)", key)
            if self.mode == "coupled":
                db.execute("UPDATE windows SET obligation='RESERVED',reserved_bytes=? WHERE epoch=? AND device=? AND idx=?",
                           (wire, *key))
        self._assert_bounds()
        self.ledger.fault("after_reservation", db)
        identifier = policy_identity(receipt.ledger_epoch, receipt.device_id, receipt.ingress_sequence)
        db.execute("INSERT INTO n4_sources VALUES (?,?,?,?)",
                   (identifier, receipt.ledger_epoch, receipt.device_id, receipt.ingress_sequence))
        previous = {item.message_id for item in self._working.queue}
        decision = self._working.submit(message, self._priority, self._now()/1000000,
                                         self.ledger.clock.utc_now(), message_id=identifier)
        # Count actual hard-queue drops, including a refused new raw candidate.
        dropped = previous-{item.message_id for item in self._working.queue}
        for record in list(self._working.decisions)[-2:]:
            if record["action"] == "DROP" and ("hard capacity" in record["reason"] or "queue admission" in record["reason"]):
                candidate_id = record["message_id"]
                if candidate_id == identifier or candidate_id in dropped:
                    for source_id in record["source_ids"]:
                        source = db.execute("SELECT o.epoch,o.device,o.idx FROM n4_sources s JOIN observations o USING(epoch,device,seq) WHERE s.id=?",
                                            (source_id,)).fetchone()
                        db.execute("UPDATE n4_scope_stats SET overflow=overflow+1 WHERE epoch=? AND device=? AND idx=?", tuple(source))
        self._sync_candidates()
        self._persist_engine()
        self._event("ADMISSION", {"policy_id": identifier, "action": decision["action"], "scope": list(key)})
        self._assert_bounds()

    def _persist_engine(self):
        encoded = checkpoint(self._working)
        if len(encoded) > self.config.max_policy_state_bytes:
            raise LedgerRefused("POLICY_STATE_CAPACITY", 429)
        self._set_state("engine", encoded)
        self._set_state("logical_us", str(self._now()).encode())

    def _envelope(self, item, sequence, created_at, message_id):
        payload = TelemetryPayload.model_validate(item.message.model_dump(mode="json", exclude={"device_id", "timestamp"}))
        return SecureTelemetryEnvelope(message_id=message_id, device_id=item.message.device_id,
            sequence_number=sequence, created_at=created_at, priority=item.priority, payload=payload,
            payload_hash=compute_payload_hash(payload), signature="A"*88,
            estimated_transmission_cost=float(item.size_bytes))

    def _sync_candidates(self):
        db, wanted = self.ledger.db, {item.message_id for item in self._working.queue}
        for row in db.execute("SELECT id FROM n4_outbox WHERE kind='CANDIDATE'").fetchall():
            if row[0] not in wanted:
                db.execute("DELETE FROM n4_outbox WHERE id=?", (row[0],))
        for item in self._working.queue:
            largest = self._envelope(item, 2**63-1, datetime.max.replace(tzinfo=timezone.utc), str(uuid4()))
            if len(canonical_bytes(largest.model_dump(mode="json"))) > self.config.max_raw_artifact_bytes:
                raise LedgerRefused("RAW_ARTIFACT_BOUND", 429)
            rows = self._sources(item)
            disposition = "REDUCED_RAW" if len(item.source_ids) > 1 else "SELECTED_RAW"
            for row in rows:
                db.execute("UPDATE observations SET disposition=? WHERE epoch=? AND device=? AND seq=?",
                           (disposition, row["epoch"], row["device"], row["seq"]))
            body = canonical_bytes(candidate_document(item))
            db.execute("INSERT INTO n4_outbox VALUES (?,?,?, ?,?,0,1,0,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body,digest=excluded.digest,refs=excluded.refs",
                (item.message_id, "CANDIDATE", "protected" if item.protected else "routine", body,
                 hashlib.sha256(body).hexdigest(), json.dumps(list(item.source_ids)), self._now()))

    def _accounting(self, key):
        counts = {row[0]: row[1] for row in self.ledger.db.execute(
            "SELECT disposition,COUNT(*) FROM observations WHERE epoch=? AND device=? AND idx=? GROUP BY disposition", key)}
        row = self.ledger.db.execute("SELECT * FROM n4_scope_stats WHERE epoch=? AND device=? AND idx=?", key).fetchone()
        return RawAccounting(pending_policy=counts.get("PENDING_POLICY", 0), selected_raw=counts.get("SELECTED_RAW", 0),
            reduced_raw=counts.get("REDUCED_RAW", 0), dropped_raw=counts.get("DROPPED_RAW", 0),
            archived_local=counts.get("ARCHIVED_LOCAL", 0), queue_overflow_drops=min(row["overflow"], counts.get("DROPPED_RAW", 0)),
            raw_dispatch_attempts=row["dispatch"])

    def _stage_scope(self, key):
        db = self.ledger.db
        row = db.execute("SELECT * FROM windows WHERE epoch=? AND device=? AND idx=?", key).fetchone()
        if row is None or row["obligation"] not in {"RESERVED", "UNSIZED"}:
            return
        encoded = self.sealer.seal(epoch=key[0], device_id=key[1], window_index=key[2], accounting=self._accounting(key))
        frames = split_artifact(encoded, self.key, max_datagram_bytes=self.config.datagram_payload_bytes)
        packed = pack_frames(frames)
        wire = sum(len(frame)+self.config.network_overhead_bytes for frame in frames)*self.config.evidence_repeats
        intent = db.execute("SELECT * FROM n4_intents WHERE epoch=? AND device=? AND idx=?", key).fetchone()
        if self.mode == "coupled" and (wire > intent["wire"] or len(packed) > intent["packed"] or len(encoded) > intent["logical"]):
            raise LedgerRefused("EVIDENCE_RESERVATION_UNDERESTIMATED")
        db.execute("UPDATE n4_intents SET actual_wire=?,actual_logical=? WHERE epoch=? AND device=? AND idx=?",
                   (wire, len(encoded), *key))
        db.execute("UPDATE windows SET obligation='EVIDENCE_READY',reserved_bytes=? WHERE epoch=? AND device=? AND idx=?",
                   (wire, *key))
        db.execute("INSERT INTO n4_outbox VALUES (?,?,?, ?,?,0,?,0,?,?)",
                   (artifact_digest(encoded), "EVIDENCE", "evidence", packed, hashlib.sha256(packed).hexdigest(),
                    self.config.evidence_repeats, json.dumps(list(key)), self._now()))
        if self.mode != "coupled":
            try:
                self._assert_bounds()
            except LedgerRefused:
                db.execute("DELETE FROM n4_outbox WHERE id=?", (artifact_digest(encoded),))
                db.execute("UPDATE windows SET obligation='UNSUPPORTED',reserved_bytes=0 WHERE epoch=? AND device=? AND idx=?", key)
                self._event("UNSUPPORTED_FACTS", {"scope": list(key), "accepted_count": row["accepted"],
                                                  "reason": "fixed summary could not obtain late outbox admission"})
        self.ledger.fault("after_evidence_stage", db)

    def _assert_bounds(self):
        db, config = self.ledger.db, self.config
        count, packed = db.execute("SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM n4_outbox").fetchone()
        intent = db.execute("SELECT COUNT(*),COALESCE(SUM(i.wire),0),COALESCE(SUM(i.packed),0),COALESCE(SUM(i.logical),0) FROM n4_intents i JOIN windows w USING(epoch,device,idx) WHERE w.obligation='RESERVED'").fetchone()
        cache_count, cache_bytes = db.execute("SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM sealed_capsules").fetchone()
        if count+intent[0] > config.max_outbox_items or packed+intent[2] > config.max_outbox_bytes:
            raise LedgerRefused("EVIDENCE_STORAGE_UNSUPPORTED", 429)
        if cache_count+intent[0] > self.sealer.limits.max_capsules or cache_bytes+intent[3] > self.sealer.limits.max_signed_bytes:
            raise LedgerRefused("SIGNED_EVIDENCE_RETENTION_CAPACITY", 429)
        debt = intent[1]
        for row in db.execute("SELECT * FROM n4_outbox WHERE kind='EVIDENCE'"):
            frames = unpack_frames(row["body"])
            debt += sum(len(frames[index % len(frames)])+config.network_overhead_bytes
                        for index in range(row["cursor"], len(frames)*row["repeats"]))
        if debt > config.quotas["evidence"]*config.max_evidence_debt_cycles:
            raise LedgerRefused("EVIDENCE_FORWARD_BUDGET_UNSUPPORTED", 429)

    def _verify_recovery(self):
        db = self.ledger.db
        if db.execute("SELECT COUNT(*) FROM n4_sources").fetchone()[0] != db.execute("SELECT COUNT(*) FROM observations").fetchone()[0]:
            raise LedgerRefused("CORRUPT_POLICY_SOURCE_POPULATION")
        if db.execute("SELECT COUNT(*) FROM n4_intents").fetchone()[0] != db.execute("SELECT COUNT(*) FROM windows").fetchone()[0]:
            raise LedgerRefused("CORRUPT_EVIDENCE_SCOPE_POPULATION")
        for row in db.execute("SELECT s.*,o.idx FROM n4_sources s JOIN observations o USING(epoch,device,seq)"):
            if row["id"] != policy_identity(row["epoch"], row["device"], row["seq"]):
                raise LedgerRefused("CORRUPT_POLICY_IDENTITY")
        for row in db.execute("SELECT i.*,w.obligation,w.reserved_bytes FROM n4_intents i JOIN windows w USING(epoch,device,idx)"):
            cost = self.costs[row["device"]]
            if self.mode == "coupled" and (row["wire"], row["packed"], row["logical"]) != (cost.wire_bytes, cost.packed_bytes, cost.logical_bytes):
                raise LedgerRefused("CORRUPT_EVIDENCE_RESERVATION")
            if self.mode == "coupled" and row["obligation"] in {"UNSIZED", "UNSUPPORTED"}:
                raise LedgerRefused("UNSUPPORTED_RECOVERED_FACTS")
            expected = row["wire"] if row["obligation"] == "RESERVED" else row["actual_wire"] if row["obligation"] == "EVIDENCE_READY" else 0
            if row["reserved_bytes"] != expected or min(row["actual_wire"], row["actual_logical"]) < 0:
                raise LedgerRefused("CORRUPT_EVIDENCE_RESERVATION")
        candidates = {item.message_id: item for item in self.engine.queue}
        recovered = set()
        for row in db.execute("SELECT * FROM n4_outbox"):
            if hashlib.sha256(row["body"]).hexdigest() != row["digest"] or row["lane"] not in LANES:
                raise LedgerRefused("CORRUPT_DURABLE_OUTBOX")
            if row["kind"] == "CANDIDATE":
                if row["id"] not in candidates or canonical_bytes(candidate_document(candidates[row["id"]])) != row["body"]:
                    raise LedgerRefused("POLICY_OUTBOX_MISMATCH")
                candidate = candidates[row["id"]]
                if (row["cursor"] != 0 or row["header"] != 0 or row["repeats"] != 1
                        or row["lane"] != ("protected" if candidate.protected else "routine")
                        or json.loads(row["refs"]) != list(candidate.source_ids)):
                    raise LedgerRefused("CORRUPT_CANDIDATE_METADATA")
                self._sources(candidate)
                recovered.add(row["id"])
            else:
                frames = unpack_frames(row["body"])
                if (type(row["repeats"]) is not int or not 1 <= row["repeats"] <= self.config.evidence_repeats
                        or not 0 <= row["cursor"] < len(frames)*row["repeats"]
                        or any(len(frame)+row["header"] > self.config.datagram_payload_bytes for frame in frames)):
                    raise LedgerRefused("CORRUPT_OUTBOX_CURSOR")
                if row["kind"] == "EVIDENCE":
                    encoded = assemble_parts(frames, self.sealer._public_keys(), {self.ledger.digest: self.ledger.contract},
                                             max_datagram_bytes=self.config.datagram_payload_bytes)
                    body = parse_artifact(encoded).body
                    key = (body.ledger_epoch, body.device_id, body.window_index)
                    scope = db.execute("SELECT w.obligation,i.actual_wire FROM windows w JOIN n4_intents i USING(epoch,device,idx) WHERE epoch=? AND device=? AND idx=?", key).fetchone()
                    wire = sum(len(frame)+self.config.network_overhead_bytes for frame in frames)*row["repeats"]
                    if (row["id"] != artifact_digest(encoded) or tuple(json.loads(row["refs"])) != key
                            or row["lane"] != "evidence" or row["header"] != 0
                            or row["repeats"] != self.config.evidence_repeats
                            or scope is None or scope["obligation"] != "EVIDENCE_READY" or scope["actual_wire"] != wire):
                        raise LedgerRefused("CORRUPT_EVIDENCE_WORK_BINDING")
                elif row["kind"] == "RAW":
                    encoded = b"".join(frames)
                    envelope = SecureTelemetryEnvelope.model_validate_json(encoded)
                    if not verify_envelope_signature(envelope, self.key.public_key()):
                        raise LedgerRefused("CORRUPT_RAW_SIGNATURE")
                    counter = strict_json(self._state("outgoing_"+envelope.device_id))
                    refs = json.loads(row["refs"])
                    if (len(encoded) > self.config.max_raw_artifact_bytes or row["header"] != self.config.raw_header_bytes
                            or row["repeats"] != 1 or row["lane"] not in {"protected", "routine"}
                            or not 1 <= len(refs) <= self.policy.aggregation_max_samples or len(set(refs)) != len(refs)
                            or envelope.sequence_number > counter["sequence"]
                            or utc_microseconds(envelope.created_at) > counter["stamp_us"]):
                        raise LedgerRefused("CORRUPT_RAW_WORK_BINDING")
                    for reference in refs:
                        source = db.execute("SELECT device FROM n4_sources WHERE id=?", (reference,)).fetchone()
                        if source is None or source["device"] != envelope.device_id:
                            raise LedgerRefused("CORRUPT_RAW_WORK_BINDING")
                else:
                    raise LedgerRefused("UNKNOWN_OUTBOX_KIND")
        if recovered != set(candidates):
            raise LedgerRefused("POLICY_OUTBOX_MISMATCH")
        self._service()
        lease = db.execute("SELECT l.*,o.body,o.header,o.cursor AS work_cursor,o.kind FROM n4_inflight l JOIN n4_outbox o ON o.id=l.work").fetchone()
        if db.execute("SELECT COUNT(*) FROM n4_inflight").fetchone()[0]:
            if (lease is None or str(UUID(lease["lease"])) != lease["lease"] or lease["kind"] == "CANDIDATE"
                    or lease["cursor"] != lease["work_cursor"]):
                raise LedgerRefused("CORRUPT_LOCAL_LEASE")
            frames = unpack_frames(lease["body"])
            cost = len(frames[lease["cursor"] % len(frames)])+lease["header"]+self.config.network_overhead_bytes
            if lease["cost"] != cost or cost > self._service().total_bytes:
                raise LedgerRefused("CORRUPT_LOCAL_LEASE")
        self._assert_bounds()

    def _service(self):
        try:
            service = ByteService(**strict_json(self._state("service")))
            service.validate(self.config)
            return service
        except (TypeError, ValueError, KeyError) as exc:
            raise LedgerRefused("CORRUPT_BYTE_SERVICE_STATE") from exc

    def admit(self, message, *, expected_epoch, retry_sequence, priority=PriorityLevel.LOW, freshness_seconds=None):
        ledger = self.ledger
        with ledger._mutex:
            self._working, self._priority = deepcopy(self.engine), PriorityLevel(priority)
            try:
                receipt = ledger.admit(message, expected_epoch=expected_epoch, retry_sequence=retry_sequence,
                                       freshness_seconds=freshness_seconds)
                self.engine = self._load_engine()
                return receipt
            except BaseException as exc:
                self.engine = self._load_engine()
                if isinstance(exc, LedgerRefused) and not ledger._failed:
                    try:
                        with ledger._transaction():
                            self._set_state("refused", str(int(self._state("refused"))+1).encode())
                            self._event("REFUSED_UNACCEPTED", {"device_id": message.device_id, "reason": exc.reason,
                                "input_hash": hashlib.sha256(canonical_bytes(message.model_dump(mode="json"))).hexdigest()})
                    except sqlite3.Error:
                        ledger._failed = True
                raise
            finally:
                self._working = None

    def _prepare_raw(self, lane):
        db = self.ledger.db
        if db.execute("SELECT 1 FROM n4_outbox WHERE kind='RAW' AND lane=?", (lane,)).fetchone():
            return
        selected = self._working.pop(self._now()/1000000,
            eligible=lambda item: ("protected" if item.protected else "routine") == lane, shaped=False)
        if selected is None:
            self._sync_candidates()
            return
        key = "outgoing_" + selected.message.device_id
        counter = db.execute("SELECT value FROM n4_state WHERE key=?", (key,)).fetchone()
        old = strict_json(counter[0]) if counter else {"sequence": 0, "stamp_us": -(2**63)}
        sequence = old["sequence"]+1
        stamp = max(utc_microseconds(self.ledger.clock.utc_now()), old["stamp_us"]+1)
        if sequence > 2**63-1:
            raise LedgerRefused("OUTGOING_SEQUENCE_EXHAUSTED")
        created = datetime(1970, 1, 1, tzinfo=timezone.utc)+timedelta(microseconds=stamp)
        envelope = self._envelope(selected, sequence, created, str(uuid4()))
        envelope = envelope.model_copy(update={"signature": sign_envelope(envelope, self.key)})
        encoded = canonical_bytes(envelope.model_dump(mode="json"))
        if len(encoded) > self.config.max_raw_artifact_bytes:
            raise LedgerRefused("RAW_ARTIFACT_BOUND")
        chunk = self.config.datagram_payload_bytes-self.config.raw_header_bytes
        packed = pack_frames(tuple(encoded[index:index+chunk] for index in range(0, len(encoded), chunk)))
        db.execute("INSERT INTO n4_state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                   (key, canonical_bytes({"sequence": sequence, "stamp_us": stamp})))
        db.execute("UPDATE n4_outbox SET kind='RAW',body=?,digest=?,header=? WHERE id=?",
                   (packed, hashlib.sha256(packed).hexdigest(), self.config.raw_header_bytes, selected.message_id))
        self._sync_candidates()

    def lease_frame(self):
        """Charge a local frame grant. An unresolved lease blocks further grants."""
        ledger = self.ledger
        with ledger._mutex:
            ledger._ensure_open()
            if ledger.db.execute("SELECT 1 FROM n4_inflight").fetchone():
                raise LedgerRefused("LOCAL_LEASE_UNRESOLVED")
            ledger.tick()
            if ledger.schedule.halted:
                raise LedgerRefused("CLOCK_DISCONTINUITY")
            if (not ledger.db.execute("SELECT 1 FROM n4_outbox").fetchone()
                    or self._now() < self._service().next_us):
                return None
            self._working = deepcopy(self.engine)
            try:
                with ledger._transaction():
                    self._prepare_raw("protected")
                    self._prepare_raw("routine")
                    heads = {}
                    for lane in LANES:
                        row = ledger.db.execute("SELECT * FROM n4_outbox WHERE lane=? AND kind!='CANDIDATE' ORDER BY created,id LIMIT 1", (lane,)).fetchone()
                        if row:
                            frames = unpack_frames(row["body"])
                            frame = frames[row["cursor"] % len(frames)]
                            heads[lane] = (row, frame, len(frame)+row["header"]+self.config.network_overhead_bytes)
                    service = self._service()
                    lane = service.choose(self._now(), {key: value[2] for key, value in heads.items()}, self.config)
                    self._set_state("service", canonical_bytes(asdict(service)))
                    self._persist_engine()
                    self._assert_bounds()
                    result = None
                    if lane:
                        row, frame, cost = heads[lane]
                        token = str(uuid4())
                        ledger.db.execute("INSERT INTO n4_inflight VALUES (1,?,?,?,?)", (token, row["id"], row["cursor"], cost))
                        result = FrameLease(lease_id=token, work_id=row["id"], lane=lane, kind=row["kind"],
                            payload=frame, modeled_wire_bytes=cost, framing_header_bytes=row["header"],
                            grant_utc_us=utc_microseconds(ledger.clock.utc_now()))
                    ledger.fault("before_service_commit", ledger.db)
                self.engine = self._load_engine()
                ledger.fault("after_service_commit", ledger.db)
                return result
            except sqlite3.Error as exc:
                ledger._failed = True
                raise LedgerRefused("STORAGE_UNAVAILABLE") from exc
            finally:
                self.engine = self._load_engine()
                self._working = None

    def complete_local_attempt(self, lease_id):
        """Local-only completion assertion; no receiver reply or success is accepted."""
        ledger = self.ledger
        with ledger._mutex, ledger._transaction():
            ledger._ensure_open()
            lease = ledger.db.execute("SELECT * FROM n4_inflight WHERE lease=?", (lease_id,)).fetchone()
            if lease is None:
                raise LedgerRefused("UNKNOWN_LOCAL_LEASE")
            row = ledger.db.execute("SELECT * FROM n4_outbox WHERE id=?", (lease["work"],)).fetchone()
            frames = unpack_frames(row["body"])
            cursor = row["cursor"]+1
            ledger.db.execute("DELETE FROM n4_inflight WHERE slot=1")
            if cursor == len(frames)*row["repeats"]:
                if row["kind"] == "EVIDENCE":
                    key = tuple(json.loads(row["refs"]))
                    ledger.db.execute("UPDATE windows SET obligation='LOCAL_ATTEMPTED',reserved_bytes=0 WHERE epoch=? AND device=? AND idx=?", key)
                else:
                    scopes = set()
                    for identifier in json.loads(row["refs"]):
                        source = ledger.db.execute("SELECT o.epoch,o.device,o.idx FROM n4_sources s JOIN observations o USING(epoch,device,seq) WHERE s.id=?", (identifier,)).fetchone()
                        scopes.add(tuple(source))
                    for key in scopes:
                        ledger.db.execute("UPDATE n4_scope_stats SET dispatch=dispatch+1 WHERE epoch=? AND device=? AND idx=?", key)
                ledger.db.execute("DELETE FROM n4_outbox WHERE id=?", (row["id"],))
            else:
                ledger.db.execute("UPDATE n4_outbox SET cursor=? WHERE id=?", (cursor, row["id"]))
            self._event("LOCAL_ATTEMPT", {"work_id": row["id"], "modeled_wire_bytes": lease["cost"], "cursor": cursor})
            ledger.fault("before_attempt_commit", ledger.db)
        ledger.fault("after_attempt_commit", ledger.db)

    def _retirement_guard(self, key):
        db = self.ledger.db
        if db.execute("SELECT obligation FROM windows WHERE epoch=? AND device=? AND idx=?", key).fetchone()[0] not in {"LOCAL_ATTEMPTED", "UNSUPPORTED"}:
            raise LedgerRefused("UNFULFILLED_EVIDENCE_OBLIGATION")
        for row in db.execute("SELECT kind,refs FROM n4_outbox"):
            if row["kind"] == "EVIDENCE" and tuple(json.loads(row["refs"])) == key:
                raise LedgerRefused("PENDING_SCOPE_WORK")
            if row["kind"] != "EVIDENCE":
                for identifier in json.loads(row["refs"]):
                    scope = db.execute("SELECT o.epoch,o.device,o.idx FROM n4_sources s JOIN observations o USING(epoch,device,seq) WHERE s.id=?", (identifier,)).fetchone()
                    if tuple(scope) == key:
                        raise LedgerRefused("PENDING_SCOPE_WORK")

    def status(self):
        with self.ledger._mutex:
            self.ledger._ensure_open()
            self._assert_bounds()
            db = self.ledger.db
            return {"mode": self.mode, "baseline_policy": InformationEngine.BASELINE_NAME,
                "outbox_items": db.execute("SELECT COUNT(*) FROM n4_outbox").fetchone()[0],
                "outbox_bytes": db.execute("SELECT COALESCE(SUM(length(body)),0) FROM n4_outbox").fetchone()[0],
                "reserved_wire_bytes": db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM windows").fetchone()[0],
                "unsupported_scopes": db.execute("SELECT COUNT(*) FROM windows WHERE obligation='UNSUPPORTED'").fetchone()[0],
                "refused_unaccepted": int(self._state("refused")), "local_lease_unresolved": bool(db.execute("SELECT 1 FROM n4_inflight").fetchone()),
                "modeled_scheduled_bytes": self._service().total_bytes, "confirmed_receipt": "NOT_OBSERVED"}

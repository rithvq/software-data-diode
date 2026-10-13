"""Edge-only bounded SQLite admission, with no reduction or transport work."""
from __future__ import annotations

from contextlib import contextmanager
from copy import copy
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
from threading import RLock
from uuid import uuid4

from pydantic import Field

from shared.http import strict_json
from shared.models import EdgeTelemetryMessage
from shared.security.crypto import canonical_bytes

from .contracts import contract_bytes, contract_hash
from .evaluation import condition_facts
from .models import (ConditionFacts, CoverageLimitation, FrozenModel, IngressObservation,
                     MetricReading, RuleContract, WindowIdentity)
from .windows import SystemClock, WindowSchedule, utc_microseconds


PROJECT_NAME = "software-data-diode-coverage"
PAGE_SIZE = 4096


class LedgerLimits(FrozenModel):
    max_input_bytes: int = Field(default=8192, strict=True, ge=256, le=65536)
    max_active_windows: int = Field(default=16, strict=True, ge=1, le=256)
    max_retained_windows: int = Field(default=256, strict=True, ge=1, le=10000)
    max_retained_records: int = Field(default=10000, strict=True, ge=1, le=1000000)
    max_pending_outbox_bytes: int = Field(default=16*1024*1024, strict=True, ge=1, le=1024**3)
    max_database_bytes: int = Field(default=32*1024*1024, strict=True, ge=128*1024, le=1024**3)


class LedgerRefused(RuntimeError):
    def __init__(self, reason: str, http_status: int = 503):
        self.reason, self.http_status = reason, http_status
        super().__init__(reason)


class AdmissionReceipt(FrozenModel):
    ledger_epoch: str
    device_id: str
    ingress_sequence: int
    window_index: int
    contract_hash: str
    input_hash: str
    duplicate: bool = False
    disposition: str = "PENDING_POLICY"


class ObservationLedger:
    """One OS-locked writer per store; threads serialize whole transactions.

    Provisioning is explicit. A missing store with an existing identity anchor
    cannot be auto-recreated. SQLite rollback journals keep disk use bounded
    without the unbounded-reader WAL retention problem.
    """
    def __init__(self, path: str | Path, contract: RuleContract, *, create: bool = False,
                 project_name: str = PROJECT_NAME, limits: LedgerLimits | None = None,
                 clock=None, fault=None):
        if project_name != PROJECT_NAME:
            raise LedgerRefused("RESEARCH_PROJECT_REQUIRED")
        supplied = Path(path).absolute()
        for candidate in (supplied, supplied.parent, Path(str(supplied)+".anchor.json"), Path(str(supplied)+".lock")):
            if candidate.is_symlink():
                raise LedgerRefused("SYMLINK_STATE_REFUSED")
        self.path, self.contract = supplied, contract
        self.digest, self.limits = contract_hash(contract), limits or LedgerLimits()
        self.clock, self.fault = clock or SystemClock(), fault or (lambda stage, db: None)
        self._mutex, self._closed, self._failed = RLock(), False, False
        self.admission_hook = self.closure_hook = self.retirement_hook = None
        self._coupled = False
        self._savepoint_number = 0
        self.db = self._lock_file = None
        self.anchor_path = Path(str(self.path)+".anchor.json")
        if not self.path.parent.is_dir():
            raise LedgerRefused("LEDGER_DIRECTORY_NOT_PROVISIONED")
        try:
            self._acquire_writer()
            if create:
                if self.path.exists() or self.anchor_path.exists():
                    raise LedgerRefused("EXISTING_IDENTITY_REFUSED")
                anchor = {"version": 1, "project": PROJECT_NAME, "store_id": str(uuid4())}
                with self.anchor_path.open("x", encoding="utf-8") as handle:
                    handle.write(canonical_bytes(anchor).decode("utf-8"))
                    handle.flush()
                    os.fsync(handle.fileno())
            elif not self.path.is_file() or not self.anchor_path.is_file():
                raise LedgerRefused("STORE_OR_IDENTITY_MISSING")
            with self.anchor_path.open("rb") as handle:
                anchor_bytes = handle.read(513)
            if len(anchor_bytes) > 512:
                raise LedgerRefused("FOREIGN_IDENTITY_REFUSED")
            anchor = strict_json(anchor_bytes)
            if (not isinstance(anchor, dict) or set(anchor) != {"version","project","store_id"}
                    or type(anchor["version"]) is not int or anchor["version"] != 1 or anchor["project"] != PROJECT_NAME):
                raise LedgerRefused("FOREIGN_IDENTITY_REFUSED")
            if self.path.exists() and self.path.stat().st_size > self.limits.max_database_bytes:
                raise LedgerRefused("DATABASE_LIMIT")
            self.db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False, timeout=2)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA page_size=4096")
            if self.db.execute("PRAGMA page_size").fetchone()[0] != PAGE_SIZE:
                raise LedgerRefused("UNSUPPORTED_PAGE_SIZE")
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA temp_store=MEMORY")
            self.db.execute(f"PRAGMA max_page_count={self.limits.max_database_bytes//PAGE_SIZE}")
            if create:
                self._initialize(anchor["store_id"])
            if self.db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise LedgerRefused("CORRUPT_LEDGER")
            if (self._meta("schema_version") != "1" or self._meta("store_id") != anchor["store_id"]
                    or self._meta("contract_hash") != self.digest):
                raise LedgerRefused("IDENTITY_OR_CONTRACT_MISMATCH")
            self._window_has_reason = "closure_reason" in {row["name"] for row in self.db.execute("PRAGMA table_info(windows)")}
            mode = self.db.execute("SELECT value FROM metadata WHERE key='coupled_schema_version'").fetchone()
            if mode and mode[0] != "1":
                raise LedgerRefused("UNSUPPORTED_COUPLED_STORE_VERSION")
            self._coupled = bool(mode)
            self.schedule = WindowSchedule(self.clock, jump_tolerance_us=contract.limits.clock_jump_tolerance_us,
                                           interrupted=not create)
            with self._transaction():
                if not create:
                    self._recover()
                self._check_limits()
                self._verify_recovered_state()
        except BaseException as exc:
            self.close()
            if isinstance(exc, (sqlite3.Error, OSError)):
                raise LedgerRefused("STORAGE_UNAVAILABLE") from exc
            raise

    def _acquire_writer(self):
        self._lock_file = Path(str(self.path)+".lock").open("a+b")
        self._lock_file.seek(0, os.SEEK_END)
        if self._lock_file.tell() == 0:
            self._lock_file.write(b"0")
            self._lock_file.flush()
        self._lock_file.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise LedgerRefused("WRITER_ALREADY_ACTIVE") from exc

    @contextmanager
    def _transaction(self):
        if self.db.in_transaction:
            self._savepoint_number += 1
            name = "coverage_nested_" + str(self._savepoint_number)
            self.db.execute("SAVEPOINT " + name)
            try:
                yield
                self.db.execute("RELEASE " + name)
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK TO " + name)
                    self.db.execute("RELEASE " + name)
                raise
            return
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def _meta(self, key):
        row = self.db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        if row is None:
            raise LedgerRefused("INVALID_LEDGER_METADATA")
        return row[0]

    def _set_meta(self, key, value):
        self.db.execute("UPDATE metadata SET value=? WHERE key=?", (str(value), key))

    @property
    def epoch(self):
        with self._mutex:
            return self._meta("epoch")

    def _initialize(self, store_id):
        self.db.executescript("""
            BEGIN IMMEDIATE;
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE devices (device TEXT PRIMARY KEY, ingress INTEGER NOT NULL,
                                  retry_highwater INTEGER NOT NULL, input_chain TEXT NOT NULL);
            CREATE TABLE windows (epoch TEXT NOT NULL, device TEXT NOT NULL, idx INTEGER NOT NULL,
                closed INTEGER NOT NULL, limitations TEXT NOT NULL, accepted INTEGER NOT NULL,
                first_seq INTEGER NOT NULL, last_seq INTEGER NOT NULL, input_chain TEXT NOT NULL,
                obligation TEXT NOT NULL, reserved_bytes INTEGER NOT NULL, archive_hash TEXT, archive_path TEXT,
                PRIMARY KEY(epoch, device, idx));
            CREATE TABLE facts (epoch TEXT NOT NULL, device TEXT NOT NULL, idx INTEGER NOT NULL,
                condition TEXT NOT NULL, matches INTEGER NOT NULL, misses INTEGER NOT NULL,
                unresolved INTEGER NOT NULL, PRIMARY KEY(epoch,device,idx,condition),
                FOREIGN KEY(epoch,device,idx) REFERENCES windows(epoch,device,idx) ON DELETE CASCADE);
            CREATE TABLE observations (epoch TEXT NOT NULL, device TEXT NOT NULL, seq INTEGER NOT NULL,
                retry INTEGER NOT NULL, idx INTEGER NOT NULL, ingress_us INTEGER NOT NULL,
                body BLOB NOT NULL, input_hash TEXT NOT NULL, size INTEGER NOT NULL, disposition TEXT NOT NULL,
                PRIMARY KEY(epoch,device,seq), UNIQUE(device,retry),
                FOREIGN KEY(epoch,device,idx) REFERENCES windows(epoch,device,idx));
            CREATE INDEX pending_idx ON observations(disposition);
            COMMIT;
        """)
        with self._transaction():
            entries = {"schema_version": "1", "store_id": store_id, "epoch": str(uuid4()),
                       "generation": "0", "retirement_chain": "0"*64, "closed_floor": str(-(2**63)),
                       "clock_limitations": "0", "last_limitation": "", "contract_hash": self.digest,
                       "contract": contract_bytes(self.contract).decode("utf-8")}
            self.db.executemany("INSERT INTO metadata VALUES (?,?)", entries.items())
            self.db.executemany("INSERT INTO devices VALUES (?,0,0,?)",
                                ((device.device_id, "0"*64) for device in self.contract.devices))

    def _seal_open(self, limitations=(), before=None, closure_reason=None):
        query = "SELECT * FROM windows WHERE closed=0"
        parameters = ()
        if before is not None:
            query += " AND idx<?"
            parameters = (before,)
        rows = self.db.execute(query, parameters).fetchall()
        for row in rows:
            merged = tuple(dict.fromkeys((*json.loads(row["limitations"]), *limitations)))
            self.db.execute("UPDATE windows SET closed=1,limitations=? WHERE epoch=? AND device=? AND idx=?",
                            (json.dumps(merged), row["epoch"], row["device"], row["idx"]))
            if self._window_has_reason:
                reason = closure_reason or ("CLOCK_DISCONTINUITY" if CoverageLimitation.CLOCK_DISCONTINUITY in merged
                    else "INTERRUPTED" if CoverageLimitation.INTERRUPTED in merged else "WINDOW_END")
                self.db.execute("UPDATE windows SET closure_reason=? WHERE epoch=? AND device=? AND idx=?",
                                (reason,row["epoch"],row["device"],row["idx"]))
            if self.closure_hook is not None:
                self.closure_hook((row["epoch"], row["device"], row["idx"]))
        if rows:
            self._set_meta("closed_floor", max(int(self._meta("closed_floor")), max(row["idx"] for row in rows)))

    def _recover(self):
        self._seal_open((CoverageLimitation.INTERRUPTED,),closure_reason="RECOVERY")
        # Counters and UNSIZED obligations are retained; no restored epoch or queue is invented.
        self._set_meta("clock_limitations", int(self._meta("clock_limitations"))+1)
        self._set_meta("last_limitation", "RECOVERY_DOWNTIME")

    def _verify_recovered_state(self):
        devices = self.db.execute("SELECT * FROM devices").fetchall()
        if {row["device"] for row in devices} != {item.device_id for item in self.contract.devices}:
            raise LedgerRefused("INCONSISTENT_RECOVERED_DEVICES")
        if any(not 0 <= row["ingress"] <= 2**63-1 or not 0 <= row["retry_highwater"] <= 2**63-1 for row in devices):
            raise LedgerRefused("INCONSISTENT_RECOVERED_COUNTERS")
        for window in self.db.execute("SELECT * FROM windows"):
            permitted = {"UNSIZED", "RETIRED_LOCAL"}
            if self._coupled:
                permitted |= {"RESERVED", "EVIDENCE_READY", "LOCAL_ATTEMPTED", "UNSUPPORTED"}
            if (window["obligation"] not in permitted or window["reserved_bytes"] < 0
                    or (not self._coupled and window["reserved_bytes"] != 0)
                    or (window["obligation"] == "RETIRED_LOCAL" and (not window["closed"] or not window["archive_hash"] or not window["archive_path"]))):
                raise LedgerRefused("INCONSISTENT_RECOVERED_OBLIGATION")
            if window["obligation"] == "RETIRED_LOCAL":
                self._check_archive(window)
            expected = {item.condition_id for item in self.contract.conditions if item.device_id == window["device"]}
            rows = self.db.execute("SELECT * FROM facts WHERE epoch=? AND device=? AND idx=?",
                                   (window["epoch"], window["device"], window["idx"])).fetchall()
            if {row["condition"] for row in rows} != expected:
                raise LedgerRefused("INCONSISTENT_RECOVERED_FACTS")
            if any(row["matches"]+row["misses"]+row["unresolved"] != window["accepted"] for row in rows):
                raise LedgerRefused("INCONSISTENT_RECOVERED_FACTS")
            records = self.db.execute("SELECT * FROM observations WHERE epoch=? AND device=? AND idx=? ORDER BY seq",
                                      (window["epoch"], window["device"], window["idx"])).fetchall()
            if len(records) != window["accepted"] or not records:
                raise LedgerRefused("INCONSISTENT_RECOVERED_POPULATION")
            if records[0]["seq"] != window["first_seq"] or records[-1]["seq"] != window["last_seq"]:
                raise LedgerRefused("INCONSISTENT_RECOVERED_IDENTITIES")
            device = self.db.execute("SELECT * FROM devices WHERE device=?", (window["device"],)).fetchone()
            if device is None or device["ingress"] < window["last_seq"] or device["retry_highwater"] < max(r["retry"] for r in records):
                raise LedgerRefused("INCONSISTENT_RECOVERED_COUNTERS")
            originals = []
            for record in records:
                if hashlib.sha256(record["body"]).hexdigest() != record["input_hash"] or len(record["body"]) != record["size"]:
                    raise LedgerRefused("CORRUPT_CANONICAL_INPUT")
                message = EdgeTelemetryMessage.model_validate_json(record["body"])
                if (message.device_id != record["device"] or record["ingress_us"]//10000000 != window["idx"]
                        or canonical_bytes(message.model_dump(mode="json")) != record["body"]
                        or (record["disposition"] not in {"PENDING_POLICY", "SELECTED_RAW", "REDUCED_RAW", "DROPPED_RAW"}
                            if self._coupled and window["obligation"] != "RETIRED_LOCAL"
                            else record["disposition"] != ("ARCHIVED_LOCAL" if window["obligation"] == "RETIRED_LOCAL" else "PENDING_POLICY"))):
                    raise LedgerRefused("INCONSISTENT_RECOVERED_INPUT")
                originals.append(self._observation(message, record["epoch"], record["seq"], record["ingress_us"]))
            identity = WindowIdentity(ledger_epoch=window["epoch"], device_id=window["device"],
                                      window_index=window["idx"], contract_hash=self.digest)
            for row in rows:
                calculated = condition_facts(self.contract, row["condition"], identity, originals)
                if (calculated.matching_count, calculated.nonmatching_count, calculated.unresolved_count) != (row["matches"],row["misses"],row["unresolved"]):
                    raise LedgerRefused("INCONSISTENT_RECOVERED_FACTS")

    def _check_limits(self):
        counts = self.db.execute("SELECT COUNT(*),COALESCE(SUM(CASE WHEN disposition='PENDING_POLICY' THEN size ELSE 0 END),0) FROM observations").fetchone()
        windows = self.db.execute("SELECT COUNT(*),COALESCE(SUM(closed=0),0) FROM windows").fetchone()
        if (counts[0] > self.limits.max_retained_records or counts[1] > self.limits.max_pending_outbox_bytes
                or windows[0] > self.limits.max_retained_windows or windows[1] > self.limits.max_active_windows):
            raise LedgerRefused("LEDGER_CAPACITY", 429)
        pages = self.db.execute("PRAGMA page_count").fetchone()[0]
        if pages*PAGE_SIZE > self.limits.max_database_bytes:
            raise LedgerRefused("DATABASE_LIMIT", 429)

    def _ensure_open(self):
        if self._closed or self._failed:
            raise LedgerRefused("LEDGER_REOPEN_REQUIRED")

    def _observation(self, message, epoch, sequence, ingress_us):
        readings = [MetricReading(path=name, value=getattr(message, name))
                    for name in ("temperature", "humidity", "cpu_usage", "memory_usage")]
        registered = next(item for item in self.contract.devices if item.device_id == message.device_id)
        paths = {item.path for item in registered.metrics if item.path.startswith("measurements.")}
        readings += [MetricReading(path=path, value=message.measurements.get(path.split(".",1)[1])) for path in sorted(paths)]
        return IngressObservation(ledger_epoch=epoch, device_id=message.device_id,
            ingress_sequence=sequence, ingress_utc_us=ingress_us,
            telemetry_type=message.telemetry_type, metrics=tuple(readings))

    def _receipt(self, row, duplicate=False):
        return AdmissionReceipt(ledger_epoch=row["epoch"], device_id=row["device"], ingress_sequence=row["seq"],
            window_index=row["idx"], contract_hash=self.digest, input_hash=row["input_hash"],
            duplicate=duplicate, disposition=row["disposition"])

    def admit(self, message: EdgeTelemetryMessage, *, expected_epoch: str, retry_sequence: int,
              freshness_seconds: float | None = None) -> AdmissionReceipt:
        message = EdgeTelemetryMessage.model_validate(message.model_dump(mode="json"))
        body = canonical_bytes(message.model_dump(mode="json"))
        if len(body) > self.limits.max_input_bytes:
            raise LedgerRefused("INPUT_TOO_LARGE", 413)
        if message.device_id not in {item.device_id for item in self.contract.devices}:
            raise LedgerRefused("UNREGISTERED_DEVICE", 422)
        if type(retry_sequence) is not int or not 1 <= retry_sequence <= 2**63-1:
            raise LedgerRefused("RETRY_SEQUENCE_REQUIRED", 422)
        if type(expected_epoch) is not str or not expected_epoch:
            raise LedgerRefused("EPOCH_REQUIRED", 422)
        digest = hashlib.sha256(body).hexdigest()
        with self._mutex:
            self._ensure_open()
            if self._coupled and self.admission_hook is None:
                raise LedgerRefused("COUPLED_CONTROLLER_REQUIRED")
            if expected_epoch != self._meta("epoch"):
                raise LedgerRefused("EPOCH_MISMATCH", 409)
            previous = self.db.execute("SELECT * FROM observations WHERE device=? AND retry=?",
                                       (message.device_id, retry_sequence)).fetchone()
            if previous:
                if previous["input_hash"] != digest:
                    raise LedgerRefused("RETRY_INPUT_CONFLICT", 409)
                return self._receipt(previous, True)
            device = self.db.execute("SELECT * FROM devices WHERE device=?", (message.device_id,)).fetchone()
            if retry_sequence <= device["retry_highwater"]:
                raise LedgerRefused("RETIRED_OR_OLD_RETRY", 409)
            if device["ingress"] >= 2**63-1:
                raise LedgerRefused("SEQUENCE_EXHAUSTED")
            candidate = copy(self.schedule)
            try:
                update = candidate.poll()
                now_us = utc_microseconds(self.clock.utc_now())
                if update.active_window_index is None:
                    with self._transaction():
                        self._seal_open((CoverageLimitation.CLOCK_DISCONTINUITY,))
                        self._set_meta("closed_floor", max(int(self._meta("closed_floor")), self.schedule.active_index, now_us//10000000))
                        self._set_meta("clock_limitations", int(self._meta("clock_limitations"))+1)
                        self._set_meta("last_limitation", "CLOCK_DISCONTINUITY")
                    self.schedule = candidate
                    raise LedgerRefused("CLOCK_DISCONTINUITY")
                if now_us//10000000 != update.active_window_index:
                    raise LedgerRefused("CLOCK_SAMPLE_BOUNDARY_RETRY", 409)
                if update.active_window_index <= int(self._meta("closed_floor")):
                    raise LedgerRefused("CLOSED_WINDOW_REFUSED", 409)
                if freshness_seconds is not None:
                    if not math.isfinite(freshness_seconds) or freshness_seconds <= 0:
                        raise ValueError("invalid freshness limit")
                    source = message.timestamp
                    if source.tzinfo is None:
                        from datetime import timezone
                        source = source.replace(tzinfo=timezone.utc)
                    age = (now_us-utc_microseconds(source))/1000000
                    if not -30 <= age <= freshness_seconds:
                        raise LedgerRefused("EXPIRED_MESSAGE", 400)
                epoch, sequence = self._meta("epoch"), device["ingress"]+1
                idx = update.active_window_index
                observation = self._observation(message, epoch, sequence, now_us)
                identity = WindowIdentity(ledger_epoch=epoch, device_id=message.device_id,
                                          window_index=idx, contract_hash=self.digest)
                with self._transaction():
                    self.fault("before_identity", self.db)
                    if update.closed_window:
                        self._seal_open(update.closed_window.limitations, before=idx)
                    window = self.db.execute("SELECT * FROM windows WHERE epoch=? AND device=? AND idx=?",
                                             (epoch, message.device_id, idx)).fetchone()
                    if window and window["closed"]:
                        raise LedgerRefused("CLOSED_WINDOW_REFUSED", 409)
                    if not window:
                        self.db.execute("INSERT INTO windows (epoch,device,idx,closed,limitations,accepted,first_seq,last_seq,input_chain,obligation,reserved_bytes,archive_hash,archive_path) VALUES (?,?,?,0,?,0,?,?,?,'UNSIZED',0,NULL,NULL)",
                            (epoch, message.device_id, idx, json.dumps(candidate.limitations), sequence, sequence, "0"*64))
                    chain = hashlib.sha256(canonical_bytes({"previous": device["input_chain"], "epoch": epoch,
                        "device": message.device_id, "sequence": sequence, "window": idx, "input_hash": digest})).hexdigest()
                    self.db.execute("UPDATE devices SET ingress=?,retry_highwater=?,input_chain=? WHERE device=?",
                                    (sequence, retry_sequence, chain, message.device_id))
                    self.db.execute("INSERT INTO observations VALUES (?,?,?,?,?,?,?,?,?,'PENDING_POLICY')",
                                    (epoch,message.device_id,sequence,retry_sequence,idx,now_us,body,digest,len(body)))
                    self.db.execute("UPDATE windows SET accepted=accepted+1,last_seq=?,input_chain=? WHERE epoch=? AND device=? AND idx=?",
                                    (sequence, chain, epoch,message.device_id,idx))
                    self.fault("after_observation", self.db)
                    for condition in self.contract.conditions:
                        if condition.device_id != message.device_id:
                            continue
                        fact = condition_facts(self.contract, condition.condition_id, identity, (observation,), closed=False)
                        self.db.execute("INSERT INTO facts VALUES (?,?,?,?,?,?,?) ON CONFLICT(epoch,device,idx,condition) DO UPDATE SET matches=matches+excluded.matches,misses=misses+excluded.misses,unresolved=unresolved+excluded.unresolved",
                            (epoch,message.device_id,idx,condition.condition_id,fact.matching_count,fact.nonmatching_count,fact.unresolved_count))
                    self.fault("after_facts", self.db)
                    if self.admission_hook is not None:
                        self.admission_hook(AdmissionReceipt(ledger_epoch=epoch, device_id=message.device_id,
                            ingress_sequence=sequence, window_index=idx, contract_hash=self.digest, input_hash=digest),
                            message)
                    self._check_limits()
                    self.fault("after_obligation", self.db)
                    self.fault("before_commit", self.db)
                self.schedule = candidate
                self.fault("after_commit", self.db)
                return self._receipt(self.db.execute("SELECT * FROM observations WHERE epoch=? AND device=? AND seq=?",
                                                     (epoch, message.device_id, sequence)).fetchone())
            except sqlite3.Error as exc:
                self._failed = True
                raise LedgerRefused("STORAGE_UNAVAILABLE") from exc

    def tick(self):
        """Seal only observed scopes; admission uses the same writer lock."""
        with self._mutex:
            self._ensure_open()
            candidate = copy(self.schedule)
            update = candidate.poll()
            try:
                with self._transaction():
                    if update.active_window_index is None:
                        self._seal_open((CoverageLimitation.CLOCK_DISCONTINUITY,))
                        self._set_meta("closed_floor", max(int(self._meta("closed_floor")), self.schedule.active_index,
                                                          utc_microseconds(self.clock.utc_now())//10000000))
                        self._set_meta("last_limitation", "CLOCK_DISCONTINUITY")
                    elif update.closed_window:
                        self._seal_open(update.closed_window.limitations, before=update.active_window_index)
                self.schedule = candidate
            except sqlite3.Error as exc:
                self._failed = True
                raise LedgerRefused("STORAGE_UNAVAILABLE") from exc

    def facts(self) -> tuple[ConditionFacts, ...]:
        with self._mutex:
            rows = self.db.execute("SELECT f.*,w.closed,w.limitations,w.accepted FROM facts f JOIN windows w USING(epoch,device,idx) ORDER BY idx,device,condition").fetchall()
            return tuple(ConditionFacts(window=WindowIdentity(ledger_epoch=row["epoch"], device_id=row["device"],
                window_index=row["idx"], contract_hash=self.digest), condition_id=row["condition"],
                accepted_count=row["accepted"], matching_count=row["matches"], nonmatching_count=row["misses"],
                unresolved_count=row["unresolved"], closed=bool(row["closed"]),
                limitations=tuple(json.loads(row["limitations"]))) for row in rows)

    def records(self):
        with self._mutex:
            return tuple(dict(row) for row in self.db.execute("SELECT * FROM observations ORDER BY device,seq"))

    def status(self):
        with self._mutex:
            self._ensure_open()
            counts = self.db.execute("SELECT COUNT(*),COALESCE(SUM(CASE WHEN disposition='PENDING_POLICY' THEN size ELSE 0 END),0) FROM observations").fetchone()
            return {"epoch": self._meta("epoch"), "generation": int(self._meta("generation")),
                "contract_hash": self.digest, "retained_records": counts[0], "pending_outbox_bytes": counts[1],
                "unsized_obligations": self.db.execute("SELECT COUNT(*) FROM windows WHERE obligation='UNSIZED'").fetchone()[0],
                "last_limitation": self._meta("last_limitation"), "clock_halted": self.schedule.halted,
                "admission_blocked": self.schedule.halted or self.schedule.active_index <= int(self._meta("closed_floor")),
                "database_bytes": self.db.execute("PRAGMA page_count").fetchone()[0]*PAGE_SIZE}

    def _archive_bytes(self, key):
        window = self.db.execute("SELECT * FROM windows WHERE epoch=? AND device=? AND idx=?", key).fetchone()
        if not window or not window["closed"]:
            raise LedgerRefused("OPEN_OR_MISSING_WINDOW")
        facts = [dict(row) for row in self.db.execute("SELECT * FROM facts WHERE epoch=? AND device=? AND idx=? ORDER BY condition", key)]
        records = []
        for row in self.db.execute("SELECT * FROM observations WHERE epoch=? AND device=? AND idx=? ORDER BY seq", key):
            record = dict(row)
            record["canonical_input"] = json.loads(record.pop("body"))
            record.pop("disposition")
            records.append(record)
        scope = {name: window[name] for name in ("epoch","device","idx","closed","limitations","accepted","first_seq","last_seq","input_chain")}
        body = canonical_bytes({"schema_version":1,"store_id":self._meta("store_id"),
            "contract":self.contract.model_dump(mode="json"),"scope":scope,"facts":facts,"observations":records})
        if len(body) > self.limits.max_database_bytes*2+65536:
            raise LedgerRefused("ARCHIVE_SIZE_LIMIT")
        return body

    def export_closed_window(self, *, epoch: str, device_id: str, window_index: int, path: str | Path) -> str:
        """Write a new fsynced local raw/fact archive, never overwrite existing files."""
        with self._mutex:
            self._ensure_open()
            body = self._archive_bytes((epoch,device_id,window_index))
            with self._external_archive_path(path).open("xb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            return hashlib.sha256(body).hexdigest()

    def _external_archive_path(self, path):
        result = Path(path).resolve()
        if result.is_relative_to(self.path.parent.resolve()) or len(str(result)) > 1024:
            raise LedgerRefused("ARCHIVE_MUST_BE_EXTERNAL")
        return result

    def _check_archive(self, row):
        try:
            with self._external_archive_path(row["archive_path"]).open("rb") as handle:
                body = handle.read(self.limits.max_database_bytes*2+65537)
        except OSError as exc:
            raise LedgerRefused("LOCAL_ARCHIVE_UNAVAILABLE") from exc
        if hashlib.sha256(body).hexdigest() != row["archive_hash"]:
            raise LedgerRefused("ARCHIVE_CHECKPOINT_MISMATCH")

    def archive_closed_window(self, *, epoch: str, device_id: str, window_index: int, archive_path: str | Path):
        """Explicit LOCAL archival retirement, never a claim of Fog receipt.

        Caller must export raw inputs/facts first; compare the archive to this scope.
        N3/N4 will implement signed evidence and obligation fulfillment separately.
        """
        with self._mutex, self._transaction():
            self._ensure_open()
            if self._coupled:
                if self.retirement_hook is None:
                    raise LedgerRefused("COUPLED_CONTROLLER_REQUIRED")
                self.retirement_hook((epoch, device_id, window_index))
            expected = self._archive_bytes((epoch,device_id,window_index))
            archive_path = self._external_archive_path(archive_path)
            with archive_path.open("rb") as handle:
                actual = handle.read(self.limits.max_database_bytes*2+65537)
            if actual != expected:
                raise LedgerRefused("ARCHIVE_CHECKPOINT_MISMATCH")
            archive_hash = hashlib.sha256(actual).hexdigest()
            self.db.execute("UPDATE observations SET disposition='ARCHIVED_LOCAL' WHERE epoch=? AND device=? AND idx=?",
                            (epoch,device_id,window_index))
            self.db.execute("UPDATE windows SET obligation='RETIRED_LOCAL',reserved_bytes=0,archive_hash=?,archive_path=? WHERE epoch=? AND device=? AND idx=?",
                            (archive_hash,str(archive_path),epoch,device_id,window_index))

    def compact(self) -> int:
        with self._mutex, self._transaction():
            self._ensure_open()
            eligible = self.db.execute("SELECT epoch,device,idx,archive_hash,archive_path,input_chain,accepted FROM windows WHERE closed=1 AND obligation='RETIRED_LOCAL' AND archive_hash IS NOT NULL ORDER BY idx,device").fetchall()
            head = self._meta("retirement_chain")
            for row in eligible:
                self._check_archive(row)
                head = hashlib.sha256(canonical_bytes({"previous": head, **dict(row)})).hexdigest()
                key = (row["epoch"],row["device"],row["idx"])
                self.db.execute("DELETE FROM observations WHERE epoch=? AND device=? AND idx=?", key)
                self.db.execute("DELETE FROM windows WHERE epoch=? AND device=? AND idx=?", key)
            self._set_meta("retirement_chain", head)
            return len(eligible)

    def retire_epoch(self, *, expected_epoch: str, checkpoint_hash: str) -> str:
        if len(checkpoint_hash) != 64 or any(c not in "0123456789abcdef" for c in checkpoint_hash):
            raise ValueError("retirement requires an external checkpoint hash")
        with self._mutex, self._transaction():
            self._ensure_open()
            if expected_epoch != self._meta("epoch") or self.db.execute("SELECT COUNT(*) FROM windows").fetchone()[0]:
                raise LedgerRefused("EPOCH_NOT_QUIESCENT")
            new_epoch = str(uuid4())
            head = hashlib.sha256(canonical_bytes({"previous":self._meta("retirement_chain"),
                "old_epoch":expected_epoch,"new_epoch":new_epoch,"checkpoint":checkpoint_hash,
                "generation":int(self._meta("generation"))+1})).hexdigest()
            self._set_meta("epoch", new_epoch)
            self._set_meta("generation", int(self._meta("generation"))+1)
            self._set_meta("retirement_chain", head)
            # Device ingress/retry highwaters and closed-window floors never reset.
            return new_epoch

    def close(self):
        with self._mutex:
            if self.db is not None:
                self.db.close()
                self.db = None
            if self._lock_file is not None:
                self._lock_file.close()
                self._lock_file = None
            self._closed = True

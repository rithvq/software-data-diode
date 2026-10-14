"""Fog-private UDP reorder history. Never imports the legacy ReplayDetector."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from threading import RLock
import time

from shared.security.crypto import canonical_bytes
from .capsules import EvidenceError


class ResearchReplayStore:
    def __init__(self, path, framer, *, now_us=None):
        self.path, self.framer, self.mutex = Path(path).absolute(), framer, RLock()
        self.now = now_us or (lambda: time.time_ns()//1000)
        self.db = self.lock = None
        anchor = Path(str(self.path)+".anchor.json")
        if not self.path.parent.is_dir() or any(p.is_symlink() for p in (self.path, self.path.parent, anchor, Path(str(self.path)+".lock"))):
            raise ValueError("provision a private nonsymlink Fog state directory")
        binding = canonical_bytes({"profile": framer.profile.model_dump(mode="json"), "config": framer.config.model_dump(mode="json")})
        try:
            self.lock = Path(str(self.path)+".lock").open("a+b")
            if os.name == "nt":
                import msvcrt
                self.lock.seek(0)
                if not self.lock.read(1):
                    self.lock.write(b"0")
                    self.lock.flush()
                self.lock.seek(0)
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fresh = not self.path.exists()
            if fresh and anchor.exists():
                raise ValueError("missing anchored replay store; refusing a reset")
            if not fresh and not anchor.exists():
                raise ValueError("missing replay identity anchor")
            if fresh:
                with anchor.open("xb") as handle:
                    handle.write(binding)
                    handle.flush()
                    os.fsync(handle.fileno())
            elif anchor.read_bytes() != binding:
                raise ValueError("research trust/config changed; explicit operator migration required")
            self.db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            if self.db.execute("PRAGMA page_size").fetchone()[0] != 4096:
                raise ValueError("unsupported research replay page size")
            self.db.execute("PRAGMA max_page_count="+str(framer.config.replay_bytes//4096))
            if fresh:
                self.db.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE meta (key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE heads (kind TEXT,device TEXT,high INTEGER NOT NULL,PRIMARY KEY(kind,device));
                CREATE TABLE records (kind TEXT,id TEXT,device TEXT,seq INTEGER,stamp INTEGER,digest TEXT,body BLOB,pending INTEGER,
                    PRIMARY KEY(kind,id),UNIQUE(kind,device,seq));
                COMMIT;
                """)
                self.db.execute("INSERT INTO meta VALUES ('binding',?)", (binding.decode(),))
                self.db.execute("INSERT INTO meta VALUES ('retired','0')")
            if (self.db.execute("PRAGMA quick_check").fetchone()[0] != "ok"
                    or self.db.execute("SELECT value FROM meta WHERE key='binding'").fetchone()[0] != binding.decode()):
                raise ValueError("corrupt research replay metadata")
            devices = {d.device_id for d in framer.contract.devices} | {framer.profile.gateway_id}
            for row in self.db.execute("SELECT * FROM heads"):
                if row["kind"] not in {"RAW", "STATE", "EVIDENCE"} or row["device"] not in devices or row["high"] < 0:
                    raise ValueError("corrupt durable reorder head")
            for row in self.db.execute("SELECT * FROM records"):
                head = self.db.execute("SELECT high FROM heads WHERE kind=? AND device=?", (row["kind"], row["device"])).fetchone()
                if (hashlib.sha256(row["body"]).hexdigest() != row["digest"] or head is None or row["seq"] > head[0]
                        or row["pending"] not in {0, 1} or row["kind"] not in {"RAW", "STATE", "EVIDENCE"}):
                    raise ValueError("corrupt retained UDP artifact")
            self._capacity()
        except BaseException:
            self.close()
            raise

    def _capacity(self):
        count, size = self.db.execute("SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM records").fetchone()
        if count > self.framer.config.replay_records or size > self.framer.config.replay_bytes//2:
            raise EvidenceError("RESEARCH_REPLAY_CAPACITY")

    def accept(self, artifact):
        cfg, db, now = self.framer.config, self.db, self.now()
        devices = {d.device_id for d in self.framer.contract.devices}
        if (artifact.kind not in {"RAW", "STATE", "EVIDENCE"} or type(artifact.sequence) is not int
                or not 1 <= artifact.sequence <= 2**63-1 or type(artifact.stamp_us) is not int
                or not 1 <= len(artifact.encoded) <= 32768
                or artifact.device not in (devices if artifact.kind != "STATE" else {self.framer.profile.gateway_id})):
            raise EvidenceError("INVALID_RESEARCH_REPLAY_SCOPE")
        if not now-cfg.freshness_seconds*1000000 <= artifact.stamp_us <= now+30_000_000:
            raise EvidenceError("EXPIRED_RESEARCH_ARTIFACT")
        digest = hashlib.sha256(artifact.encoded).hexdigest()
        with self.mutex:
            db.execute("BEGIN IMMEDIATE")
            try:
                if db.execute("SELECT value FROM meta WHERE key='retired'").fetchone()[0] != "0":
                    raise EvidenceError("RETIRED_RESEARCH_EPOCH")
                seen = db.execute("SELECT * FROM records WHERE kind=? AND id=?", (artifact.kind, artifact.identity)).fetchone()
                if seen:
                    if seen["digest"] != digest:
                        raise EvidenceError("RESEARCH_IDENTITY_FORK")
                    db.execute("ROLLBACK")
                    return False
                same = db.execute("SELECT 1 FROM records WHERE kind=? AND device=? AND seq=?", (artifact.kind, artifact.device, artifact.sequence)).fetchone()
                if same:
                    raise EvidenceError("RESEARCH_SEQUENCE_FORK")
                head = db.execute("SELECT high FROM heads WHERE kind=? AND device=?", (artifact.kind, artifact.device)).fetchone()
                high = max(head[0] if head else 0, artifact.sequence)
                width = cfg.replay_width if artifact.kind != "EVIDENCE" else max(2, cfg.freshness_seconds//10)
                if artifact.sequence <= high-width:
                    raise EvidenceError("STALE_RESEARCH_SEQUENCE_WINDOW")
                db.execute("DELETE FROM records WHERE pending=0 AND (stamp<? OR (kind=? AND device=? AND seq<=?))",
                           (now-cfg.freshness_seconds*1000000, artifact.kind, artifact.device, high-width))
                db.execute("INSERT INTO records VALUES (?,?,?,?,?,?,?,?)", (artifact.kind, artifact.identity, artifact.device,
                    artifact.sequence, artifact.stamp_us, digest, artifact.encoded, int(artifact.kind in {"RAW", "STATE"})))
                db.execute("INSERT INTO heads VALUES (?,?,?) ON CONFLICT(kind,device) DO UPDATE SET high=excluded.high", (artifact.kind, artifact.device, high))
                self._capacity()
                db.execute("COMMIT")
                return True
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise

    def pending(self):
        with self.mutex:
            return self.db.execute("SELECT * FROM records WHERE pending=1 ORDER BY stamp,id LIMIT 1").fetchone()

    def completed(self, kind, identity):
        with self.mutex:
            self.db.execute("UPDATE records SET pending=0 WHERE kind=? AND id=?", (kind, identity))

    def retire_epoch(self):
        """Explicit local operator action, never driven by an incoming packet."""
        with self.mutex:
            self.db.execute("UPDATE meta SET value='1' WHERE key='retired'")

    def status(self):
        with self.mutex:
            cfg, now = self.framer.config, self.now()
            state = self.db.execute("SELECT body,stamp FROM records WHERE kind='STATE' ORDER BY seq DESC LIMIT 1").fetchone()
            evidence = []
            for device in self.framer.contract.devices:
                row = self.db.execute("SELECT MAX(seq),MAX(stamp) FROM records WHERE kind='EVIDENCE' AND device=?", (device.device_id,)).fetchone()
                age = max(0, (now-row[1])/1000000) if row[1] is not None else None
                evidence.append({"device_id": device.device_id, "last_closed_window": row[0], "age_seconds": age,
                                 "stale_or_missing": age is None or age > 30})
            return {"received_artifacts": self.db.execute("SELECT COUNT(*) FROM records").fetchone()[0],
                "pending_internal_processing": self.db.execute("SELECT COUNT(*) FROM records WHERE pending=1").fetchone()[0],
                "retired_epoch": self.db.execute("SELECT value FROM meta WHERE key='retired'").fetchone()[0] != "0",
                "edge_state_stale": not state or now-state["stamp"] > cfg.state_interval_seconds*3*1000000,
                "edge_state": json.loads(state["body"])["metrics"] if state else None,
                "evidence_freshness": evidence, "coverage_evidence_stale_or_missing": any(x["stale_or_missing"] for x in evidence),
                "coverage": "NOT_EVALUATED_N5", "receipt_scope": "VERIFIED_FOG_LOCAL_ARTIFACT"}

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock is not None:
            self.lock.close()
            self.lock = None

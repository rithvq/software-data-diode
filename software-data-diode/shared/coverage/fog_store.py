"""Additive N6 evidence/outcome spool on the bounded N5 Fog-only store."""
import hashlib
import json
import time

from shared.security.crypto import canonical_bytes
from .budget import pack_frames, unpack_frames
from .capsules import EvidenceError
from .research_replay import ResearchReplayStore
from .verification import FogEvidenceVerifier


class FogEvidenceStore(ResearchReplayStore):
    def __init__(self, path, framer, *, now_us=None):
        if framer.config.replay_bytes//2 < 190000:
            raise ValueError("N6 spool budget cannot hold a maximum signed artifact and its bounded parts")
        super().__init__(path, framer, now_us=now_us)
        self.verifier = FogEvidenceVerifier(framer)
        self.publish_outcome_next = False
        try:
            with self.mutex:
                self.db.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE IF NOT EXISTS evidence_work (
                        digest TEXT PRIMARY KEY,scope TEXT,device TEXT,seq INTEGER,stamp INTEGER,
                        received INTEGER,body BLOB,frames BLOB,legacy INTEGER,pending INTEGER,seconds REAL);
                    CREATE TABLE IF NOT EXISTS evidence_outcomes (id TEXT PRIMARY KEY,body BLOB,pending INTEGER);
                    COMMIT;
                """)
                if not self.db.execute("SELECT 1 FROM meta WHERE key='n6_evidence'").fetchone():
                    self.db.execute("BEGIN IMMEDIATE")
                    try:
                        for row in self.db.execute("SELECT * FROM records WHERE kind='EVIDENCE' ORDER BY stamp,id").fetchall():
                            record = self.verifier.verify(row["body"], received_us=self.now(), legacy=True)
                            self._insert(row["body"], (), record, True, 0)
                        self.db.execute("INSERT INTO meta VALUES ('n6_evidence','1')")
                        self._capacity()
                        self.db.execute("COMMIT")
                    except BaseException:
                        self.db.execute("ROLLBACK")
                        raise
                for row in self.db.execute("SELECT * FROM evidence_work"):
                    frames = () if row["legacy"] else unpack_frames(row["frames"])
                    record = self.verifier.verify(row["body"], received_us=row["received"], frames=frames, legacy=bool(row["legacy"]))
                    if (record.artifact_digest != row["digest"] or record.scope_id != row["scope"]
                            or record.device_id != row["device"] or record.window_index != row["seq"]
                            or row["pending"] not in {0, 1}):
                        raise ValueError("corrupt Fog evidence spool")
                if self.db.execute("SELECT value FROM meta WHERE key='n6_evidence'").fetchone()[0] != "1":
                    raise ValueError("unsupported Fog evidence spool version")
                self._capacity()
        except BaseException:
            self.close()
            raise

    def _capacity(self):
        super()._capacity()
        if not self.db.execute("SELECT 1 FROM sqlite_master WHERE name='evidence_work'").fetchone():
            return
        count, size = self.db.execute("""SELECT COUNT(*),COALESCE(SUM(length(body)+length(frames)),0)
            FROM evidence_work""").fetchone()
        raw_count, raw_size = self.db.execute("SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM records WHERE kind!='EVIDENCE'").fetchone()
        outcome_size = self.db.execute("SELECT COALESCE(SUM(length(body)),0) FROM evidence_outcomes").fetchone()[0]
        if count+raw_count > self.framer.config.replay_records or size+raw_size+outcome_size > self.framer.config.replay_bytes//2:
            raise EvidenceError("FOG_EVIDENCE_SPOOL_CAPACITY")

    def _insert(self, encoded, frames, record, legacy, seconds):
        self.db.execute("INSERT INTO evidence_work VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
            record.artifact_digest, record.scope_id, record.device_id, record.window_index,
            record.created_at_utc_us, record.received_at_utc_us, encoded, pack_frames(frames), int(legacy), 1, seconds))

    def accept(self, artifact):
        if artifact.kind != "EVIDENCE":
            return super().accept(artifact)
        start, now = time.monotonic(), self.now()
        record = self.verifier.verify(artifact.encoded, received_us=now, frames=artifact.frames)
        if (record.scope_id, record.device_id, record.window_index, record.created_at_utc_us) != (
                artifact.identity, artifact.device, artifact.sequence, artifact.stamp_us):
            raise EvidenceError("INCONSISTENT_REASSEMBLY_IDENTITY")
        with self.mutex:
            db = self.db
            db.execute("BEGIN IMMEDIATE")
            try:
                if db.execute("SELECT value FROM meta WHERE key='retired'").fetchone()[0] != "0":
                    raise EvidenceError("RETIRED_RESEARCH_EPOCH")
                if db.execute("SELECT 1 FROM evidence_work WHERE digest=?", (record.artifact_digest,)).fetchone():
                    db.execute("ROLLBACK")
                    return False
                known = db.execute("SELECT 1 FROM evidence_work WHERE scope=?", (record.scope_id,)).fetchone()
                head = db.execute("SELECT high FROM heads WHERE kind='EVIDENCE' AND device=?", (artifact.device,)).fetchone()
                high = max(head[0] if head else artifact.sequence, artifact.sequence)
                if not known and artifact.sequence <= high-record.replay_width_windows:
                    raise EvidenceError("STALE_RESEARCH_SEQUENCE_WINDOW")
                db.execute("DELETE FROM evidence_work WHERE pending=0 AND stamp<?", (now-self.framer.config.freshness_seconds*1000000,))
                self._insert(artifact.encoded, artifact.frames, record, False, time.monotonic()-start)
                db.execute("INSERT INTO heads VALUES ('EVIDENCE',?,?) ON CONFLICT(kind,device) DO UPDATE SET high=excluded.high",
                           (artifact.device, high))
                self._capacity()
                db.execute("COMMIT")
                return True
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise

    def record_outcome(self, reason, content=b"", details=None):
        reason = reason[:96]
        timestamp = self.now()
        digest = hashlib.sha256(content).hexdigest()
        identity = hashlib.sha256(canonical_bytes([reason, digest, details or {}])).hexdigest()
        outcome = {"outcome_id": identity, "timestamp_us": timestamp, "reason_code": reason,
                   "details": {"input_digest": digest, **(details or {})}}
        encoded = canonical_bytes(outcome)
        if len(encoded) > 2048:
            raise EvidenceError("OUTCOME_METADATA_BOUND")
        with self.mutex:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                if not self.db.execute("SELECT 1 FROM evidence_outcomes WHERE id=?", (identity,)).fetchone():
                    limit = min(128, self.framer.config.replay_records//4)
                    self.db.execute("DELETE FROM evidence_outcomes WHERE pending=0")
                    if self.db.execute("SELECT COUNT(*) FROM evidence_outcomes").fetchone()[0] >= limit:
                        raise EvidenceError("FOG_OUTCOME_SPOOL_CAPACITY")
                    self.db.execute("INSERT INTO evidence_outcomes VALUES (?,?,1)", (identity, encoded))
                self._capacity()
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def evidence_pending(self):
        with self.mutex:
            return self.db.execute("SELECT * FROM evidence_work WHERE pending=1 ORDER BY received,seq,digest LIMIT 1").fetchone()

    def outcome_pending(self):
        with self.mutex:
            return self.db.execute("SELECT * FROM evidence_outcomes WHERE pending=1 ORDER BY rowid LIMIT 1").fetchone()

    def evidence_completed(self, digest):
        with self.mutex:
            self.db.execute("UPDATE evidence_work SET pending=0 WHERE digest=?", (digest,))

    def outcome_completed(self, identity):
        with self.mutex:
            self.db.execute("UPDATE evidence_outcomes SET pending=0 WHERE id=?", (identity,))

    def publish_one(self, repository):
        outcome = self.outcome_pending()
        if outcome and self.publish_outcome_next:
            repository.save_coverage_outcome(json.loads(outcome["body"]))
            self.outcome_completed(outcome["id"])
            self.publish_outcome_next = False
            return "OUTCOME_COMMITTED"
        row = self.evidence_pending()
        if row:
            frames = () if row["legacy"] else unpack_frames(row["frames"])
            record = self.verifier.verify(row["body"], received_us=row["received"], frames=frames, legacy=bool(row["legacy"]))
            try:
                result = repository.save_coverage_evidence(row["body"], record, frames, row["seconds"])
            except EvidenceError as exc:
                # Terminal durable policy rejection; do not drop transient DB failures.
                self.record_outcome(str(exc), row["body"], {"scope_id": row["scope"]})
                result = "REJECTED"
            self.evidence_completed(row["digest"])
            self.publish_outcome_next = True
            return result
        row = self.outcome_pending()
        if row:
            repository.save_coverage_outcome(json.loads(row["body"]))
            self.outcome_completed(row["id"])
            return "OUTCOME_COMMITTED"
        return None

    def status(self):
        with self.mutex:
            status = super().status()
            pending = self.db.execute("SELECT COUNT(*) FROM evidence_work WHERE pending=1").fetchone()[0]
            count, size = self.db.execute("SELECT COUNT(*),COALESCE(SUM(length(body)+length(frames)),0) FROM evidence_work").fetchone()
            raw_count, raw_size = self.db.execute("SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM records WHERE kind!='EVIDENCE'").fetchone()
            status.update(pending_evidence=pending,
                pending_verification_outcomes=self.db.execute("SELECT COUNT(*) FROM evidence_outcomes WHERE pending=1").fetchone()[0],
                evidence_spool_records=self.db.execute("SELECT COUNT(*) FROM evidence_work").fetchone()[0],
                evidence_spool_max_records=self.framer.config.replay_records,
                evidence_spool_max_bytes=self.framer.config.replay_bytes//2,
                local_admission_available=(not status["retired_epoch"] and count+raw_count < self.framer.config.replay_records
                    and size+raw_size+190000 < self.framer.config.replay_bytes//2),
                coverage="AUTHENTICATED_SUMMARY_NOT_RULE_VERDICTS", receipt_scope="FOG_DURABLE_SPOOL_NOT_POSTGRES_COMMIT")
            for entry in status["evidence_freshness"]:
                row = self.db.execute("SELECT MAX(seq),MAX(stamp) FROM evidence_work WHERE device=?", (entry["device_id"],)).fetchone()
                if row[1] is not None:
                    entry.update(last_closed_window=row[0], age_seconds=max(0,(self.now()-row[1])/1000000))
                    entry["stale_or_missing"] = entry["age_seconds"] > 30
            status["coverage_evidence_stale_or_missing"] = any(x["stale_or_missing"] for x in status["evidence_freshness"])
            return status

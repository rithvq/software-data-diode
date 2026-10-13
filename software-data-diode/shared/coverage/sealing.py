"""Optional Edge-local signing journal, never a live publisher or scheduler."""
import json
import sqlite3

from pydantic import Field
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .capsules import (CapsuleBody, EvidenceError, InputRecord, MAX_INPUT_RECORDS, MAX_INPUT_SCOPE_BYTES,
                       RawAccounting, artifact_digest, build_capsule, scope_id, sign_artifact, verify_artifact)
from .ledger import LedgerRefused
from .models import CoverageLimitation, FrozenModel, Identifier, WindowIdentity
from .windows import utc_microseconds


class SealingLimits(FrozenModel):
    max_capsules: int = Field(default=256,strict=True,ge=1,le=10000)
    max_signed_bytes: int = Field(default=4*1024*1024,strict=True,ge=1,le=32*1024*1024)


class Publisher(FrozenModel):
    gateway_id: Identifier
    signing_key_id: Identifier


class CapsuleSealer:
    def __init__(self, ledger, gateway_id, signing_key_id, private_key, *, limits=None):
        publisher = Publisher(gateway_id=gateway_id,signing_key_id=signing_key_id)
        if not isinstance(private_key,Ed25519PrivateKey):
            raise ValueError("Ed25519 signing key required")
        gateway_id, signing_key_id = publisher.gateway_id, publisher.signing_key_id
        self.ledger,self.gateway_id,self.key_id,self.key = ledger,gateway_id,signing_key_id,private_key
        self.limits = limits or SealingLimits()
        with ledger._mutex, ledger._transaction():
            ledger._ensure_open()
            version = ledger.db.execute("SELECT value FROM metadata WHERE key='capsule_schema_version'").fetchone()
            if version and version[0] != "1":
                raise LedgerRefused("UNSUPPORTED_CAPSULE_STORE_VERSION")
            columns = {row["name"] for row in ledger.db.execute("PRAGMA table_info(windows)")}
            if "closure_reason" not in columns:
                ledger.db.execute("ALTER TABLE windows ADD COLUMN closure_reason TEXT")
                ledger.db.execute("UPDATE windows SET closure_reason='LEGACY_CLOSURE' WHERE closed=1")
            ledger.db.execute("CREATE TABLE IF NOT EXISTS sealed_capsules (identity TEXT PRIMARY KEY, epoch TEXT NOT NULL, device TEXT NOT NULL, idx INTEGER NOT NULL, body BLOB NOT NULL, digest TEXT NOT NULL)")
            ledger.db.execute("CREATE TABLE IF NOT EXISTS capsule_heads (device TEXT PRIMARY KEY, epoch TEXT NOT NULL, idx INTEGER NOT NULL, digest TEXT NOT NULL)")
            ledger.db.execute("CREATE TABLE IF NOT EXISTS capsule_public_keys (key_id TEXT PRIMARY KEY, public_key BLOB NOT NULL)")
            bound = ledger.db.execute("SELECT value FROM metadata WHERE key='capsule_gateway_id'").fetchone()
            if bound and bound[0] != gateway_id:
                raise LedgerRefused("CAPSULE_GATEWAY_BINDING_CONFLICT")
            ledger.db.execute("INSERT OR IGNORE INTO metadata VALUES ('capsule_gateway_id',?)",(gateway_id,))
            ledger.db.execute("INSERT OR IGNORE INTO metadata VALUES ('capsule_schema_version','1')")
            public = private_key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
            registered = ledger.db.execute("SELECT public_key FROM capsule_public_keys WHERE key_id=?",(signing_key_id,)).fetchone()
            if registered and registered[0] != public:
                raise LedgerRefused("SIGNING_KEY_ID_BINDING_CONFLICT")
            ledger.db.execute("INSERT OR IGNORE INTO capsule_public_keys VALUES (?,?)",(signing_key_id,public))
            if ledger.db.execute("SELECT COUNT(*) FROM capsule_public_keys").fetchone()[0] > 16:
                raise LedgerRefused("SIGNING_KEY_REGISTRY_CAPACITY")
            self._check_capacity()
            keys = self._public_keys()
            for row in ledger.db.execute("SELECT * FROM sealed_capsules"):
                verified = verify_artifact(bytes(row["body"]),keys,{ledger.digest:ledger.contract})
                body = verified.body
                if (not isinstance(body,CapsuleBody) or body.capsule_id != row["identity"]
                        or body.ledger_epoch != row["epoch"] or body.device_id != row["device"]
                        or body.window_index != row["idx"] or artifact_digest(row["body"]) != row["digest"]):
                    raise LedgerRefused("CORRUPT_STORED_CAPSULE")
            for head in ledger.db.execute("SELECT * FROM capsule_heads"):
                latest = ledger.db.execute("SELECT * FROM sealed_capsules WHERE device=? ORDER BY idx DESC LIMIT 1",(head["device"],)).fetchone()
                if latest is None or (latest["epoch"],latest["idx"],latest["digest"]) != (head["epoch"],head["idx"],head["digest"]):
                    raise LedgerRefused("CORRUPT_CAPSULE_HEAD")
            if ledger.db.execute("SELECT COUNT(DISTINCT device) FROM sealed_capsules").fetchone()[0] != ledger.db.execute("SELECT COUNT(*) FROM capsule_heads").fetchone()[0]:
                raise LedgerRefused("CORRUPT_CAPSULE_HEAD")
        ledger._window_has_reason = True

    def _public_keys(self):
        return {(self.gateway_id,row["key_id"]):Ed25519PublicKey.from_public_bytes(row["public_key"])
                for row in self.ledger.db.execute("SELECT * FROM capsule_public_keys")}

    def _check_capacity(self):
        count,total = self.ledger.db.execute("SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM sealed_capsules").fetchone()
        if count > self.limits.max_capsules or total > self.limits.max_signed_bytes:
            raise LedgerRefused("SEALED_EVIDENCE_CAPACITY",429)

    def seal(self, *, device_id, window_index, epoch=None, accounting=None):
        ledger = self.ledger
        with ledger._mutex:
            ledger._ensure_open()
            window = WindowIdentity(ledger_epoch=epoch or ledger.epoch,device_id=device_id,
                                    window_index=window_index,contract_hash=ledger.digest)
            identity = scope_id(self.gateway_id,window)
            cached = ledger.db.execute("SELECT * FROM sealed_capsules WHERE identity=?",(identity,)).fetchone()
            if cached:
                if artifact_digest(cached["body"]) != cached["digest"]:
                    raise LedgerRefused("CORRUPT_STORED_CAPSULE")
                verify_artifact(bytes(cached["body"]),self._public_keys(),{ledger.digest:ledger.contract})
                return bytes(cached["body"])
            row = ledger.db.execute("SELECT * FROM windows WHERE epoch=? AND device=? AND idx=?",
                                    (window.ledger_epoch,device_id,window_index)).fetchone()
            if row is None or not row["closed"]:
                raise LedgerRefused("ONLY_RETAINED_CLOSED_SCOPES_CAN_SEAL")
            head = ledger.db.execute("SELECT * FROM capsule_heads WHERE device=?",(device_id,)).fetchone()
            if head and window_index <= head["idx"]:
                raise LedgerRefused("CAPSULE_ORDER_OR_RESEAL_REFUSED")
            count,size = ledger.db.execute("SELECT COUNT(*),COALESCE(SUM(size),0) FROM observations WHERE epoch=? AND device=? AND idx=?",
                                          (window.ledger_epoch,device_id,window_index)).fetchone()
            if count > MAX_INPUT_RECORDS or size > MAX_INPUT_SCOPE_BYTES:
                raise EvidenceError("INPUT_SCOPE_LIMIT")
            rows = ledger.db.execute("SELECT * FROM observations WHERE epoch=? AND device=? AND idx=? ORDER BY seq",
                                      (window.ledger_epoch,device_id,window_index)).fetchall()
            records = tuple(InputRecord.from_ledger(record) for record in rows)
            if len(records) != row["accepted"]:
                raise LedgerRefused("INCONSISTENT_SEAL_POPULATION")
            pending = sum(record["disposition"] == "PENDING_POLICY" for record in rows)
            archived = sum(record["disposition"] == "ARCHIVED_LOCAL" for record in rows)
            reason = row["closure_reason"] or "LEGACY_CLOSURE"
            limitations = tuple(CoverageLimitation(item) for item in json.loads(row["limitations"]))
            if reason == "LEGACY_CLOSURE" and CoverageLimitation.INTERRUPTED not in limitations:
                limitations += (CoverageLimitation.INTERRUPTED,)
            body = build_capsule(contract=ledger.contract,window=window,records=records,
                gateway_id=self.gateway_id,signing_key_id=self.key_id,created_at_utc_us=utc_microseconds(ledger.clock.utc_now()),
                closure_reason=reason,limitations=limitations,accounting=accounting or RawAccounting(pending_policy=pending,archived_local=archived),
                previous_digest=head["digest"] if head and head["epoch"] == window.ledger_epoch else None)
            persisted = {fact.condition_id:fact for fact in ledger.facts() if fact.window == window}
            if set(persisted) != {fact.condition_id for fact in body.per_condition_facts}:
                raise LedgerRefused("INCONSISTENT_SEAL_FACT_SET")
            for fact in body.per_condition_facts:
                original = persisted[fact.condition_id]
                if (original.matching_count,original.nonmatching_count,original.unresolved_count) != (fact.matching_count,fact.nonmatching_count,fact.unresolved_count):
                    raise LedgerRefused("INCONSISTENT_SEAL_FACTS")
            encoded = sign_artifact(body,self.key)
            digest = artifact_digest(encoded)
            try:
                with ledger._transaction():
                    ledger.db.execute("INSERT INTO sealed_capsules VALUES (?,?,?,?,?,?)",
                                      (identity,window.ledger_epoch,device_id,window_index,encoded,digest))
                    ledger.db.execute("INSERT INTO capsule_heads VALUES (?,?,?,?) ON CONFLICT(device) DO UPDATE SET epoch=excluded.epoch,idx=excluded.idx,digest=excluded.digest",
                                      (device_id,window.ledger_epoch,window_index,digest))
                    self._check_capacity()
                    ledger.fault("before_capsule_commit",ledger.db)
                ledger.fault("after_capsule_commit",ledger.db)
                return encoded
            except sqlite3.Error as exc:
                ledger._failed = True
                raise LedgerRefused("STORAGE_UNAVAILABLE") from exc

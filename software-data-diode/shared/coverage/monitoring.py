"""Fog-local transactional rule monitor and durable alert delivery authority."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import time
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field, model_validator

from shared.http import strict_json
from shared.models import AlertRecord, AlertSeverity
from shared.security.crypto import canonical_bytes
from .capsules import EvidenceError, InputRecord, artifact_digest, verify_artifact
from .models import FrozenModel, Identifier
from .rules import EVALUATOR_VERSION, MODE, VerifiedScope, checked_witnesses, evaluate_window
from .verification import VerificationRecord


class RulePolicy(FrozenModel):
    rule_id: Identifier
    severity: AlertSeverity
    cooldown_windows: int = Field(default=3, strict=True, ge=0, le=360)


class MonitoringConfig(FrozenModel):
    evidence_grace_seconds: int = Field(default=20, strict=True, ge=0, le=300)
    visibility_cooldown_windows: int = Field(default=30, strict=True, ge=0, le=360)
    max_active_windows: int = Field(default=120, strict=True, ge=30, le=360)
    max_tick_windows: int = Field(default=6, strict=True, ge=1, le=12)
    policies: tuple[RulePolicy, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def unique_rules(self):
        if len({p.rule_id for p in self.policies}) != len(self.policies):
            raise ValueError("duplicate monitoring policy")
        return self

    @classmethod
    def load(cls, path):
        encoded = Path(path).read_bytes()
        if len(encoded) > 65536:
            raise ValueError("monitoring config exceeds limit")
        return cls.model_validate(strict_json(encoded))


class CoverageMonitor:
    def __init__(self, framer, config, *, now_us=None):
        self.framer, self.config = framer, config
        self.now = now_us or (lambda: time.time_ns()//1000)
        if {p.rule_id for p in config.policies} != {r.rule_id for r in framer.contract.rules}:
            raise ValueError("alert policy rule set must equal the provisioned contract")
        self.config_digest = hashlib.sha256(canonical_bytes(config.model_dump(mode="json"))).hexdigest()

    def _epoch(self, cursor):
        p = self.framer.profile
        binding = {"key": p.signing_key_id, "public_key": p.public_key_sha256,
                   "contract": p.contract_hash, "replay_width": max(2, self.framer.config.freshness_seconds//10)}
        cursor.execute("INSERT INTO coverage_epochs (gateway_id,ledger_epoch,binding) VALUES (%s,%s,%s::jsonb) ON CONFLICT DO NOTHING",
                       (p.gateway_id, p.ledger_epoch, json.dumps(binding)))
        cursor.execute("SELECT binding,retired FROM coverage_epochs WHERE gateway_id=%s AND ledger_epoch=%s FOR UPDATE", (p.gateway_id,p.ledger_epoch))
        stored, retired = cursor.fetchone()
        if stored != binding:
            raise EvidenceError("MONITOR_TRUST_BINDING_CHANGED")
        return retired

    def process_one(self, repository):
        p, now = self.framer.profile, self.now()
        with repository._connect() as connection, connection.cursor() as cursor:
            retired = self._epoch(cursor)
            key = (p.gateway_id,p.ledger_epoch,p.contract_hash)
            cursor.execute("INSERT INTO coverage_monitor_state VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                           (*key,self.config_digest,now//10000000-1,now))
            cursor.execute("SELECT config_digest,next_window,last_tick_us FROM coverage_monitor_state WHERE gateway_id=%s AND ledger_epoch=%s AND contract_hash=%s FOR UPDATE", key)
            digest, next_window, last_tick = cursor.fetchone()
            if digest != self.config_digest:
                raise EvidenceError("MONITOR_CONFIG_CHANGE_REQUIRES_OPERATOR_MIGRATION")
            cursor.execute("""SELECT s.window_index FROM coverage_publications p JOIN coverage_scopes s USING(scope_id)
                WHERE s.gateway_id=%s AND s.ledger_epoch=%s AND s.contract_hash=%s AND p.published_revision<p.revision
                ORDER BY s.window_index,s.scope_id LIMIT 1""", (p.gateway_id,p.ledger_epoch,p.contract_hash))
            row = cursor.fetchone()
            if row:
                window = row[0]
                # Same lock order as N6: epoch first, then publication rows.
                cursor.execute("""SELECT p.scope_id,p.revision FROM coverage_publications p JOIN coverage_scopes s USING(scope_id)
                    WHERE s.gateway_id=%s AND s.ledger_epoch=%s AND s.contract_hash=%s AND s.window_index=%s
                    ORDER BY p.scope_id FOR UPDATE OF p""", (p.gateway_id,p.ledger_epoch,p.contract_hash,window))
                publications = cursor.fetchall()
                self._evaluate(cursor, window, now, retired)
                for scope, revision in publications:
                    cursor.execute("UPDATE coverage_publications SET published_revision=%s WHERE scope_id=%s", (revision,scope))
                return "EVIDENCE_WINDOW"
            if retired:
                return None
            if now < last_tick:
                cursor.execute("INSERT INTO coverage_monitor_gaps VALUES (%s,%s,%s,%s,%s,'FOG_CLOCK_REGRESSION') ON CONFLICT DO NOTHING", (*key,now//10000000,last_tick//10000000))
                return "CLOCK_LIMITATION"
            deadline = (now-self.config.evidence_grace_seconds*1000000)//10000000-1
            if next_window < deadline-self.config.max_active_windows:
                cursor.execute("INSERT INTO coverage_monitor_gaps VALUES (%s,%s,%s,%s,%s,'FOG_MONITOR_DOWNTIME') ON CONFLICT DO NOTHING",
                               (*key,next_window,deadline-1))
                next_window = deadline
            stop = min(deadline+1,next_window+self.config.max_tick_windows)
            for window in range(next_window, stop):
                self._evaluate(cursor, window, now, False)
            cursor.execute("UPDATE coverage_monitor_state SET next_window=%s,last_tick_us=%s WHERE gateway_id=%s AND ledger_epoch=%s AND contract_hash=%s",
                           (max(next_window,stop),now,*key))
            return "DEADLINE_WINDOWS" if stop > next_window else None

    def _load(self, cursor, window, retired):
        p, scopes, unavailable = self.framer.profile, [], {}
        cursor.execute("""SELECT s.device_id,s.quarantined,c.artifact_digest,c.encoded,c.verification
            FROM coverage_scopes s CROSS JOIN LATERAL
            (SELECT artifact_digest,encoded,verification FROM coverage_capsules WHERE scope_id=s.scope_id ORDER BY artifact_digest LIMIT 2) c
            WHERE s.gateway_id=%s AND s.ledger_epoch=%s AND s.contract_hash=%s AND s.window_index=%s ORDER BY s.device_id,c.artifact_digest""",
            (p.gateway_id,p.ledger_epoch,p.contract_hash,window))
        for device, quarantined, digest, encoded, verification in cursor.fetchall():
            try:
                encoded = bytes(encoded)
                body = verify_artifact(encoded,self.framer.keys,self.framer.contracts).body
                if artifact_digest(encoded) != digest or body.device_id != device or body.window_index != window:
                    raise EvidenceError("PERSISTED_BODY_SCOPE_MISMATCH")
                record = VerificationRecord.model_validate(verification)
                cursor.execute("SELECT ingress_sequence,input_hash,ingress_utc_us,canonical_input FROM coverage_original_witnesses WHERE artifact_digest=%s ORDER BY ingress_sequence LIMIT 129", (digest,))
                originals = tuple(InputRecord(ledger_epoch=body.ledger_epoch,device_id=device,ingress_sequence=seq,
                    input_hash=ih,ingress_utc_us=stamp,canonical_input=bytes(raw)) for seq,ih,stamp,raw in cursor.fetchall())
                scopes.append(VerifiedScope(body,digest,record,quarantined,retired,originals))
            except (ValueError, TypeError, AttributeError):
                unavailable[device] = "UNSUPPORTED_OR_CORRUPT_EVIDENCE"
        cursor.execute("""SELECT details->'authenticated_scope'->>'device_id' FROM coverage_outcomes
            WHERE reason_code IN ('EXPIRED_EVIDENCE','EXPIRED_EVIDENCE_WINDOW')
            AND details->'authenticated_scope'->>'gateway_id'=%s AND details->'authenticated_scope'->>'ledger_epoch'=%s
            AND details->'authenticated_scope'->>'contract_hash'=%s AND details->'authenticated_scope'->>'window_index'=%s LIMIT 16""",
            (p.gateway_id,p.ledger_epoch,p.contract_hash,str(window)))
        for row in cursor.fetchall():
            unavailable.setdefault(row[0],"AUTHENTICATED_EVIDENCE_EXPIRED")
        return scopes, unavailable

    def _evaluate(self, cursor, window, now, retired):
        p = self.framer.profile
        scopes, unavailable = self._load(cursor,window,retired)
        results = evaluate_window(self.framer.contract,gateway_id=p.gateway_id,ledger_epoch=p.ledger_epoch,
                                  window_index=window,scopes=scopes,unavailable=unavailable)
        for result in results:
            key = (p.gateway_id,p.ledger_epoch,p.contract_hash,window,result["rule_id"])
            cursor.execute("""INSERT INTO coverage_rule_verdicts
                (gateway_id,ledger_epoch,contract_hash,window_index,rule_id,verdict,verification_status,evidence,reasons,verifier_version,decision_id,result)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s,%s::jsonb)
                ON CONFLICT (gateway_id,ledger_epoch,contract_hash,window_index,rule_id) DO UPDATE SET
                verdict=excluded.verdict,verification_status=excluded.verification_status,evidence=excluded.evidence,
                reasons=excluded.reasons,verifier_version=excluded.verifier_version,decision_id=excluded.decision_id,result=excluded.result""",
                (*key,result["truth"],result["verification_status"],json.dumps(result["supporting_artifacts"]),
                 json.dumps(result["reason_codes"]),EVALUATOR_VERSION,result["decision_id"],json.dumps(result)))
            cursor.execute("SELECT revision FROM coverage_rule_verdicts WHERE decision_id=%s", (result["decision_id"],))
            result_revision = cursor.fetchone()[0]
            policy = next(a for a in self.config.policies if a.rule_id == result["rule_id"])
            self._intent(cursor,result,result_revision,"INCIDENT",result["truth"] == "TRUE",policy.severity,policy.cooldown_windows)
            self._intent(cursor,result,result_revision,"VISIBILITY",not result["coverage_complete"],AlertSeverity.WARNING,self.config.visibility_cooldown_windows)

    def _intent(self, cursor, result, revision, kind, wanted, severity, cooldown):
        alert_id = uuid5(NAMESPACE_URL,"RCCD-ALERT-V1:"+result["decision_id"]+":"+kind)
        cursor.execute("SELECT active,payload,reason FROM coverage_alert_intents WHERE alert_id=%s", (alert_id,))
        existing = cursor.fetchone()
        if not wanted and existing is None:
            return
        key = (result["gateway_id"],result["ledger_epoch"],result["contract_hash"],result["rule_id"],kind)
        allowed, reason = wanted, "SCOPED_RULE_TRUE" if kind == "INCIDENT" else "OBSERVATION_DEGRADED_NOT_ATTACK"
        if existing and existing[2] == "COOLDOWN_SUPPRESSED":
            allowed, reason = False, "COOLDOWN_SUPPRESSED"
        elif wanted and existing is None:
            cursor.execute("SELECT last_window FROM coverage_alert_cooldowns WHERE gateway_id=%s AND ledger_epoch=%s AND contract_hash=%s AND rule_id=%s AND kind=%s", key)
            head = cursor.fetchone()
            if head and (result["window_index"] < head[0] or result["window_index"] < head[0]+cooldown):
                allowed, reason = False,"COOLDOWN_SUPPRESSED"
            if allowed:
                cursor.execute("INSERT INTO coverage_alert_cooldowns VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (gateway_id,ledger_epoch,contract_hash,rule_id,kind) DO UPDATE SET last_window=GREATEST(coverage_alert_cooldowns.last_window,excluded.last_window)", (*key,result["window_index"]))
        if not wanted:
            reason = "DECISION_REASSESSED" if kind == "INCIDENT" else "OBSERVATION_RECOVERED"
        stamp = datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(microseconds=(result["window_index"]+1)*10000000)
        description = ("Synthetic registered rule matched in accepted gateway ingress. "+result["quantifier"] if kind == "INCIDENT" else
            "Observation coverage is degraded. Missing, expired or unsupported evidence does not establish an attack.")
        alert = AlertRecord(alert_id=alert_id,timestamp=stamp,source_devices=result["source_devices"],
            alert_type="COVERAGE_RULE_INCIDENT" if kind == "INCIDENT" else "COVERAGE_VISIBILITY",severity=severity,
            evidence=[{"mode":MODE,"decision_id":result["decision_id"],"decision_revision":revision,
                "decision_status":result["truth"],"contract_hash":result["contract_hash"],"ledger_epoch":result["ledger_epoch"],
                "window_index":result["window_index"],"supporting_artifacts":result["supporting_artifacts"],
                "checked_original_witnesses":result["checked_original_witnesses"],"coverage_health":result["coverage_health"],"reason_codes":result["reason_codes"]}],
            description=description)
        payload = alert.model_dump(mode="json")
        if existing and existing == (allowed,payload,reason):
            return
        cursor.execute("""INSERT INTO coverage_alert_intents (alert_id,decision_id,kind,active,payload,reason,delivered_revision)
            VALUES (%s,%s,%s,%s,%s::jsonb,%s,%s) ON CONFLICT (alert_id) DO UPDATE SET active=excluded.active,
            payload=excluded.payload,reason=excluded.reason,delivery_revision=coverage_alert_intents.delivery_revision+1""",
            (alert_id,result["decision_id"],kind,allowed,json.dumps(payload),reason,1 if reason == "COOLDOWN_SUPPRESSED" else 0))


def pending_alert(repository):
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT alert_id,delivery_revision FROM coverage_alert_intents WHERE delivered_revision<delivery_revision ORDER BY alert_id LIMIT 1")
        row = cursor.fetchone()
        return {"alert_id":str(row[0]),"revision":row[1]} if row else None


def store_original_witness(repository, framer, digest, record):
    record = InputRecord.model_validate(record)
    monitor = CoverageMonitor(framer,MonitoringConfig(policies=tuple(RulePolicy(rule_id=r.rule_id,severity=AlertSeverity.HIGH) for r in framer.contract.rules)))
    with repository._connect() as connection, connection.cursor() as cursor:
        if monitor._epoch(cursor):
            raise EvidenceError("RETIRED_WITNESS_EPOCH")
        cursor.execute("SELECT encoded,verification,scope_id FROM coverage_capsules WHERE artifact_digest=%s", (digest,))
        row = cursor.fetchone()
        if row is None:
            raise EvidenceError("NO_AUTHENTICATED_WITNESS_REFERENCE")
        body = verify_artifact(bytes(row[0]),framer.keys,framer.contracts).body
        cursor.execute("SELECT ingress_sequence,input_hash,ingress_utc_us,canonical_input FROM coverage_original_witnesses WHERE artifact_digest=%s ORDER BY ingress_sequence LIMIT 129", (digest,))
        retained = tuple(InputRecord(ledger_epoch=body.ledger_epoch,device_id=body.device_id,ingress_sequence=seq,
            input_hash=ih,ingress_utc_us=stamp,canonical_input=bytes(raw)) for seq,ih,stamp,raw in cursor.fetchall())
        previous = next((r for r in retained if r.ingress_sequence == record.ingress_sequence),None)
        if previous:
            if previous != record:
                raise EvidenceError("ORIGINAL_WITNESS_IDENTITY_CONFLICT")
            return False
        contradiction = None
        try:
            checked_witnesses(VerifiedScope(body,digest,VerificationRecord.model_validate(row[1]),originals=(*retained,record)),framer.contract)
        except EvidenceError as exc:
            if not str(exc).startswith("AUTHENTICATED_WITNESS_CONTRADICTS"):
                raise
            contradiction = str(exc)
        cursor.execute("INSERT INTO coverage_original_witnesses VALUES (%s,%s,%s,%s,%s)", (digest,record.ingress_sequence,record.input_hash,record.ingress_utc_us,record.canonical_input))
        if contradiction:
            cursor.execute("UPDATE coverage_scopes SET quarantined=TRUE WHERE scope_id=%s", (row[2],))
            cursor.execute("""UPDATE coverage_capsules SET verification=verification ||
                '{"status":"CONFLICT","reason_codes":["AUTHENTICATED_WITNESS_CONTRADICTION"]}'::jsonb WHERE scope_id=%s""", (row[2],))
            cursor.execute("""UPDATE coverage_rule_verdicts SET verdict='UNKNOWN',verification_status='CONFLICT',verifier_version='rccd-fog-verifier-v1',
                reasons='["AUTHENTICATED_WITNESS_CONTRADICTION"]'::jsonb WHERE gateway_id=%s AND ledger_epoch=%s AND contract_hash=%s AND window_index=%s""",
                (body.gateway_id,body.ledger_epoch,body.contract_hash,body.window_index))
        cursor.execute("UPDATE coverage_publications SET revision=revision+1 WHERE scope_id=%s", (row[2],))
        return "QUARANTINED" if contradiction else True

"""Bounded, read-only N8 queries. No Edge connections or ledger access."""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from shared.coverage.contracts import contract_hash


class CoverageQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    gateway_id: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    ledger_epoch: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    contract_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    rule_id: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    device_id: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    truth: Literal["TRUE", "FALSE", "UNKNOWN"] | None = None
    start_window: int = Field(default=0, ge=0, le=2**60)
    end_window: int = Field(default=2**60, ge=0, le=2**60)
    limit: int = Field(default=25, ge=1, le=100)
    before_window: int | None = Field(default=None, ge=0, le=2**60)
    before_id: UUID | None = None

    @model_validator(mode="after")
    def bounds(self):
        if self.end_window < self.start_window:
            raise ValueError("end_window must be at least start_window")
        if (self.before_window is None) != (self.before_id is None):
            raise ValueError("both cursor fields are required")
        return self


def rows(connection, sql, params=()):
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        return list(cursor.fetchall())


def predicate(query, alias="v", *, page=False):
    clauses = [f"{alias}.decision_id IS NOT NULL", f"{alias}.window_index BETWEEN %s AND %s"]
    params = [query.start_window, query.end_window]
    for name in ("gateway_id", "ledger_epoch", "contract_hash", "rule_id"):
        value = getattr(query, name)
        if value is not None:
            clauses.append(f"{alias}.{name}=%s")
            params.append(value)
    if query.truth:
        clauses.append(f"{alias}.verdict=%s")
        params.append(query.truth)
    if query.device_id:
        clauses.append(f"{alias}.result->'source_devices' ? %s")
        params.append(query.device_id)
    if page and query.before_id is not None:
        clauses.append(f"({alias}.window_index,{alias}.decision_id)<(%s,%s)")
        params.extend((query.before_window, query.before_id))
    return " AND ".join(clauses), tuple(params)


def verdict_page(connection, query):
    where, params = predicate(query, page=True)
    found = rows(connection, f"""SELECT decision_id,window_index,rule_id,verdict,revision,
        contract_hash,gateway_id,ledger_epoch,verification_status,reasons,result,updated_at
        FROM coverage_rule_verdicts v WHERE {where}
        ORDER BY window_index DESC,decision_id DESC LIMIT %s""", (*params, query.limit+1))
    items = found[:query.limit]
    last = items[-1] if items and len(found) > query.limit else None
    return {"items": items, "next_cursor": {"before_window": last["window_index"],
            "before_id": str(last["decision_id"])} if last else None,
            "scope": "LATEST_REVISION_PER_RULE_WINDOW", "limit": query.limit,
            "filters": query.model_dump(mode="json")}


def sender_accounting(snapshot):
    """Never divide historical Fog bytes by a different sender lifetime."""
    metrics = snapshot.get("metrics", {}) if snapshot else {}
    accounting = metrics.get("forward_byte_accounting") or {}
    total = accounting.get("total", 0)
    evidence = accounting.get("EVIDENCE", 0)
    valid = (accounting.get("scope") == "N8_LOCAL_GRANTS_SINCE_START"
             and all(type(accounting.get(k)) is int and 0 <= accounting[k] <= 2**63-1
                     for k in ("total", "RAW", "EVIDENCE", "STATE"))
             and sum(accounting[k] for k in ("RAW", "EVIDENCE", "STATE")) == total)
    return {"reported_at": snapshot.get("timestamp") if snapshot else None,
            "binding": snapshot.get("labels", {}) if snapshot else {},
            "assurance": "AUTHENTICATED_FORWARD_STATE", "receipt": "NOT_OBSERVED",
            "scope": accounting.get("scope") if valid else "UNAVAILABLE",
            "start_utc_us": accounting.get("start_utc_us") if valid else None,
            "bytes": accounting if valid else None,
            "evidence_fraction": evidence/total if valid and total else None,
            "pending_reserved_bytes": metrics.get("reserved_wire_bytes"),
            "pending_obligations": metrics.get("pending_evidence_obligations"),
            "fraction_reason": "MATCHED_LOCAL_GRANTS_INCLUDING_REPEATS_AND_MODELED_OVERHEAD" if valid
                               else "MATCHED_SENDER_BYTE_COUNTERS_NOT_AVAILABLE"}


def overview(connection, query, contract):
    where, params = predicate(query)
    counts = rows(connection, f"""SELECT COUNT(*) AS opportunities,
        COUNT(*) FILTER(WHERE verdict!='UNKNOWN') AS definite,
        COUNT(*) FILTER(WHERE verdict='UNKNOWN') AS unknown,
        COUNT(*) FILTER(WHERE verdict='TRUE') AS positive,
        COUNT(*) FILTER(WHERE verdict='FALSE') AS negative
        FROM coverage_rule_verdicts v WHERE {where}""", params)[0]
    count = counts["opportunities"]
    counts.update(definite_yield=counts["definite"]/count if count else None,
                  unknown_rate=counts["unknown"]/count if count else None,
                  scope="FILTERED_PERSISTED_LATEST_RULE_WINDOWS_NOT_ORACLE_ACCURACY")
    # DISTINCT scopes prevent multi-rule dependencies from multiplying byte totals.
    byte_where = ["s.window_index BETWEEN %s AND %s"]
    byte_params = [query.start_window, query.end_window]
    for name in ("gateway_id", "ledger_epoch", "contract_hash", "device_id"):
        if getattr(query, name):
            byte_where.append(f"s.{name}=%s")
            byte_params.append(getattr(query, name))
    if query.rule_id or query.truth:
        byte_where.append(f"""EXISTS(SELECT 1 FROM coverage_rule_verdicts v WHERE {where}
            AND v.gateway_id=s.gateway_id AND v.ledger_epoch=s.ledger_epoch
            AND v.contract_hash=s.contract_hash AND v.window_index=s.window_index
            AND v.result->'source_devices' ? s.device_id)""")
        byte_params.extend(params)
    bw = " AND ".join(byte_where)
    cost = rows(connection, f"""SELECT COUNT(*) AS capsules,
        COALESCE(SUM(p.transport_bytes),0) AS received_evidence_bytes,
        COALESCE(SUM(octet_length(c.encoded)),0) AS signed_body_bytes,
        COUNT(*) FILTER(WHERE s.quarantined) AS conflicting_capsules
        FROM coverage_capsules c JOIN coverage_scopes s USING(scope_id)
        LEFT JOIN coverage_performance p USING(artifact_digest) WHERE {bw}""", tuple(byte_params))[0]
    cost["scope"] = "PERSISTED_UNIQUE_COMPLETE_CAPSULE_PART_PAYLOADS_EXCLUDES_LOST_REPEATS_AND_NETWORK_OVERHEAD"
    devices = []
    now_us = int(datetime.now(timezone.utc).timestamp()*1_000_000)
    for device in contract.devices:
        if query.device_id and device.device_id != query.device_id:
            continue
        device_query = query.model_copy(update={"device_id": device.device_id, "rule_id": None, "truth": None})
        device_where, device_params = predicate(device_query)
        latest = rows(connection, f"""SELECT window_index,result,updated_at FROM coverage_rule_verdicts v
            WHERE {device_where} ORDER BY window_index DESC,decision_id DESC LIMIT 1""", device_params)
        result = latest[0]["result"] if latest else {}
        status = result.get("coverage_health", {}).get("devices", {}).get(device.device_id, "MISSING")
        # The newest rule window can lack evidence even if an older capsule exists.
        window = latest[0]["window_index"] if latest else None
        evidence_where = ["s.device_id=%s", "s.window_index BETWEEN %s AND %s"]
        evidence_params = [device.device_id, query.start_window, query.end_window]
        for name in ("gateway_id", "ledger_epoch", "contract_hash"):
            if getattr(query, name):
                evidence_where.append(f"s.{name}=%s")
                evidence_params.append(getattr(query, name))
        evidence = rows(connection, f"""SELECT s.window_index,c.received_at_us FROM coverage_capsules c
            JOIN coverage_scopes s USING(scope_id) JOIN coverage_epochs e USING(gateway_id,ledger_epoch)
            WHERE {' AND '.join(evidence_where)} AND NOT s.quarantined AND NOT e.retired
            ORDER BY s.window_index DESC,c.received_at_us DESC LIMIT 1""", tuple(evidence_params))
        evidence_window = evidence[0]["window_index"] if evidence else None
        age = max(0, (now_us-(evidence_window+1)*10_000_000)/1_000_000) if evidence_window is not None else None
        devices.append({"device_id": device.device_id, "window_index": window,
                        "artifact_state": status, "latest_capsule_window": evidence_window, "age_seconds": age,
                        "freshness": "STALE" if age is not None and age > 40 else "RECENT" if age is not None else "MISSING",
                        "device_health": "NOT_ASSESSED"})
    state = rows(connection, """SELECT timestamp,metrics,labels FROM latest_observability_snapshots
        WHERE service='edge-gateway' AND labels->>'assurance'='AUTHENTICATED_FORWARD_STATE'""")
    failures = rows(connection, "SELECT COUNT(*) AS count FROM coverage_outcomes WHERE reason_code!='EVIDENCE_COMMITTED'")[0]["count"]
    outcomes = rows(connection, """SELECT reason_code,COUNT(*) AS count FROM coverage_outcomes
        GROUP BY reason_code ORDER BY count DESC,reason_code LIMIT 32""")
    pending = rows(connection, "SELECT COUNT(*) AS count FROM coverage_publications WHERE published_revision<revision")[0]["count"]
    return {"observed_at": datetime.now(timezone.utc), "counts": counts, "cost": cost,
            "devices": devices, "sender": sender_accounting(state[0] if state else {}),
            "pending_fog_publications": pending, "verification_outcomes": outcomes, "verification_failures": failures,
            "outcome_scope": "ALL_PERSISTED_OUTCOMES_INCLUDING_VALID_NOT_FILTERED",
            "contract_hash": contract_hash(contract), "contract": contract.model_dump(mode="json"),
            "rules": [r.rule_id for r in contract.rules],
            "observation_scope": "accepted_normalized_gateway_ingress",
            "assurance": "AUTHENTICATED_SUMMARY", "offline_recomputation": "NOT_RUN_BY_DASHBOARD",
            "filters": query.model_dump(mode="json"),
            "sender_scope": "LATEST_PROVISIONED_SIGNED_STATE_NOT_FILTERED_BY_RULE_OR_TIME"}


def decision_detail(connection, identity, before_revision=None):
    found = rows(connection, "SELECT * FROM coverage_rule_verdicts WHERE decision_id=%s", (identity,))
    if not found:
        return None
    record = found[0]
    result = record["result"]
    devices = result.get("source_devices", [])[:16]
    capsules = rows(connection, """SELECT c.artifact_digest,c.scope_id,c.verification,c.body,
        s.quarantined,e.retired FROM coverage_capsules c JOIN coverage_scopes s USING(scope_id)
        JOIN coverage_epochs e USING(gateway_id,ledger_epoch)
        WHERE s.gateway_id=%s AND s.ledger_epoch=%s AND s.contract_hash=%s
        AND s.window_index=%s AND s.device_id=ANY(%s)
        ORDER BY c.artifact_digest LIMIT 33""", (record["gateway_id"], record["ledger_epoch"],
                 record["contract_hash"], record["window_index"], devices))
    history = rows(connection, """SELECT revision,record,recorded_at FROM coverage_rule_history
        WHERE decision_id=%s AND revision<%s ORDER BY revision DESC LIMIT 21""",
        (identity, before_revision if before_revision is not None else 2**63-1))
    alerts = rows(connection, """SELECT alert_id,kind,active,reason,delivery_revision,delivered_revision
        FROM coverage_alert_intents WHERE decision_id=%s ORDER BY kind LIMIT 2""", (identity,))
    return {"decision": record, "capsules": capsules[:32], "capsules_truncated": len(capsules)>32,
            "missing_supporting_artifacts": sorted(set(result.get("supporting_artifacts", []))-
                  {c["artifact_digest"] for c in capsules}),
            "history": history[:20], "next_revision": history[19]["revision"] if len(history)>20 else None,
            "alerts": alerts, "assurance": "AUTHENTICATED_SUMMARY",
            "offline_recomputation": "NOT_RUN_BY_DASHBOARD"}


def capsule_detail(connection, digest):
    found = rows(connection, """SELECT c.artifact_digest,c.scope_id,c.body,c.verification,c.encoded,
        c.received_at_us,s.quarantined,e.retired FROM coverage_capsules c
        JOIN coverage_scopes s USING(scope_id) JOIN coverage_epochs e USING(gateway_id,ledger_epoch)
        WHERE artifact_digest=%s""", (digest,))
    if not found:
        return None
    record = found[0]
    record["signed_artifact"] = json.loads(bytes(record.pop("encoded")))
    record["parts"] = rows(connection, """SELECT part_index,octet_length(encoded) AS bytes
        FROM coverage_parts WHERE artifact_digest=%s ORDER BY part_index LIMIT 96""", (digest,))
    record["witness_references"] = rows(connection, """SELECT ingress_sequence,input_hash,ingress_utc_us
        FROM coverage_original_witnesses WHERE artifact_digest=%s ORDER BY ingress_sequence LIMIT 128""", (digest,))
    record["conflicts"] = rows(connection, """SELECT first_digest,second_digest,timestamp FROM coverage_conflicts
        WHERE scope_id=%s ORDER BY timestamp DESC LIMIT 32""", (record["scope_id"],))
    return record


def witnesses(connection, digest, after_sequence=0, limit=8):
    found = rows(connection, """SELECT ingress_sequence,input_hash,ingress_utc_us,canonical_input
        FROM coverage_original_witnesses WHERE artifact_digest=%s AND ingress_sequence>%s
        ORDER BY ingress_sequence LIMIT %s""", (digest, after_sequence, limit+1))
    items = found[:limit]
    for item in items:
        item["canonical_input_base64"] = base64.b64encode(bytes(item.pop("canonical_input"))).decode("ascii")
    return {"items": items, "next_sequence": items[-1]["ingress_sequence"] if len(found)>limit else None,
            "assurance": "CHECKED_DISCLOSED_ORIGINALS_NOT_FULL_RAW_RECOMPUTATION"}

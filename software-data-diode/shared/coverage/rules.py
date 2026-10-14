"""N7 scoped decisions. Selected raw telemetry is never original-ingress proof."""
from dataclasses import dataclass
import json
from uuid import NAMESPACE_URL, uuid5

from .capsules import CapsuleBody, EvidenceError, InputRecord
from .contracts import contract_hash
from .evaluation import condition_facts, evaluate_condition, evaluate_rule
from .models import (ArtifactVerification, ConditionFacts, CoverageLimitation, IngressObservation,
                     MetricReading)

EVALUATOR_VERSION = "rccd-rules-v1"
MODE = "RCCD_SCOPED_RULES_V1"
LEGACY_BASELINE = "LEGACY_RECEIVED_PAYLOAD_BASELINE"


def decision_identity(gateway, epoch, contract, window, rule):
    return uuid5(NAMESPACE_URL, f"RCCD-RULE-V1:{gateway}:{epoch}:{contract}:{window}:{rule}")


@dataclass(frozen=True)
class VerifiedScope:
    body: CapsuleBody
    digest: str
    verification: object
    quarantined: bool = False
    retired: bool = False
    originals: tuple[InputRecord, ...] = ()


def original_observation(record, contract):
    document = json.loads(record.canonical_input)
    device = next(d for d in contract.devices if d.device_id == record.device_id)
    return IngressObservation(ledger_epoch=record.ledger_epoch, device_id=record.device_id,
        ingress_sequence=record.ingress_sequence, ingress_utc_us=record.ingress_utc_us,
        telemetry_type=document["telemetry_type"], metrics=tuple(MetricReading(path=m.path,
            value=document.get("measurements", {}).get(m.path.split(".", 1)[1]) if m.path.startswith("measurements.") else document.get(m.path))
            for m in device.metrics))


def checked_witnesses(scope, contract):
    """Disclosures are authenticated ONLY by an already signed RCC hash/reference."""
    body = scope.body
    references = {(w.ingress_sequence, w.input_hash) for f in body.per_condition_facts for w in f.witnesses}
    originals, identities, size = [], set(), 0
    for record in scope.originals:
        record = InputRecord.model_validate(record)
        size += len(record.canonical_input)
        if len(originals) >= 128 or size > 8*1024*1024:
            raise EvidenceError("ORIGINAL_WITNESS_BOUNDS")
        if (record.ledger_epoch != body.ledger_epoch or record.device_id != body.device_id
                or not body.window_start_utc_us <= record.ingress_utc_us < body.window_end_utc_us
                or (record.ingress_sequence, record.input_hash) not in references
                or record.ingress_sequence in identities):
            raise EvidenceError("UNAUTHENTICATED_OR_DUPLICATE_ORIGINAL_WITNESS")
        observation = original_observation(record, contract)
        for fact in body.per_condition_facts:
            if any(w.ingress_sequence == record.ingress_sequence and w.input_hash == record.input_hash for w in fact.witnesses):
                result = condition_facts(contract, fact.condition_id, body.window, [observation], population_complete=False)
                if result.matching_count != 1:
                    raise EvidenceError("AUTHENTICATED_WITNESS_CONTRADICTS_MATCHING_ASSERTION")
        originals.append(observation)
        identities.add(record.ingress_sequence)
    for fact in body.per_condition_facts:
        counts = condition_facts(contract,fact.condition_id,body.window,originals,population_complete=False)
        if any(getattr(counts,name) > getattr(fact,name) for name in ("matching_count","nonmatching_count","unresolved_count")):
            raise EvidenceError("AUTHENTICATED_WITNESS_CONTRADICTS_COUNTS")
    return tuple(originals)


def evaluate_window(contract, *, gateway_id, ledger_epoch, window_index, scopes=(), unavailable=None):
    digest = contract_hash(contract)
    unavailable = dict(unavailable or {})
    supplied, sources, witness_ids, scope_status = {}, {}, {}, {}
    matching = {}
    for scope in scopes:
        body, record = scope.body, scope.verification
        if (body.gateway_id, body.ledger_epoch, body.window_index, body.contract_hash) != (gateway_id, ledger_epoch, window_index, digest):
            continue
        matching.setdefault(body.device_id, []).append(scope)
    for device in contract.devices:
        candidates = matching.get(device.device_id, [])
        if not candidates:
            scope_status[device.device_id] = unavailable.get(device.device_id, "MISSING_EVIDENCE")
            continue
        if len({s.digest for s in candidates}) > 1 or any(s.quarantined or s.verification.status == "CONFLICT" for s in candidates):
            scope_status[device.device_id] = "CONFLICTING_SIGNED_SCOPE"
            continue
        scope = candidates[0]
        body, record = scope.body, scope.verification
        if scope.retired:
            scope_status[device.device_id] = "RETIRED_EPOCH"
            continue
        if (record.artifact_digest != scope.digest or record.scope_id != body.capsule_id
                or record.gateway_id != gateway_id or record.ledger_epoch != ledger_epoch
                or record.contract_hash != digest or record.device_id != device.device_id
                or record.window_index != window_index or record.status not in {"VALID", "LIMITED"}):
            scope_status[device.device_id] = "UNSUPPORTED_VERIFICATION_RECORD"
            continue
        try:
            originals = checked_witnesses(scope, contract)
        except EvidenceError:
            scope_status[device.device_id] = "AUTHENTICATED_WITNESS_CONFLICT"
            continue
        scope_status[device.device_id] = "LIMITED_EVIDENCE" if record.status == "LIMITED" else "VERIFIED_EVIDENCE"
        for fact in body.per_condition_facts:
            witness = condition_facts(contract, fact.condition_id, body.window, originals, population_complete=False)
            # A checked witness already belongs to the signed population. Never
            # sum the RCC count and its witness and manufacture COUNT_GE matches.
            lower = max(fact.matching_count, witness.matching_count)
            if lower != fact.matching_count:
                scope_status[device.device_id] = "AUTHENTICATED_WITNESS_CONFLICT"
                continue
            supplied[fact.condition_id] = ConditionFacts(window=body.window, condition_id=fact.condition_id,
                accepted_count=body.accepted_observation_count, matching_count=lower,
                nonmatching_count=fact.nonmatching_count, unresolved_count=fact.unresolved_count, closed=True,
                population_complete=body.population_complete and record.status == "VALID",
                limitations=body.coverage_limitations)
            sources[fact.condition_id] = scope.digest
            witness_ids[fact.condition_id] = [f"{body.ledger_epoch}:{body.device_id}:{w.ingress_sequence}:{w.input_hash}" for w in fact.witnesses
                if any(o.ingress_sequence == w.ingress_sequence for o in originals)]
    results = []
    all_complete = all(evaluate_condition(a,supplied.get(a.condition_id)).coverage_complete for a in contract.conditions)
    for rule in contract.rules:
        verdict = evaluate_rule(contract, rule.rule_id, ledger_epoch=ledger_epoch, window_index=window_index, facts=supplied.values())
        atom_ids = [v.condition_id for v in verdict.conditions]
        atoms = {a.condition_id: a for a in contract.conditions}
        devices = sorted({atoms[a].device_id for a in atom_ids})
        statuses = {d: scope_status[d] for d in devices}
        conflict = any("CONFLICT" in s for s in statuses.values())
        artifact_state = ArtifactVerification.CONFLICT if conflict else ArtifactVerification.VALID if any(a in sources for a in atom_ids) else ArtifactVerification.NOT_PERFORMED
        verdict = verdict.model_copy(update={"artifact_verification": artifact_state})
        bounds = {}
        for name in atom_ids:
            f = supplied.get(name)
            usable_time = f is not None and CoverageLimitation.CLOCK_DISCONTINUITY not in f.limitations
            bounds[name] = {"lower": f.matching_count if usable_time else 0,
                "upper": f.matching_count+f.unresolved_count if usable_time and f.closed and f.population_complete and not f.limitations else None}
        result = {"decision_id": str(decision_identity(gateway_id, ledger_epoch, digest, window_index, rule.rule_id)),
            "gateway_id": gateway_id, "evaluator_version": EVALUATOR_VERSION, "mode": MODE,
            "observation_scope": contract.observation_scope, "time_basis": contract.time_basis,
            "quantifier": "Each EXISTS needs at least one match and each COUNT_GE its registered count bound in the same gateway-ingress window; physical simultaneity is not asserted.",
            **verdict.model_dump(mode="json"), "condition_bounds": bounds, "source_devices": devices,
            "supporting_artifacts": sorted({sources[a] for a in verdict.supporting_conditions if a in sources}),
            "examined_artifacts": sorted({sources[a] for a in atom_ids if a in sources}),
            "checked_original_witnesses": sorted({w for a in atom_ids for w in witness_ids.get(a, [])}),
            "coverage_health": {"complete": all_complete, "rule_conditions_complete": verdict.coverage_complete,
                "state": "COMPLETE" if all_complete else "DEGRADED", "devices": scope_status,
                "device_health": "NOT_ASSESSED", "scope": "REGISTERED_CONDITIONS_THIS_WINDOW_ONLY"},
            "rule_device_status": statuses,
            "verification_status": "CONFLICT_PRESENT" if conflict else "VERIFIED" if verdict.coverage_complete else "PARTIAL_OR_MISSING",
            "reason_codes": sorted({v.reason for v in verdict.conditions} | {s for s in statuses.values() if s != "VERIFIED_EVIDENCE"})}
        results.append(result)
    return results

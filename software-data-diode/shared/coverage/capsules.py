"""Bounded authenticated assertions. No sockets, telemetry wrapping or key I/O."""
from __future__ import annotations

import base64
import hashlib
import math
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from pydantic import Field, StringConstraints, model_validator

from shared.http import strict_json
from shared.models import EdgeTelemetryMessage
from shared.security.crypto import canonical_bytes

from .contracts import contract_hash
from .evaluation import condition_facts
from .models import (ConditionFacts, Count, CoverageLimitation, Digest, FrozenModel, Identifier,
                     IngressObservation, MetricReading, PositiveCount, WindowIdentity, WindowIndex)


MAX_ARTIFACT_BYTES = 32768
MAX_INPUT_RECORDS = 10000
MAX_INPUT_SCOPE_BYTES = 8*1024*1024
BODY_DOMAIN = b"RCCD-EVIDENCE-BODY-V1\x00"
SIGN_DOMAIN = b"RCCD-EVIDENCE-SIGN-V1\x00"
ARTIFACT_DOMAIN = b"RCCD-EVIDENCE-ARTIFACT-V1\x00"
IDENTITY_DOMAIN = b"RCCD-CAPSULE-IDENTITY-V1\x00"
TRANSITION_DOMAIN = b"RCCD-TRANSITION-IDENTITY-V1\x00"
INPUT_SEED_DOMAIN = b"RCCD-INPUT-SEED-V1\x00"
INPUT_LEAF_DOMAIN = b"RCCD-INPUT-LEAF-V1\x00"
INPUT_FOLD_DOMAIN = b"RCCD-INPUT-FOLD-V1\x00"
Signature = Annotated[str, StringConstraints(strict=True, min_length=88, max_length=88)]
Microseconds = Annotated[int, Field(strict=True)]


class EvidenceError(ValueError):
    pass


class EvidenceConflict(EvidenceError):
    pass


class InputRecord(FrozenModel):
    ledger_epoch: Identifier
    device_id: Identifier
    ingress_sequence: PositiveCount
    ingress_utc_us: Microseconds
    canonical_input: Annotated[bytes, Field(strict=True, min_length=1, max_length=65536)]
    input_hash: Digest

    @model_validator(mode="after")
    def canonical_original(self):
        message = EdgeTelemetryMessage.model_validate(strict_json(self.canonical_input))
        if (message.device_id != self.device_id or canonical_bytes(message.model_dump(mode="json")) != self.canonical_input
                or hashlib.sha256(self.canonical_input).hexdigest() != self.input_hash):
            raise ValueError("noncanonical or inconsistent original input")
        return self

    @classmethod
    def from_ledger(cls, row):
        return cls(ledger_epoch=row["epoch"], device_id=row["device"], ingress_sequence=row["seq"],
                   ingress_utc_us=row["ingress_us"], canonical_input=row["body"], input_hash=row["input_hash"])


class InputCommitment(FrozenModel):
    construction: Literal["sha256-scope-seeded-input-fold-v1"] = "sha256-scope-seeded-input-fold-v1"
    root: Digest
    record_count: Count


class WitnessReference(FrozenModel):
    ingress_sequence: PositiveCount
    input_hash: Digest


class CapsuleFact(FrozenModel):
    condition_id: Identifier
    matching_count: Count
    nonmatching_count: Count
    unresolved_count: Count
    witnesses: tuple[WitnessReference, ...] = Field(default=(), max_length=2)

    @model_validator(mode="after")
    def witness_bounds(self):
        ids = [item.ingress_sequence for item in self.witnesses]
        if len(set(ids)) != len(ids) or len(ids) > self.matching_count:
            raise ValueError("duplicate/excess matching witness references")
        return self


class RawAccounting(FrozenModel):
    pending_policy: Count = 0
    selected_raw: Count = 0
    reduced_raw: Count = 0
    dropped_raw: Count = 0
    archived_local: Count = 0
    queue_overflow_drops: Count = 0
    raw_dispatch_attempts: Count = 0
    confirmed_receipt_count: Literal[None] = None
    receipt_assurance: Literal["NOT_OBSERVED"] = "NOT_OBSERVED"

    @model_validator(mode="after")
    def overflow_subset(self):
        if self.queue_overflow_drops > self.dropped_raw:
            raise ValueError("queue overflow is a subset of raw drops")
        return self

    @property
    def disposition_count(self):
        return self.pending_policy+self.selected_raw+self.reduced_raw+self.dropped_raw+self.archived_local


def scope_id(gateway_id: str, window: WindowIdentity) -> str:
    return hashlib.sha256(IDENTITY_DOMAIN+canonical_bytes({"gateway_id":gateway_id,
                            **window.model_dump(mode="json")})).hexdigest()


class CapsuleBody(FrozenModel):
    protocol_version: Literal["rccd-capsule-v1"] = "rccd-capsule-v1"
    artifact_kind: Literal["RCC"] = "RCC"
    scope_kind: Literal["WINDOW", "NO_INPUT"] = "WINDOW"
    gateway_id: Identifier
    signing_key_id: Identifier
    ledger_epoch: Identifier
    capsule_id: Digest
    contract_hash: Digest
    contract_profile: Literal["rccd-contract-v1"] = "rccd-contract-v1"
    device_id: Identifier
    window_index: WindowIndex
    window_start_utc_us: Microseconds
    window_end_utc_us: Microseconds
    time_basis: Literal["gateway_ingress_utc_microseconds"] = "gateway_ingress_utc_microseconds"
    observation_scope: Literal["accepted_normalized_gateway_ingress"] = "accepted_normalized_gateway_ingress"
    closure_reason: Literal["WINDOW_END", "NO_INPUT", "RECOVERY", "INTERRUPTED", "CLOCK_DISCONTINUITY", "LEGACY_CLOSURE"]
    ingress_first_sequence: PositiveCount | None = None
    ingress_last_sequence: PositiveCount | None = None
    accepted_observation_count: Annotated[Count, Field(le=MAX_INPUT_RECORDS)]
    input_commitment: InputCommitment
    per_condition_facts: tuple[CapsuleFact, ...] = Field(max_length=64)
    coverage_limitations: tuple[CoverageLimitation, ...] = Field(default=(), max_length=3)
    population_complete: bool = Field(default=True, strict=True)
    reduction_accounting: RawAccounting
    previous_capsule_digest: Digest | None = None
    created_at_utc_us: Microseconds
    online_assurance: Literal["AUTHENTICATED_SUMMARY"] = "AUTHENTICATED_SUMMARY"

    @property
    def window(self):
        return WindowIdentity(ledger_epoch=self.ledger_epoch, device_id=self.device_id,
                              window_index=self.window_index, contract_hash=self.contract_hash)

    @model_validator(mode="after")
    def consistent_scope(self):
        if self.capsule_id != scope_id(self.gateway_id, self.window):
            raise ValueError("capsule identity differs from immutable scope")
        if (self.window_start_utc_us != self.window.start_utc_us or self.window_end_utc_us != self.window.end_utc_us):
            raise ValueError("unaligned or inconsistent window")
        count = self.accepted_observation_count
        if count:
            if (self.scope_kind != "WINDOW" or self.ingress_first_sequence is None or self.ingress_last_sequence is None
                    or self.ingress_last_sequence-self.ingress_first_sequence+1 != count):
                raise ValueError("accepted range must be contiguous and match count")
        elif self.scope_kind != "NO_INPUT" or self.ingress_first_sequence is not None or self.ingress_last_sequence is not None:
            raise ValueError("empty scope requires NO_INPUT and no ingress range")
        if self.scope_kind == "NO_INPUT" and self.closure_reason != "NO_INPUT":
            raise ValueError("empty scope closure must be NO_INPUT")
        if self.scope_kind == "WINDOW" and self.closure_reason == "NO_INPUT":
            raise ValueError("nonempty scope cannot claim NO_INPUT")
        required = {"RECOVERY":CoverageLimitation.INTERRUPTED, "INTERRUPTED":CoverageLimitation.INTERRUPTED,
                    "CLOCK_DISCONTINUITY":CoverageLimitation.CLOCK_DISCONTINUITY,
                    "LEGACY_CLOSURE":CoverageLimitation.INTERRUPTED}.get(self.closure_reason)
        if required and required not in self.coverage_limitations:
            raise ValueError("limited closure must declare its limitation")
        if len(set(self.coverage_limitations)) != len(self.coverage_limitations):
            raise ValueError("duplicate coverage limitations")
        if (self.closure_reason in {"WINDOW_END","NO_INPUT"} and not self.coverage_limitations
                and self.created_at_utc_us < self.window_end_utc_us):
            raise ValueError("normal scope cannot be sealed before its end")
        if (self.input_commitment.record_count != count or self.reduction_accounting.disposition_count != count):
            raise ValueError("input/disposition counts differ from accepted scope")
        ids = [item.condition_id for item in self.per_condition_facts]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate condition facts")
        for fact in self.per_condition_facts:
            if fact.matching_count+fact.nonmatching_count+fact.unresolved_count != count:
                raise ValueError("condition facts must partition accepted scope")
            for witness in fact.witnesses:
                if not count or not self.ingress_first_sequence <= witness.ingress_sequence <= self.ingress_last_sequence:
                    raise ValueError("witness outside ingress range")
        return self


class ContractTransitionBody(FrozenModel):
    protocol_version: Literal["rccd-transition-v1"] = "rccd-transition-v1"
    artifact_kind: Literal["RCC_CONTRACT_TRANSITION"] = "RCC_CONTRACT_TRANSITION"
    gateway_id: Identifier
    signing_key_id: Identifier
    ledger_epoch: Identifier
    transition_id: Digest
    previous_contract_hash: Digest
    next_contract_hash: Digest
    effective_window_index: WindowIndex
    effective_start_utc_us: Microseconds
    time_basis: Literal["gateway_ingress_utc_microseconds"] = "gateway_ingress_utc_microseconds"
    created_at_utc_us: Microseconds
    effect: Literal["OPERATOR_PROVISIONING_REQUIRED"] = "OPERATOR_PROVISIONING_REQUIRED"

    @model_validator(mode="after")
    def boundary(self):
        identity = {"gateway_id":self.gateway_id,"ledger_epoch":self.ledger_epoch,
                    "previous_contract_hash":self.previous_contract_hash,"effective_window_index":self.effective_window_index}
        expected = hashlib.sha256(TRANSITION_DOMAIN+canonical_bytes(identity)).hexdigest()
        if (self.transition_id != expected or self.previous_contract_hash == self.next_contract_hash
                or self.effective_start_utc_us != self.effective_window_index*10000000):
            raise ValueError("invalid contract transition identity/boundary")
        return self


class SignedArtifact(FrozenModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    signature_domain: Literal["RCCD-EVIDENCE-V1"] = "RCCD-EVIDENCE-V1"
    body: CapsuleBody | ContractTransitionBody = Field(discriminator="artifact_kind")
    body_digest: Digest
    signature: Signature


def artifact_bytes(artifact: SignedArtifact) -> bytes:
    artifact = SignedArtifact.model_validate(artifact.model_dump(mode="json"))
    result = canonical_bytes(artifact.model_dump(mode="json"))
    if len(result) > MAX_ARTIFACT_BYTES:
        raise EvidenceError("ARTIFACT_TOO_LARGE")
    return result


def artifact_digest(encoded: bytes) -> str:
    return hashlib.sha256(ARTIFACT_DOMAIN+encoded).hexdigest()


def _unsigned(body):
    document = body.model_dump(mode="json")
    return {"algorithm":"Ed25519","signature_domain":"RCCD-EVIDENCE-V1","body":document,
            "body_digest":hashlib.sha256(BODY_DOMAIN+canonical_bytes(document)).hexdigest()}


def sign_artifact(body: CapsuleBody | ContractTransitionBody, private_key) -> bytes:
    body = type(body).model_validate(body.model_dump(mode="json"))
    unsigned = _unsigned(body)
    signature = base64.b64encode(private_key.sign(SIGN_DOMAIN+canonical_bytes(unsigned))).decode("ascii")
    return artifact_bytes(SignedArtifact.model_validate({**unsigned,"signature":signature}))


def parse_artifact(encoded: bytes) -> SignedArtifact:
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise EvidenceError("ARTIFACT_TOO_LARGE")
    try:
        artifact = SignedArtifact.model_validate(strict_json(encoded))
        if artifact_bytes(artifact) != encoded:
            raise EvidenceError("NONCANONICAL_ARTIFACT")
        return artifact
    except (ValueError, RecursionError) as exc:
        raise EvidenceError("INVALID_ARTIFACT_SCHEMA") from exc


def check_contract_scope(body, contracts):
    if isinstance(body, ContractTransitionBody):
        hashes = (body.previous_contract_hash,body.next_contract_hash)
    else:
        hashes = (body.contract_hash,)
    for digest in hashes:
        if digest not in contracts or contract_hash(contracts[digest]) != digest:
            raise EvidenceError("UNPROVISIONED_CONTRACT")
    if isinstance(body, CapsuleBody):
        contract = contracts[body.contract_hash]
        if body.device_id not in {item.device_id for item in contract.devices}:
            raise EvidenceError("UNREGISTERED_DEVICE_SCOPE")
        expected = {item.condition_id for item in contract.conditions if item.device_id == body.device_id}
        if {item.condition_id for item in body.per_condition_facts} != expected:
            raise EvidenceError("INCOMPLETE_OR_UNKNOWN_CONDITION_SET")


def verify_artifact(encoded: bytes, public_keys, contracts) -> SignedArtifact:
    artifact = parse_artifact(encoded)
    body = artifact.body
    unsigned = _unsigned(body)
    if unsigned["body_digest"] != artifact.body_digest:
        raise EvidenceError("BODY_DIGEST_MISMATCH")
    key = public_keys.get((body.gateway_id,body.signing_key_id))
    if key is None:
        raise EvidenceError("UNPROVISIONED_SIGNER")
    try:
        signature = base64.b64decode(artifact.signature, validate=True)
        if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != artifact.signature:
            raise ValueError("noncanonical signature")
        key.verify(signature,SIGN_DOMAIN+canonical_bytes(unsigned))
    except (InvalidSignature, ValueError) as exc:
        raise EvidenceError("INVALID_SIGNATURE") from exc
    check_contract_scope(body,contracts)
    return artifact


def authenticated_facts(encoded, public_keys, contracts):
    artifact = verify_artifact(encoded,public_keys,contracts)
    body = artifact.body
    if not isinstance(body,CapsuleBody):
        raise EvidenceError("TRANSITION_IS_NOT_RULE_EVIDENCE")
    return tuple(ConditionFacts(window=body.window,condition_id=fact.condition_id,
        accepted_count=body.accepted_observation_count,matching_count=fact.matching_count,
        nonmatching_count=fact.nonmatching_count,unresolved_count=fact.unresolved_count,
        closed=True,population_complete=body.population_complete,limitations=body.coverage_limitations)
        for fact in body.per_condition_facts)


def prepare_inputs(window: WindowIdentity, records) -> tuple[InputRecord, ...]:
    result, total, seen = [], 0, set()
    for record in records:
        if len(result) >= MAX_INPUT_RECORDS:
            raise EvidenceError("INPUT_RECORD_LIMIT")
        record = InputRecord.model_validate(record.model_dump())
        total += len(record.canonical_input)
        if total > MAX_INPUT_SCOPE_BYTES:
            raise EvidenceError("INPUT_SCOPE_BYTE_LIMIT")
        if (record.ledger_epoch != window.ledger_epoch or record.device_id != window.device_id
                or not window.start_utc_us <= record.ingress_utc_us < window.end_utc_us
                or record.ingress_sequence in seen):
            raise EvidenceError("INVALID_DISCLOSED_SCOPE")
        seen.add(record.ingress_sequence)
        result.append(record)
    result.sort(key=lambda record:record.ingress_sequence)
    if result and result[-1].ingress_sequence-result[0].ingress_sequence+1 != len(result):
        raise EvidenceError("NONCONTIGUOUS_INPUT_SCOPE")
    return tuple(result)


def input_commitment(window: WindowIdentity, records) -> InputCommitment:
    records = prepare_inputs(window,records)
    root = hashlib.sha256(INPUT_SEED_DOMAIN+canonical_bytes(window.model_dump(mode="json"))).digest()
    for record in records:
        leaf = hashlib.sha256(INPUT_LEAF_DOMAIN+canonical_bytes({"ledger_epoch":record.ledger_epoch,
            "device_id":record.device_id,"ingress_sequence":record.ingress_sequence,
            "ingress_utc_us":record.ingress_utc_us,"input_hash":record.input_hash})).digest()
        root = hashlib.sha256(INPUT_FOLD_DOMAIN+root+leaf).digest()
    return InputCommitment(root=root.hex(),record_count=len(records))


def _original_observation(record, contract):
    original = strict_json(record.canonical_input)
    device = next(item for item in contract.devices if item.device_id == record.device_id)
    readings = []
    for metric in device.metrics:
        if metric.path.startswith("measurements."):
            value = original.get("measurements",{}).get(metric.path.split(".",1)[1])
        else:
            value = original.get(metric.path)
        readings.append(MetricReading(path=metric.path,value=value))
    return IngressObservation(ledger_epoch=record.ledger_epoch,device_id=record.device_id,
        ingress_sequence=record.ingress_sequence,ingress_utc_us=record.ingress_utc_us,
        telemetry_type=original["telemetry_type"],metrics=tuple(readings))


def build_capsule(*, contract, window, records, gateway_id, signing_key_id, created_at_utc_us,
                  closure_reason="WINDOW_END", limitations=(), accounting=None, previous_digest=None,
                  population_complete=True) -> CapsuleBody:
    if contract_hash(contract) != window.contract_hash:
        raise EvidenceError("CONTRACT_SCOPE_MISMATCH")
    if window.device_id not in {item.device_id for item in contract.devices}:
        raise EvidenceError("UNREGISTERED_DEVICE_SCOPE")
    records = prepare_inputs(window,records)
    originals = tuple(_original_observation(record,contract) for record in records)
    facts = []
    for condition in contract.conditions:
        if condition.device_id != window.device_id:
            continue
        counts = condition_facts(contract,condition.condition_id,window,originals)
        witnesses = []
        for record, original in zip(records,originals):
            if len(witnesses) == 2:
                break
            if condition_facts(contract,condition.condition_id,window,(original,)).matching_count:
                witnesses.append(WitnessReference(ingress_sequence=record.ingress_sequence,input_hash=record.input_hash))
        facts.append(CapsuleFact(condition_id=condition.condition_id,matching_count=counts.matching_count,
                                nonmatching_count=counts.nonmatching_count,unresolved_count=counts.unresolved_count,
                                witnesses=tuple(witnesses)))
    return CapsuleBody(gateway_id=gateway_id,signing_key_id=signing_key_id,ledger_epoch=window.ledger_epoch,
        capsule_id=scope_id(gateway_id,window),contract_hash=window.contract_hash,device_id=window.device_id,
        window_index=window.window_index,window_start_utc_us=window.start_utc_us,window_end_utc_us=window.end_utc_us,
        closure_reason=closure_reason if records else "NO_INPUT",scope_kind="WINDOW" if records else "NO_INPUT",
        ingress_first_sequence=records[0].ingress_sequence if records else None,
        ingress_last_sequence=records[-1].ingress_sequence if records else None,
        accepted_observation_count=len(records),input_commitment=input_commitment(window,records),
        per_condition_facts=tuple(facts),coverage_limitations=limitations,population_complete=population_complete,
        reduction_accounting=accounting or RawAccounting(pending_policy=len(records)),
        previous_capsule_digest=previous_digest,created_at_utc_us=created_at_utc_us)


def build_transition(*, gateway_id, signing_key_id, ledger_epoch, previous_contract_hash,
                     next_contract_hash, effective_window_index, created_at_utc_us):
    identity = {"gateway_id":gateway_id,"ledger_epoch":ledger_epoch,
                "previous_contract_hash":previous_contract_hash,"effective_window_index":effective_window_index}
    return ContractTransitionBody(gateway_id=gateway_id,signing_key_id=signing_key_id,ledger_epoch=ledger_epoch,
        transition_id=hashlib.sha256(TRANSITION_DOMAIN+canonical_bytes(identity)).hexdigest(),
        previous_contract_hash=previous_contract_hash,next_contract_hash=next_contract_hash,
        effective_window_index=effective_window_index,effective_start_utc_us=effective_window_index*10000000,
        created_at_utc_us=created_at_utc_us)


class OfflineAudit(FrozenModel):
    status: Literal["RECOMPUTED", "MISMATCH", "INCOMPLETE_DISCLOSURE"]
    assurance: Literal["OFFLINE_RAW_RECOMPUTATION"] = "OFFLINE_RAW_RECOMPUTATION"
    findings: tuple[str, ...] = Field(default=(),max_length=128)
    delivery_accounting: Literal["NOT_RECOMPUTED"] = "NOT_RECOMPUTED"


def audit_capsule(encoded, public_keys, contracts, records) -> OfflineAudit:
    artifact = verify_artifact(encoded,public_keys,contracts)
    body = artifact.body
    if not isinstance(body,CapsuleBody):
        raise EvidenceError("TRANSITION_IS_NOT_RULE_EVIDENCE")
    records = prepare_inputs(body.window,records)
    if len(records) < body.accepted_observation_count:
        return OfflineAudit(status="INCOMPLETE_DISCLOSURE",findings=("missing original records",))
    findings = []
    if (input_commitment(body.window,records) != body.input_commitment
            or (records and (records[0].ingress_sequence != body.ingress_first_sequence
                             or records[-1].ingress_sequence != body.ingress_last_sequence))):
        findings.append("input commitment/range differs")
    contract = contracts[body.contract_hash]
    device = next(item for item in contract.devices if item.device_id == body.device_id)
    by_id = {item.condition_id:item for item in contract.conditions}
    for fact in body.per_condition_facts:
        atom = by_id[fact.condition_id]
        matching, misses, unresolved, matching_ids = 0, 0, 0, {}
        for record in records:
            original = strict_json(record.canonical_input)
            value = (original.get("measurements",{}).get(atom.metric_path.split(".",1)[1])
                     if atom.metric_path.startswith("measurements.") else original.get(atom.metric_path))
            if original["telemetry_type"] != device.telemetry_type or type(value) not in (int,float) or not math.isfinite(value):
                unresolved += 1
                continue
            if atom.inequality == ">": hit = value > atom.threshold
            elif atom.inequality == ">=": hit = value >= atom.threshold
            elif atom.inequality == "<": hit = value < atom.threshold
            else: hit = value <= atom.threshold
            if hit:
                matching += 1
                matching_ids[record.ingress_sequence] = record.input_hash
            else:
                misses += 1
        if (matching,misses,unresolved) != (fact.matching_count,fact.nonmatching_count,fact.unresolved_count):
            findings.append("predicate counts differ: "+fact.condition_id)
        if any(matching_ids.get(item.ingress_sequence) != item.input_hash for item in fact.witnesses):
            findings.append("witness differs: "+fact.condition_id)
    return OfflineAudit(status="MISMATCH" if findings else "RECOMPUTED",findings=tuple(findings))


class EvidenceInspection(FrozenModel):
    artifact_id: Digest
    artifact_digest: Digest
    duplicate: bool
    continuity: Literal["COMPLETE", "INCOMPLETE", "BROKEN", "NOT_APPLICABLE"]
    assurance: Literal["AUTHENTICATED_SUMMARY"] = "AUTHENTICATED_SUMMARY"


class EvidenceTracker:
    """Bounded local inspection only; durable replay and Fog publication are N6."""
    def __init__(self, public_keys, contracts, max_artifacts=256):
        if type(max_artifacts) is not int or not 1 <= max_artifacts <= 256:
            raise ValueError("invalid evidence cache capacity")
        self.keys,self.contracts,self.limit = dict(public_keys),dict(contracts),max_artifacts
        self.entries = {}

    def inspect(self, encoded):
        artifact = verify_artifact(encoded,self.keys,self.contracts)
        body = artifact.body
        identity = body.capsule_id if isinstance(body,CapsuleBody) else body.transition_id
        digest = artifact_digest(encoded)
        previous = self.entries.get(identity)
        if previous and previous[0] != digest:
            raise EvidenceConflict("SAME_SCOPE_DIFFERENT_SIGNED_BODY")
        if previous is None:
            if len(self.entries) >= self.limit:
                raise EvidenceError("EVIDENCE_CACHE_FULL")
            self.entries[identity] = (digest,body)
        continuity = self._continuity(body,set())
        return EvidenceInspection(artifact_id=identity,artifact_digest=digest,duplicate=previous is not None,continuity=continuity)

    def _continuity(self, body, seen):
        if not isinstance(body,CapsuleBody):
            return "NOT_APPLICABLE"
        if body.previous_capsule_digest is None:
            return "COMPLETE"
        if body.capsule_id in seen:
            return "BROKEN"
        seen.add(body.capsule_id)
        parent = next((entry[1] for entry in self.entries.values() if entry[0] == body.previous_capsule_digest),None)
        if parent is None:
            return "INCOMPLETE"
        if (not isinstance(parent,CapsuleBody) or parent.gateway_id != body.gateway_id
                or parent.device_id != body.device_id or parent.ledger_epoch != body.ledger_epoch
                or parent.window_index >= body.window_index):
            return "BROKEN"
        return self._continuity(parent,seen)

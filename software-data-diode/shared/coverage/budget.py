"""Conservative serialization costs, not a claim about measured UDP delivery."""
import base64
import math

from pydantic import Field, model_validator

from shared.security.crypto import canonical_bytes

from .capsules import (CapsuleBody, CapsuleFact, InputCommitment, RawAccounting,
                       WitnessReference, MAX_ARTIFACT_BYTES, scope_id)
from .contracts import contract_hash
from .models import FrozenModel, WindowIdentity
from .parts import CHUNK_BYTES, MAX_PARTS, PartBody, SignedPart


LANES = ("protected", "evidence", "routine")


class AdmissionConfig(FrozenModel):
    link_bytes_per_second: int = Field(default=131072, strict=True, ge=1, le=10**9)
    service_cycle_seconds: int = Field(default=10, strict=True, ge=1, le=10)
    evidence_share_percent: int = Field(default=10, strict=True, ge=1, le=98)
    protected_share_percent: int = Field(default=45, strict=True, ge=1, le=98)
    evidence_repeats: int = Field(default=2, strict=True, ge=1, le=8)
    datagram_payload_bytes: int = Field(default=1200, strict=True, ge=512, le=1200)
    network_overhead_bytes: int = Field(default=28, strict=True, ge=28, le=256)
    raw_header_bytes: int = Field(default=128, strict=True, ge=64, le=256)
    max_raw_artifact_bytes: int = Field(default=12288, strict=True, ge=512, le=32768)
    max_observations_per_scope: int = Field(default=1000, strict=True, ge=1, le=10000)
    max_outbox_items: int = Field(default=256, strict=True, ge=1, le=10000)
    max_raw_candidates: int = Field(default=64, strict=True, ge=1, le=256)
    max_policy_streams: int = Field(default=64, strict=True, ge=1, le=128)
    max_outbox_bytes: int = Field(default=4*1024*1024, strict=True, ge=1024, le=32*1024*1024)
    max_evidence_debt_cycles: int = Field(default=2, strict=True, ge=1, le=16)
    max_policy_state_bytes: int = Field(default=1024*1024, strict=True, ge=4096, le=4*1024*1024)
    max_journal_records: int = Field(default=256, strict=True, ge=1, le=4096)

    @model_validator(mode="after")
    def shares(self):
        if self.evidence_share_percent + self.protected_share_percent >= 100:
            raise ValueError("routine data requires a positive configured service share")
        if self.raw_header_bytes >= self.datagram_payload_bytes:
            raise ValueError("raw header consumes the entire datagram")
        if self.cycle_bytes < self.max_wire_frame:
            raise ValueError("link cycle cannot fund even one maximum frame")
        return self

    @property
    def max_wire_frame(self):
        return self.datagram_payload_bytes + self.network_overhead_bytes

    @property
    def cycle_bytes(self):
        return self.link_bytes_per_second*self.service_cycle_seconds

    @property
    def quotas(self):
        evidence = self.cycle_bytes*self.evidence_share_percent//100
        protected = self.cycle_bytes*self.protected_share_percent//100
        return {"evidence": evidence, "protected": protected,
                "routine": self.cycle_bytes-evidence-protected}


class EvidenceCost(FrozenModel):
    logical_bytes: int
    frame_bytes: int
    frames: int
    wire_bytes: int
    packed_bytes: int


def pack_frames(frames):
    return canonical_bytes([base64.b64encode(frame).decode("ascii") for frame in frames])


def unpack_frames(packed):
    from shared.http import strict_json
    values = strict_json(packed)
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_PARTS:
        raise ValueError("invalid bounded frame list")
    frames = tuple(base64.b64decode(value, validate=True) for value in values)
    if pack_frames(frames) != packed:
        raise ValueError("noncanonical frame storage")
    return frames


def worst_evidence_cost(contract, device_id, gateway_id, key_id, config):
    # Independent field maxima intentionally overestimate mutually exclusive counts.
    n, maximum = config.max_observations_per_scope, 2**63-1
    window = WindowIdentity(ledger_epoch="X"*64, device_id=device_id, window_index=maximum,
                            contract_hash=contract_hash(contract))
    facts = []
    for condition in contract.conditions:
        if condition.device_id == device_id:
            witnesses = tuple(WitnessReference(ingress_sequence=maximum-i, input_hash="f"*64)
                              for i in range(min(n, 2)))
            facts.append(CapsuleFact(condition_id=condition.condition_id, matching_count=n,
                                     nonmatching_count=0, unresolved_count=0, witnesses=witnesses))
    body = CapsuleBody(gateway_id=gateway_id, signing_key_id=key_id, ledger_epoch=window.ledger_epoch,
        capsule_id=scope_id(gateway_id, window), contract_hash=window.contract_hash, device_id=device_id,
        window_index=maximum, window_start_utc_us=window.start_utc_us, window_end_utc_us=window.end_utc_us,
        closure_reason="CLOCK_DISCONTINUITY", ingress_first_sequence=maximum-n+1,
        ingress_last_sequence=maximum, accepted_observation_count=n,
        input_commitment=InputCommitment(root="f"*64, record_count=n), per_condition_facts=tuple(facts),
        coverage_limitations=("STARTUP_PARTIAL", "INTERRUPTED", "CLOCK_DISCONTINUITY"),
        population_complete=False, reduction_accounting=RawAccounting(pending_policy=n),
        previous_capsule_digest="f"*64, created_at_utc_us=window.end_utc_us)
    document = body.model_dump(mode="json")
    for fact in document["per_condition_facts"]:
        for name in ("matching_count", "nonmatching_count", "unresolved_count"):
            fact[name] = n
    for name in ("pending_policy", "selected_raw", "reduced_raw", "dropped_raw", "archived_local", "queue_overflow_drops"):
        document["reduction_accounting"][name] = n
    document["reduction_accounting"]["raw_dispatch_attempts"] = maximum
    signature = base64.b64encode(bytes(64)).decode("ascii")
    logical = len(canonical_bytes({"algorithm": "Ed25519", "signature_domain": "RCCD-EVIDENCE-V1",
                                  "body": document, "body_digest": "f"*64, "signature": signature}))
    if logical > MAX_ARTIFACT_BYTES:
        raise ValueError("contract evidence exceeds the logical artifact bound")
    for chunk in range(CHUNK_BYTES, 0, -16):
        part = SignedPart(body=PartBody(gateway_id=gateway_id, signing_key_id=key_id, artifact_id="f"*64,
            artifact_digest="f"*64, part_index=MAX_PARTS-1, part_count=MAX_PARTS,
            total_bytes=MAX_ARTIFACT_BYTES, chunk="A"*(4*math.ceil(chunk/3))), signature=signature)
        frame = len(canonical_bytes(part.model_dump(mode="json")))
        if frame <= config.datagram_payload_bytes:
            count = math.ceil(logical/chunk)
            if count > MAX_PARTS:
                break
            packed = len(canonical_bytes(["A"*(4*math.ceil(frame/3))]*count))
            return EvidenceCost(logical_bytes=logical, frame_bytes=frame, frames=count,
                wire_bytes=count*(frame+config.network_overhead_bytes)*config.evidence_repeats,
                packed_bytes=packed)
    raise ValueError("bounded evidence parts cannot fit the configured datagrams")


def validate_budget(contract, gateway_id, key_id, config, *, coupled=True):
    if contract.window_seconds != 10 or config.service_cycle_seconds != 10:
        raise ValueError("v1 admission uses aligned 10-second closure and service cycles")
    costs = {device.device_id: worst_evidence_cost(contract, device.device_id, gateway_id, key_id, config)
             for device in contract.devices}
    if min(config.quotas.values()) <= 2*config.max_wire_frame:
        raise ValueError("each lane requires a frame-sized service quantum")
    if math.ceil(config.max_raw_artifact_bytes/(config.datagram_payload_bytes-config.raw_header_bytes)) > MAX_PARTS:
        raise ValueError("raw frame cardinality exceeds the bounded outbox format")
    if coupled and sum(cost.wire_bytes for cost in costs.values()) > config.quotas["evidence"]-2*config.max_wire_frame:
        raise ValueError("UNDERFUNDED_CONTRACT: closure frequency exceeds reserved evidence service")
    if coupled and (sum(cost.packed_bytes for cost in costs.values()) > config.max_outbox_bytes
                    or len(costs) > config.max_outbox_items):
        raise ValueError("UNDERFUNDED_STORAGE: registered scopes exceed evidence outbox capacity")
    return costs

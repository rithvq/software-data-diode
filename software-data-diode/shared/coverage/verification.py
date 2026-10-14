"""Fog verification of authenticated assertions, not hidden-input truth."""
from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from .capsules import CapsuleBody, EvidenceError, artifact_digest, verify_artifact
from .models import Digest, FrozenModel, Identifier, WindowIndex
from .parts import assemble_parts, verify_part

VERIFIER_VERSION = "rccd-fog-verifier-v1"
ReasonCode = Annotated[str, StringConstraints(strict=True, pattern=r"^[A-Z0-9_]{1,96}$")]


class VerificationRecord(FrozenModel):
    verifier_version: Literal["rccd-fog-verifier-v1"] = VERIFIER_VERSION
    scope_id: Digest
    artifact_digest: Digest
    gateway_id: Identifier
    signing_key_id: Identifier
    public_key_sha256: Digest
    ledger_epoch: Identifier
    contract_hash: Digest
    device_id: Identifier
    window_index: WindowIndex = Field(ge=1)
    observation_scope: Literal["accepted_normalized_gateway_ingress"]
    time_basis: Literal["gateway_ingress_utc_microseconds"]
    assurance_level: Literal["AUTHENTICATED_SUMMARY"] = "AUTHENTICATED_SUMMARY"
    status: Literal["VALID", "LIMITED", "CONFLICT"] = "VALID"
    continuity_status: Literal["UNASSESSED", "ROOT", "COMPLETE", "GAP", "BROKEN", "CONFLICT"] = "UNASSESSED"
    limitations: tuple[ReasonCode, ...] = Field(default=(), max_length=12)
    reason_codes: tuple[ReasonCode, ...] = Field(default=(), max_length=12)
    created_at_utc_us: int = Field(strict=True, ge=-(2**63), le=2**63-1)
    received_at_utc_us: int = Field(strict=True, ge=-(2**63), le=2**63-1)
    part_completion: Literal["COMPLETE", "LEGACY_RETAINED_BODY"]
    part_count: int = Field(strict=True, ge=0, le=96)
    transport_bytes: int = Field(strict=True, ge=0, le=115200)
    replay_width_windows: int = Field(strict=True, ge=2, le=60)


class FogEvidenceVerifier:
    def __init__(self, framer):
        self.framer = framer

    def verify(self, encoded, *, received_us, frames=(), legacy=False):
        framer, profile = self.framer, self.framer.profile
        artifact = verify_artifact(encoded, framer.keys, framer.contracts)
        body = artifact.body
        # Live operator transitions remain pinned. A received declaration cannot
        # activate a contract, key or epoch, even when its signature is valid.
        if not isinstance(body, CapsuleBody):
            raise EvidenceError("OPERATOR_CONTRACT_TRANSITION_REQUIRED")
        if (body.gateway_id, body.signing_key_id, body.ledger_epoch, body.contract_hash) != (
                profile.gateway_id, profile.signing_key_id, profile.ledger_epoch, profile.contract_hash):
            raise EvidenceError("UNAPPROVED_EVIDENCE_SCOPE")
        if body.window_index < 1:
            raise EvidenceError("UNSUPPORTED_RESEARCH_WINDOW_INDEX")
        if type(received_us) is not int:
            raise EvidenceError("INVALID_RECEIPT_TIME")
        if not legacy and not received_us-framer.config.freshness_seconds*1000000 <= body.created_at_utc_us <= received_us+30000000:
            raise EvidenceError("EXPIRED_EVIDENCE")
        if body.window_start_utc_us > received_us+30000000:
            raise EvidenceError("FUTURE_EVIDENCE_WINDOW")
        historical = body.window_end_utc_us < received_us-framer.config.freshness_seconds*1000000
        if historical and not legacy and body.closure_reason in {"WINDOW_END", "NO_INPUT"}:
            raise EvidenceError("EXPIRED_EVIDENCE_WINDOW")
        if not legacy:
            if not frames or assemble_parts(frames, framer.keys, framer.contracts,
                    max_datagram_bytes=framer.config.datagram_bytes) != encoded:
                raise EvidenceError("PART_COMPLETION_REQUIRED")
            parts = [verify_part(frame, framer.keys, max_datagram_bytes=framer.config.datagram_bytes)[0] for frame in frames]
            if len({p.part_index for p in parts}) != len(parts) or len(parts) != parts[0].part_count:
                raise EvidenceError("DUPLICATE_COMPLETION_PARTS")
        elif frames:
            raise EvidenceError("LEGACY_RECEIPT_CANNOT_CLAIM_PARTS")
        # Paths, units and inequalities are resolved from the hash-pinned contract,
        # never from unsigned intake metadata or an aggregate mean.
        contract = framer.contracts[body.contract_hash]
        device = next(d for d in contract.devices if d.device_id == body.device_id)
        metrics = {m.path: m.unit for m in device.metrics}
        for condition in contract.conditions:
            if condition.device_id == body.device_id and metrics.get(condition.metric_path) != condition.unit:
                raise EvidenceError("INCOMPATIBLE_CONDITION_METRIC")
        limitations = [item.value for item in body.coverage_limitations]
        if not body.population_complete:
            limitations.append("POPULATION_INCOMPLETE")
        if legacy:
            limitations.append("HISTORICAL_N5_RECEIPT_TIME_UNAVAILABLE")
        if historical:
            limitations.append("HISTORICAL_WINDOW")
        return VerificationRecord(scope_id=body.capsule_id, artifact_digest=artifact_digest(encoded),
            gateway_id=body.gateway_id, signing_key_id=body.signing_key_id,
            public_key_sha256=profile.public_key_sha256, ledger_epoch=body.ledger_epoch,
            contract_hash=body.contract_hash, device_id=body.device_id, window_index=body.window_index,
            observation_scope=body.observation_scope, time_basis=body.time_basis,
            status="LIMITED" if limitations else "VALID", limitations=tuple(limitations),
            reason_codes=("SIGNATURE_SCHEMA_CONTRACT_SCOPE_COUNTS_VERIFIED", "HIDDEN_INPUTS_NOT_RECOMPUTED"),
            created_at_utc_us=body.created_at_utc_us, received_at_utc_us=received_us,
            part_completion="LEGACY_RETAINED_BODY" if legacy else "COMPLETE",
            part_count=len(frames), transport_bytes=sum(map(len, frames)),
            replay_width_windows=max(2, framer.config.freshness_seconds//10))

"""Immutable, bounded v1 semantics; no transport or persistence behavior."""
from __future__ import annotations

from enum import StrEnum
import math
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from shared.models import TelemetryType


Identifier = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=64,
                                             pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")]
Digest = Annotated[str, StringConstraints(strict=True, pattern=r"^[a-f0-9]{64}$")]
MetricPath = Annotated[str, StringConstraints(strict=True, max_length=96,
    pattern=r"^(temperature|humidity|cpu_usage|memory_usage|measurements\.[A-Za-z][A-Za-z0-9_]*)$")]
Count = Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
PositiveCount = Annotated[int, Field(strict=True, ge=1, le=2**63 - 1)]
WindowIndex = Annotated[int, Field(strict=True, ge=-(2**63), le=2**63 - 1)]


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False, validate_default=True)


class Truth(StrEnum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


class CoverageLimitation(StrEnum):
    STARTUP_PARTIAL = "STARTUP_PARTIAL"
    INTERRUPTED = "INTERRUPTED"
    CLOCK_DISCONTINUITY = "CLOCK_DISCONTINUITY"


class ArtifactVerification(StrEnum):
    NOT_PERFORMED = "NOT_PERFORMED"
    VALID = "VALID"
    INVALID = "INVALID"
    CONFLICT = "CONFLICT"


class MetricDefinition(FrozenModel):
    path: MetricPath
    unit: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=32,
                                          pattern=r"^[A-Za-z0-9_%/.-]+$")]


class DeviceScope(FrozenModel):
    device_id: Identifier
    telemetry_type: TelemetryType
    metrics: tuple[MetricDefinition, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def unique_metrics(self):
        if len({item.path for item in self.metrics}) != len(self.metrics):
            raise ValueError("duplicate metric path")
        return self


class AtomicCondition(FrozenModel):
    condition_id: Identifier
    device_id: Identifier
    metric_path: MetricPath
    unit: str = Field(min_length=1, max_length=32, strict=True)
    predicate: Literal["EXISTS", "COUNT_GE"]
    inequality: Literal[">", ">=", "<", "<="]
    threshold: float
    k: PositiveCount = 1
    minimum_samples: PositiveCount = 1

    @field_validator("threshold", mode="before")
    @classmethod
    def binary64_threshold(cls, value):
        if type(value) not in (int, float):
            raise ValueError("threshold must be a finite binary64 number, not a string or boolean")
        try:
            number = float(value)
        except OverflowError as exc:
            raise ValueError("threshold is outside binary64") from exc
        if not math.isfinite(number):
            raise ValueError("threshold must be finite")
        return 0.0 if number == 0 else number

    @model_validator(mode="after")
    def exists_count(self):
        if self.predicate == "EXISTS" and self.k != 1:
            raise ValueError("EXISTS requires k=1")
        return self


class RuleExpression(FrozenModel):
    kind: Literal["ATOM", "AND", "OR"]
    condition_id: Identifier | None = None
    children: tuple[RuleExpression, ...] = Field(default=(), max_length=8)

    @model_validator(mode="after")
    def shape(self):
        if self.kind == "ATOM":
            if self.condition_id is None or self.children:
                raise ValueError("ATOM requires one condition_id and no children")
        elif self.condition_id is not None or len(self.children) < 2:
            raise ValueError("AND/OR require at least two children and no condition_id")
        return self


class RuleDefinition(FrozenModel):
    rule_id: Identifier
    expression: RuleExpression


class ContractLimits(FrozenModel):
    max_devices: int = Field(default=16, strict=True, ge=1, le=16)
    max_conditions: int = Field(default=64, strict=True, ge=1, le=64)
    max_rules: int = Field(default=32, strict=True, ge=1, le=32)
    max_expression_depth: int = Field(default=8, strict=True, ge=1, le=8)
    max_expression_nodes: int = Field(default=127, strict=True, ge=1, le=127)
    max_datagram_payload_bytes: int = Field(default=1200, strict=True, ge=256, le=1200)
    evidence_repetitions: int = Field(default=1, strict=True, ge=1, le=8)
    clock_jump_tolerance_us: int = Field(default=100000, strict=True, ge=0, le=1000000)


class RuleContract(FrozenModel):
    contract_id: Identifier
    protocol_version: Literal["rccd-contract-v1"] = "rccd-contract-v1"
    purpose: Literal["synthetic_demonstration", "research"] = "synthetic_demonstration"
    observation_scope: Literal["accepted_normalized_gateway_ingress"] = "accepted_normalized_gateway_ingress"
    numeric_interpretation: Literal["finite_ieee754_binary64"] = "finite_ieee754_binary64"
    time_basis: Literal["gateway_ingress_utc_microseconds"] = "gateway_ingress_utc_microseconds"
    window_seconds: Literal[10] = 10
    alignment: Literal["unix_epoch"] = "unix_epoch"
    boundary: Literal["start_inclusive_end_exclusive"] = "start_inclusive_end_exclusive"
    limits: ContractLimits = Field(default_factory=ContractLimits)
    devices: tuple[DeviceScope, ...] = Field(min_length=1, max_length=16)
    conditions: tuple[AtomicCondition, ...] = Field(min_length=1, max_length=64)
    rules: tuple[RuleDefinition, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def references_and_bounds(self):
        identifiers = [item.device_id for item in self.devices]
        identifiers += [item.condition_id for item in self.conditions]
        identifiers += [item.rule_id for item in self.rules]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("duplicate or ambiguous device/condition/rule identifiers")
        for items, bound in ((self.devices, self.limits.max_devices),
                             (self.conditions, self.limits.max_conditions),
                             (self.rules, self.limits.max_rules)):
            if len(items) > bound:
                raise ValueError("contract cardinality exceeds declared limits")
        devices = {item.device_id: item for item in self.devices}
        for condition in self.conditions:
            device = devices.get(condition.device_id)
            if device is None:
                raise ValueError("condition names an unregistered device")
            units = {metric.path: metric.unit for metric in device.metrics}
            if units.get(condition.metric_path) != condition.unit:
                raise ValueError("condition metric/unit differs from registered device scope")
        condition_ids = {item.condition_id for item in self.conditions}
        for rule in self.rules:
            stack, seen, nodes = [(rule.expression, 1)], set(), 0
            while stack:
                expression, depth = stack.pop()
                nodes += 1
                if depth > self.limits.max_expression_depth or nodes > self.limits.max_expression_nodes:
                    raise ValueError("expression exceeds declared structure limits")
                if expression.kind == "ATOM":
                    if expression.condition_id not in condition_ids or expression.condition_id in seen:
                        raise ValueError("unknown or repeated condition reference in rule")
                    seen.add(expression.condition_id)
                stack.extend((child, depth + 1) for child in expression.children)
        return self


class WindowIdentity(FrozenModel):
    ledger_epoch: Identifier
    device_id: Identifier
    window_index: WindowIndex
    contract_hash: Digest

    @property
    def start_utc_us(self):
        return self.window_index * 10000000

    @property
    def end_utc_us(self):
        return (self.window_index + 1) * 10000000


class ConditionFacts(FrozenModel):
    window: WindowIdentity
    condition_id: Identifier
    accepted_count: Count
    matching_count: Count
    nonmatching_count: Count
    unresolved_count: Count
    closed: bool = Field(default=False, strict=True)
    population_complete: bool = Field(default=True, strict=True)
    limitations: tuple[CoverageLimitation, ...] = ()

    @model_validator(mode="after")
    def partition(self):
        if self.accepted_count != self.matching_count + self.nonmatching_count + self.unresolved_count:
            raise ValueError("condition counts must partition the accepted population")
        return self


class AtomicVerdict(FrozenModel):
    condition_id: Identifier
    truth: Truth
    reason: str
    coverage_complete: bool


class RuleVerdict(FrozenModel):
    contract_hash: Digest
    ledger_epoch: Identifier
    window_index: WindowIndex
    rule_id: Identifier
    truth: Truth
    conditions: tuple[AtomicVerdict, ...]
    supporting_conditions: tuple[Identifier, ...]
    unknown_conditions: tuple[Identifier, ...]
    coverage_complete: bool
    artifact_verification: ArtifactVerification = ArtifactVerification.NOT_PERFORMED
    device_health: Literal["NOT_ASSESSED"] = "NOT_ASSESSED"


class MetricReading(FrozenModel):
    path: MetricPath
    value: Annotated[float, Field(strict=True)] | Annotated[int, Field(strict=True)] | Annotated[str, Field(strict=True)] | Annotated[bool, Field(strict=True)] | None


class IngressObservation(FrozenModel):
    """One original normalized ingress sample, never an aggregate or selection."""
    ledger_epoch: Identifier
    device_id: Identifier
    ingress_sequence: PositiveCount
    ingress_utc_us: Annotated[int, Field(strict=True)]
    telemetry_type: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=32)]
    metrics: tuple[MetricReading, ...] = Field(default=(), max_length=256)

    @model_validator(mode="after")
    def unique_paths(self):
        if len({metric.path for metric in self.metrics}) != len(self.metrics):
            raise ValueError("ambiguous observation metric paths")
        return self

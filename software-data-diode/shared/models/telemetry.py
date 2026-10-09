from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class RejectionReason(StrEnum):
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    HASH_MISMATCH = "HASH_MISMATCH"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    DUPLICATE_MESSAGE = "DUPLICATE_MESSAGE"
    EXPIRED_MESSAGE = "EXPIRED_MESSAGE"
    INVALID_SCHEMA = "INVALID_SCHEMA"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    UNAUTHORIZED_SOURCE = "UNAUTHORIZED_SOURCE"
    FORWARD_FAILED = "FORWARD_FAILED"
    QUEUE_FULL = "QUEUE_FULL"
    FILTERED_NO_SIGNIFICANT_CHANGE = "FILTERED_NO_SIGNIFICANT_CHANGE"
    FILTERED_DUPLICATE = "FILTERED_DUPLICATE"


class PriorityLevel(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class CongestionState(StrEnum):
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    CONGESTED = "CONGESTED"
    CRITICAL = "CRITICAL"


class TelemetryType(StrEnum):
    ENVIRONMENTAL = "environmental"
    SYSTEM = "system"
    NETWORK = "network"
    SECURITY = "security"
    INDUSTRIAL = "industrial"


class AggregationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    average_temperature: float
    minimum_temperature: float
    maximum_temperature: float
    average_humidity: float
    sample_count: int = Field(ge=1)
    metric_averages: dict[str, float] = Field(default_factory=dict)
    metric_minima: dict[str, float] = Field(default_factory=dict)
    metric_maxima: dict[str, float] = Field(default_factory=dict)
    source_message_ids: list[str] = Field(default_factory=list)
    window_start: datetime | None = None
    window_end: datetime | None = None


class TelemetryPayload(BaseModel):
    """Telemetry values signed inside a secure envelope."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    temperature: float
    humidity: float = Field(ge=0.0, le=100.0)
    status: str = Field(min_length=1)
    event_type: str = "telemetry"
    telemetry_type: TelemetryType = TelemetryType.ENVIRONMENTAL
    cpu_usage: float | None = Field(default=None, ge=0.0, le=100.0)
    memory_usage: float | None = Field(default=None, ge=0.0, le=100.0)
    measurements: dict[str, float] = Field(default_factory=dict)
    attributes: dict[str, str | int | float | bool] = Field(default_factory=dict)
    aggregation: AggregationSummary | None = None


class EdgeTelemetryMessage(TelemetryPayload):
    """Unsigned message emitted by the simulated edge device."""

    device_id: str = Field(min_length=1)
    timestamp: datetime


class SecureTelemetryEnvelope(BaseModel):
    """Signed message envelope forwarded through the software diode."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    message_id: UUID
    device_id: str = Field(min_length=1)
    created_at: datetime
    sequence_number: int = Field(ge=0)
    priority: PriorityLevel = PriorityLevel.LOW
    payload: TelemetryPayload
    payload_hash: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    signature: str = Field(min_length=1)
    estimated_transmission_cost: float = Field(default=1.0, ge=0.0)
    schema_version: str = "1.0"


# Backward-compatible alias for Phase 1-style imports.
TelemetryMessage = EdgeTelemetryMessage

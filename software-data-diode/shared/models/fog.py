from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .telemetry import PriorityLevel, SecureTelemetryEnvelope


class AlertSeverity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FogEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: UUID = Field(default_factory=uuid4)
    received_at: datetime
    envelope: SecureTelemetryEnvelope


class AnomalyRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    anomaly_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    message_id: UUID
    device_id: str
    detector: str
    metric: str
    observed_value: float
    expected_value: float | None = None
    score: float | None = None
    severity: AlertSeverity
    explanation: str


class AlertRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    source_devices: list[str] = Field(min_length=1)
    alert_type: str
    severity: AlertSeverity
    evidence: list[dict[str, object]]
    description: str


class CoverageAlertDelivery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    alert_id: UUID
    revision: int = Field(strict=True,ge=1,le=2**63-1)


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    event_type: str
    severity: AlertSeverity
    source_devices: list[str]
    evidence: list[dict[str, object]]
    description: str


class DeviceHealth(StrEnum):
    ACTIVE = "ACTIVE"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"


class DeviceStatistics(BaseModel):
    device_id: str
    health: DeviceHealth
    last_seen: datetime | None
    last_sequence_number: int
    received_count: int
    forwarded_count: int
    filtered_count: int
    rejected_count: int
    message_rate_per_minute: float
    recent_activity_count: int
    filtering_statistics: dict[str, int]
    priority_statistics: dict[PriorityLevel, int]


class ObservabilitySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    service: str
    metrics: dict[str, object]
    labels: dict[str, str] = Field(default_factory=dict)

from datetime import datetime
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class Payload(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    temperature: float
    humidity: float = Field(ge=0, le=100)
    status: str = Field(min_length=1, max_length=64)


class Telemetry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    message_id: UUID
    device_id: str = Field(min_length=1, max_length=128)
    timestamp: AwareDatetime
    sequence_number: int = Field(ge=1)
    payload: Payload


class TransferRecord(BaseModel):
    service: str
    event: str
    message_id: UUID
    device_id: str
    sequence_number: int
    arrival_timestamp: datetime
    queue_entry_timestamp: datetime | None
    transmission_timestamp: datetime | None
    message_size_bytes: int
    queue_length: int
    attempt: int = 0
    reason: str = ""

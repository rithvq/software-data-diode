from typing import Literal

from pydantic import AwareDatetime, Field, JsonValue, model_validator

from phase1.models import Telemetry


Priority = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class SourceMessage(Telemetry):
    sequence_number: int = Field(ge=1, le=9223372036854775807, strict=True)
    payload: dict[str, JsonValue]
    created_at: AwareDatetime
    message_type: Literal["environmental", "system", "network", "security", "industrial"]
    priority: Priority
    base_priority: Priority
    event_class: str = Field(min_length=1, max_length=128)
    payload_size: int = Field(ge=0, strict=True)
    supersession_key: str | None = Field(default=None, max_length=256)
    aggregation_allowed: bool = Field(strict=True)
    sampling_allowed: bool = Field(strict=True)
    must_preserve: bool = Field(strict=True)

    @model_validator(mode="after")
    def semantic_constraints(self):
        if self.timestamp != self.created_at:
            raise ValueError("timestamp and created_at must identify the same creation time")
        if self.priority != self.base_priority:
            raise ValueError("Phase 2 has no priority transformation")
        if (self.message_type == "security" or self.priority == "CRITICAL") and not self.must_preserve:
            raise ValueError("security and CRITICAL events must be preserved")
        if self.must_preserve and (self.aggregation_allowed or self.sampling_allowed or self.supersession_key):
            raise ValueError("mandatory events cannot opt into lossy transformations")
        return self


class SecureEnvelope(SourceMessage):
    schema_version: Literal["2.0"] = "2.0"
    payload_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    signature: str = Field(min_length=1, max_length=128)

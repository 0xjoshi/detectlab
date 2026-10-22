
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class HostCreate(BaseModel):
    hostname: str
    platform: str
    ip_address: str | None = None


class HostResponse(BaseModel):
    id: int
    hostname: str
    platform: str
    ip_address: str | None = None

    model_config = ConfigDict(from_attributes=True)


class RuleCreate(BaseModel):
    rule_id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=255)
    description: str
    platform: str = Field(min_length=1, max_length=50)
    definition_yaml: str = Field(min_length=1)
    severity: str = Field(min_length=1, max_length=50)
    mitre_technique: str | None = Field(default=None, max_length=50)
    enabled: bool = True


class RuleResponse(BaseModel):
    id: int
    rule_id: str
    name: str
    description: str
    platform: str
    definition_yaml: str
    severity: str
    mitre_technique: str | None = None
    enabled: bool

    model_config = ConfigDict(from_attributes=True)


class EventCreate(BaseModel):
    host_id: int = Field(gt=0)
    timestamp: datetime
    event_type: str = Field(min_length=1, max_length=100)
    event_data: dict[str, Any]
    raw_event: dict[str, Any]


class EventResponse(BaseModel):
    id: int
    host_id: int
    timestamp: datetime
    event_type: str
    event_data: dict[str, Any]
    raw_event: dict[str, Any]

    model_config = ConfigDict(from_attributes=True)

class DetectionEvaluationRequest(BaseModel):
    evaluation_time: datetime

    @field_validator("evaluation_time")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluation_time must include a timezone.")
        return value
class DetectionValidationRequest(DetectionEvaluationRequest):
    expected_rule_id: str = Field(min_length=1, max_length=100)
    expected_host: str = Field(min_length=1, max_length=255)

    @field_validator("expected_rule_id", "expected_host")
    @classmethod
    def require_non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("This field must not be blank.")
        return value
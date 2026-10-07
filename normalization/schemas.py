from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, ConfigDict


class EventSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventSource(StrEnum):
    ELASTIC = "elastic"
    MANUAL = "manual"
    API = "api"


class SOCEvent(BaseModel):
    """
    Normalized security event used internally by SOCForge.

    Raw vendor-specific events should be converted into this model
    before investigation or enrichment.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    timestamp: datetime
    source: EventSource

    event_type: str = Field(min_length=1)
    severity: EventSeverity = EventSeverity.LOW

    message: str | None = None

    host: str | None = None
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None

    process_name: str | None = None
    process_command_line: str | None = None

    raw_event: dict = Field(default_factory=dict)
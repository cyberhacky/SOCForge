from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventSource(StrEnum):
    ELASTIC = "elastic"
    MANUAL = "manual"
    API = "api"


class EventEntities(BaseModel):
    """
    Deterministically extracted entities from a normalized security event.

    These values are evidence candidates only. Extraction does not imply
    that an entity is malicious or suspicious.
    """

    model_config = ConfigDict(extra="forbid")

    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)
    command_lines: list[str] = Field(default_factory=list)


class SOCEvent(BaseModel):
    """
    Normalized security event used internally by SOCForge.

    The model contains common investigation fields while preserving
    the complete original event in raw_event.
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

    ingestion_timestamp: datetime

    source_index: str | None = None
    source_document_id: str | None = None

    entities: EventEntities = Field(default_factory=EventEntities)

    raw_event: dict[str, Any] = Field(default_factory=dict)
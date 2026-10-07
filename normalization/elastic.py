from datetime import datetime, timezone
from typing import Any

from normalization.schemas import EventSeverity, EventSource, SOCEvent


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return None


def _event_type(source: dict[str, Any]) -> str:
    event = source.get("event", {})

    action = event.get("action")
    if action:
        return str(action)

    code = event.get("code")
    if code:
        return f"event_code_{code}"

    dataset = source.get("data_stream", {}).get("dataset")
    if dataset:
        return str(dataset)

    return "unknown"


def _severity(source: dict[str, Any]) -> EventSeverity:
    level = str(source.get("log", {}).get("level", "")).lower()

    mapping = {
        "critical": EventSeverity.CRITICAL,
        "error": EventSeverity.HIGH,
        "warning": EventSeverity.MEDIUM,
        "warn": EventSeverity.MEDIUM,
        "information": EventSeverity.LOW,
        "info": EventSeverity.LOW,
        "debug": EventSeverity.LOW,
    }

    return mapping.get(level, EventSeverity.LOW)


def normalize_elastic_event(
    elastic_hit: dict[str, Any],
) -> SOCEvent:
    """
    Convert one raw Elastic hit into a SOCForge SOCEvent.

    The complete Elastic hit is preserved in raw_event.
    """

    source = elastic_hit.get("source", {})

    if not isinstance(source, dict):
        raise ValueError("Elastic event source must be an object")

    timestamp = source.get("@timestamp")

    if not timestamp:
        raise ValueError("Elastic event is missing @timestamp")

    event = source.get("event", {})
    host = source.get("host", {})
    user = source.get("user", {})
    source_entity = source.get("source", {})
    destination = source.get("destination", {})
    process = source.get("process", {})

    event_id = _first_non_empty(
        event.get("id"),
        event.get("code"),
        elastic_hit.get("id"),
    )

    if event_id is None:
        event_id = f"elastic:{elastic_hit.get('id', 'unknown')}"

    parsed_timestamp = datetime.fromisoformat(
        str(timestamp).replace("Z", "+00:00")
    )

    if parsed_timestamp.tzinfo is None:
        parsed_timestamp = parsed_timestamp.replace(tzinfo=timezone.utc)

    return SOCEvent(
        event_id=str(event_id),
        timestamp=parsed_timestamp,
        source=EventSource.ELASTIC,
        event_type=_event_type(source),
        severity=_severity(source),
        message=source.get("message"),
        host=_first_non_empty(
            host.get("hostname"),
            host.get("name"),
        ),
        username=_first_non_empty(
            user.get("name"),
            user.get("full_name"),
        ),
        source_ip=_first_non_empty(
            source_entity.get("ip"),
            source_entity.get("address"),
        ),
        destination_ip=_first_non_empty(
            destination.get("ip"),
            destination.get("address"),
        ),
        process_name=_first_non_empty(
            process.get("name"),
            process.get("executable"),
        ),
        process_command_line=process.get("command_line"),
        ingestion_timestamp=datetime.now(timezone.utc),
        source_index=elastic_hit.get("index"),
        source_document_id=elastic_hit.get("id"),
        raw_event=elastic_hit,
    )
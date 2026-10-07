from datetime import datetime, timezone

from normalization.schemas import EventSeverity, EventSource, SOCEvent


def test_soc_event_creation() -> None:
    now = datetime.now(timezone.utc)

    event = SOCEvent(
        event_id="test-001",
        timestamp=now,
        source=EventSource.MANUAL,
        event_type="authentication",
        severity=EventSeverity.MEDIUM,
        username="analyst",
        source_ip="192.0.2.10",
        message="Successful authentication",
        ingestion_timestamp=now,
        raw_event={
            "test": True,
        },
    )

    assert event.event_id == "test-001"
    assert event.source == EventSource.MANUAL
    assert event.event_type == "authentication"
    assert event.severity == EventSeverity.MEDIUM
    assert event.username == "analyst"
    assert event.source_ip == "192.0.2.10"
    assert event.ingestion_timestamp == now
    assert event.raw_event["test"] is True
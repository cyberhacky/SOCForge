from datetime import datetime, timezone

from normalization.schemas import EventSeverity, EventSource, SOCEvent


def test_soc_event_creation() -> None:
    event = SOCEvent(
        event_id="test-001",
        timestamp=datetime.now(timezone.utc),
        source=EventSource.MANUAL,
        event_type="authentication",
        severity=EventSeverity.MEDIUM,
        username="analyst",
        source_ip="192.0.2.10",
        message="Successful authentication",
        raw_event={
            "test": True,
        },
    )

    assert event.event_id == "test-001"
    assert event.source == EventSource.MANUAL
    assert event.severity == EventSeverity.MEDIUM
    assert event.username == "analyst"
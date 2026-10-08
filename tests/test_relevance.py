from datetime import datetime, timedelta, timezone

from investigation.relevance import (
    EvidenceRelevance,
    evaluate_relevance,
)
from normalization.schemas import (
    EventEntities,
    EventSeverity,
    EventSource,
    SOCEvent,
)


ALERT_TIME = datetime(
    2026,
    10,
    7,
    17,
    0,
    tzinfo=timezone.utc,
)


def make_alert() -> SOCEvent:
    return SOCEvent(
        event_id="alert-001",
        timestamp=ALERT_TIME,
        source=EventSource.ELASTIC,
        event_type="suspicious-login",
        severity=EventSeverity.HIGH,
        host="WIN-DC-01",
        username="jsmith",
        source_ip="10.10.10.25",
        destination_ip="185.0.0.1",
        process_name="powershell.exe",
        ingestion_timestamp=ALERT_TIME,
        entities=EventEntities(
            ips=["10.10.10.25", "185.0.0.1"],
            domains=["example.com"],
            usernames=["jsmith"],
            hostnames=["WIN-DC-01"],
            processes=["powershell.exe"],
        ),
    )


def make_event(
    *,
    event_id: str = "event-001",
    timestamp: datetime = ALERT_TIME,
    event_type: str = "process-start",
    host: str | None = "WIN-DC-01",
    username: str | None = "jsmith",
    source_ip: str | None = "10.10.10.25",
    process_name: str | None = "powershell.exe",
    entities: EventEntities | None = None,
) -> SOCEvent:
    return SOCEvent(
        event_id=event_id,
        timestamp=timestamp,
        source=EventSource.ELASTIC,
        event_type=event_type,
        host=host,
        username=username,
        source_ip=source_ip,
        process_name=process_name,
        ingestion_timestamp=timestamp,
        entities=entities or EventEntities(
            ips=[source_ip] if source_ip else [],
            usernames=[username] if username else [],
            hostnames=[host] if host else [],
            processes=[process_name] if process_name else [],
        ),
    )


def test_relevance_returns_structured_result() -> None:
    alert = make_alert()
    event = make_event()

    result = evaluate_relevance(alert, event)

    assert isinstance(result, EvidenceRelevance)
    assert 0 <= result.score <= 100
    assert result.category in {"high", "medium", "low"}
    assert result.reasons
    assert result.matched_entities


def test_same_host_user_and_process_is_high_relevance() -> None:
    alert = make_alert()
    event = make_event()

    result = evaluate_relevance(alert, event)

    assert result.category == "high"
    assert result.score >= 70
    assert "host" in result.matched_entities
    assert "username" in result.matched_entities
    assert "process" in result.matched_entities


def test_same_host_only_is_lower_than_multiple_entity_matches() -> None:
    alert = make_alert()

    event = make_event(
        username=None,
        source_ip=None,
        process_name=None,
        entities=EventEntities(
            hostnames=["WIN-DC-01"],
        ),
    )

    result = evaluate_relevance(alert, event)

    assert result.score < 70
    assert result.category in {"medium", "low"}
    assert result.matched_entities["host"] == ["WIN-DC-01"]


def test_close_timestamp_increases_relevance() -> None:
    alert = make_alert()

    close_event = make_event(
        timestamp=ALERT_TIME + timedelta(minutes=1),
    )

    distant_event = make_event(
        timestamp=ALERT_TIME + timedelta(minutes=25),
    )

    close_result = evaluate_relevance(alert, close_event)
    distant_result = evaluate_relevance(alert, distant_event)

    assert close_result.score > distant_result.score


def test_routine_system_telemetry_is_not_automatically_high() -> None:
    alert = make_alert()

    event = make_event(
        event_type="system.cpu",
        host="WIN-DC-01",
        username=None,
        source_ip=None,
        process_name=None,
        entities=EventEntities(
            hostnames=["WIN-DC-01"],
        ),
    )

    result = evaluate_relevance(alert, event)

    assert result.category != "high"


def test_unrelated_event_has_low_relevance() -> None:
    alert = make_alert()

    event = make_event(
        host="OTHER-HOST",
        username="other-user",
        source_ip="192.168.1.50",
        process_name="notepad.exe",
        entities=EventEntities(
            ips=["192.168.1.50"],
            usernames=["other-user"],
            hostnames=["OTHER-HOST"],
            processes=["notepad.exe"],
        ),
    )

    result = evaluate_relevance(alert, event)

    assert result.score < 30
    assert result.category == "low"


def test_relevance_never_calls_event_content_malicious() -> None:
    alert = make_alert()

    event = make_event(
        event_type="process-start",
    )

    result = evaluate_relevance(alert, event)

    assert all(
        "malicious" not in reason.lower()
        for reason in result.reasons
    )


def test_alert_itself_is_maximally_relevant() -> None:
    alert = make_alert()

    result = evaluate_relevance(alert, alert)

    assert result.score == 100
    assert result.category == "high"
    assert "original alert" in [
        reason.lower() for reason in result.reasons
    ]
from datetime import datetime, timezone
from unittest.mock import Mock

from collectors.elastic import ElasticSearchResult
from investigation.correlation import (
    CorrelatedEvidence,
    CorrelationResult,
    build_correlation_query,
    correlate_event,
)
from normalization.schemas import (
    EventEntities,
    EventSource,
    SOCEvent,
)


def make_event() -> SOCEvent:
    return SOCEvent(
        event_id="alert-001",
        timestamp=datetime(
            2026,
            10,
            7,
            17,
            0,
            tzinfo=timezone.utc,
        ),
        source=EventSource.ELASTIC,
        event_type="suspicious-login",
        host="WIN-DC-01",
        username="jsmith",
        source_ip="10.10.10.25",
        destination_ip="185.0.0.1",
        process_name="powershell.exe",
        process_command_line="powershell.exe -enc suspicious-data",
        ingestion_timestamp=datetime.now(timezone.utc),
        entities=EventEntities(
            ips=[
                "10.10.10.25",
                "185.0.0.1",
            ],
            domains=[
                "example.com",
            ],
            hashes=[
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ],
            usernames=[
                "jsmith",
            ],
            hostnames=[
                "WIN-DC-01",
            ],
            processes=[
                "powershell.exe",
            ],
        ),
    )


def test_build_correlation_query_uses_structured_terms():
    event = make_event()

    query = build_correlation_query(event)

    should = query["bool"]["should"]

    assert query["bool"]["minimum_should_match"] == 1

    assert {
        "term": {
            "host.hostname": "WIN-DC-01",
        }
    } in should

    assert {
        "term": {
            "user.name": "jsmith",
        }
    } in should

    assert {
        "term": {
            "source.ip": "10.10.10.25",
        }
    } in should

    assert {
        "term": {
            "process.name": "powershell.exe",
        }
    } in should

    assert {
        "term": {
            "url.domain": "example.com",
        }
    } in should


def test_no_entities_does_not_search_entire_cluster():
    event = make_event()

    event.entities = EventEntities()

    query = build_correlation_query(event)

    assert query == {
        "bool": {
            "must": [
                {
                    "match_none": {},
                }
            ]
        }
    }


def test_correlate_event_uses_time_window_and_returns_chronological_events():
    event = make_event()

    connector = Mock()

    connector.search_all.return_value = ElasticSearchResult(
        events=[
            {
                "index": "logs-test",
                "id": "event-2",
                "score": 1.0,
                "source": {
                    "@timestamp": "2026-10-07T17:10:00Z",
                    "event": {
                        "action": "network-connection",
                    },
                    "host": {
                        "name": "WIN-DC-01",
                    },
                },
            },
            {
                "index": "logs-test",
                "id": "event-1",
                "score": 1.0,
                "source": {
                    "@timestamp": "2026-10-07T16:45:00Z",
                    "event": {
                        "action": "logon",
                    },
                    "host": {
                        "name": "WIN-DC-01",
                    },
                },
            },
        ],
        truncated=False,
    )

    result = correlate_event(
        event,
        connector=connector,
        window_minutes=30,
        max_events=100,
    )

    connector.search_all.assert_called_once()

    call = connector.search_all.call_args.kwargs

    assert call["index"] == "*"
    assert call["batch_size"] == 100
    assert call["max_events"] == 100

    assert call["start_time"] == datetime(
        2026,
        10,
        7,
        16,
        30,
        tzinfo=timezone.utc,
    )

    assert call["end_time"] == datetime(
        2026,
        10,
        7,
        17,
        30,
        tzinfo=timezone.utc,
    )

    assert [
        item.event_id
        for item in result.related_events
    ] == [
        "event-1",
        "event-2",
    ]

    assert result.returned_count == 2
    assert result.truncated is False


def test_correlation_reports_truncation():
    event = make_event()

    connector = Mock()

    connector.search_all.return_value = ElasticSearchResult(
        events=[
            {
                "index": "logs-test",
                "id": "event-1",
                "score": 1.0,
                "source": {
                    "@timestamp": "2026-10-07T17:00:00Z",
                    "event": {
                        "action": "logon",
                    },
                    "host": {
                        "name": "WIN-DC-01",
                    },
                },
            },
        ],
        truncated=True,
    )

    result = correlate_event(
        event,
        connector=connector,
        max_events=1,
    )

    assert result.returned_count == 1
    assert result.truncated is True


def test_invalid_window_is_rejected():
    event = make_event()

    connector = Mock()

    try:
        correlate_event(
            event,
            connector=connector,
            window_minutes=0,
        )
    except ValueError as exc:
        assert "window_minutes" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_max_events_is_bounded():
    event = make_event()

    connector = Mock()

    try:
        correlate_event(
            event,
            connector=connector,
            max_events=5001,
        )
    except ValueError as exc:
        assert "max_events" in str(exc)
    else:
        raise AssertionError("Expected ValueError")

def test_correlation_attaches_relevance_to_all_events():
    event = make_event()

    connector = Mock()

    connector.search_all.return_value = ElasticSearchResult(
        events=[
            {
                "index": "logs-test",
                "id": "event-2",
                "score": 1.0,
                "source": {
                    "@timestamp": "2026-10-07T17:10:00Z",
                    "event": {
                        "action": "network-connection",
                    },
                    "host": {
                        "name": "WIN-DC-01",
                    },
                },
            },
            {
                "index": "logs-test",
                "id": "event-1",
                "score": 1.0,
                "source": {
                    "@timestamp": "2026-10-07T16:45:00Z",
                    "event": {
                        "action": "logon",
                    },
                    "host": {
                        "name": "WIN-DC-01",
                    },
                },
            },
        ],
        truncated=False,
    )

    result = correlate_event(
        event,
        connector=connector,
        window_minutes=30,
        max_events=100,
    )

    assert isinstance(result, CorrelationResult)

    assert len(result.related_events) == 2
    assert len(result.evidence) == 2

    assert all(
        isinstance(item, CorrelatedEvidence)
        for item in result.evidence
    )

    assert {
        item.event.event_id
        for item in result.evidence
    } == {
        item.event_id
        for item in result.related_events
    }


def test_correlation_evidence_is_ranked_by_relevance():
    event = make_event()

    connector = Mock()

    connector.search_all.return_value = ElasticSearchResult(
        events=[
            {
                "index": "logs-test",
                "id": "event-low",
                "score": 1.0,
                "source": {
                    "@timestamp": "2026-10-07T17:25:00Z",
                    "event": {
                        "action": "network-connection",
                    },
                    "host": {
                        "name": "OTHER-HOST",
                    },
                    "user": {
                        "name": "other-user",
                    },
                    "source": {
                        "ip": "192.168.1.50",
                    },
                    "process": {
                        "name": "notepad.exe",
                    },
                },
            },
            {
                "index": "logs-test",
                "id": "event-high",
                "score": 1.0,
                "source": {
                    "@timestamp": "2026-10-07T17:01:00Z",
                    "event": {
                        "action": "process-start",
                    },
                    "host": {
                        "name": "WIN-DC-01",
                    },
                    "user": {
                        "name": "jsmith",
                    },
                    "source": {
                        "ip": "10.10.10.25",
                    },
                    "process": {
                        "name": "powershell.exe",
                    },
                },
            },
        ],
        truncated=False,
    )

    result = correlate_event(
        event,
        connector=connector,
        window_minutes=30,
        max_events=100,
    )

    assert len(result.related_events) == 2
    assert len(result.evidence) == 2

    assert result.evidence[0].event.event_id == "event-high"
    assert result.evidence[1].event.event_id == "event-low"

    assert (
        result.evidence[0].relevance.score
        > result.evidence[1].relevance.score
    )
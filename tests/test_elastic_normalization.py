from normalization.elastic import normalize_elastic_event
from normalization.schemas import EventSeverity, EventSource


def test_normalize_elastic_security_event() -> None:
    elastic_hit = {
        "index": ".ds-logs-system.security-default-2026.09.29-000001",
        "id": "AaEXUizGAsRPJXSDlNbd",
        "score": 1.0,
        "source": {
            "@timestamp": "2026-10-07T17:04:01.293Z",
            "message": "Credential Manager credentials were read.",
            "log": {
                "level": "information",
            },
            "event": {
                "code": "5379",
                "action": "credential-manager-credentials-were-read",
            },
            "host": {
                "hostname": "CYBERHACKY",
            },
            "user": {
                "name": "C Y B E R  H A C K Y",
            },
        },
    }

    event = normalize_elastic_event(elastic_hit)

    assert event.event_id == "5379"
    assert event.source == EventSource.ELASTIC
    assert event.event_type == "credential-manager-credentials-were-read"
    assert event.severity == EventSeverity.LOW
    assert event.host == "CYBERHACKY"
    assert event.username == "C Y B E R  H A C K Y"
    assert event.source_index == elastic_hit["index"]
    assert event.source_document_id == elastic_hit["id"]
    assert event.raw_event == elastic_hit


def test_normalize_elastic_network_event() -> None:
    elastic_hit = {
        "index": ".ds-metrics-system.network-default-2026.09.29-000001",
        "id": "network-event-1",
        "score": 1.0,
        "source": {
            "@timestamp": "2026-10-07T17:29:33.341Z",
            "data_stream": {
                "dataset": "system.network",
            },
            "host": {
                "hostname": "CYBERHACKY",
            },
        },
    }

    event = normalize_elastic_event(elastic_hit)

    assert event.event_id == "network-event-1"
    assert event.source == EventSource.ELASTIC
    assert event.event_type == "system.network"
    assert event.host == "CYBERHACKY"
    assert event.source_index == elastic_hit["index"]
    assert event.raw_event == elastic_hit
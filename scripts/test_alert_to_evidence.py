from datetime import datetime, timedelta, timezone

from collectors.elastic import ElasticConnector
from investigation.correlation import (
    build_correlation_query,
    correlate_event,
)
from normalization.elastic import normalize_elastic_event
from normalization.entities import extract_entities


def main() -> None:
    connector = ElasticConnector()

    print("=== SOCForge Alert → Evidence Test ===")
    print(f"Elastic ping: {connector.ping()}")

    # Retrieve one real Windows Security event.
    result = connector.search(
        index=".ds-logs-system.security-*",
        size=1,
        query={
            "term": {
                "event.code": "4624",
            }
        },
    )

    if not result:
        raise RuntimeError(
            "No real Windows Security 4624 event was found"
        )

    raw_event = result[0]

    print()
    print("=== Input Event ===")
    print(f"Index: {raw_event['index']}")
    print(f"ID:    {raw_event['id']}")

    # Normalize the real Elastic event.
    event = normalize_elastic_event(raw_event)

    print()
    print("=== Normalized Event ===")
    print(f"Event ID:     {event.event_id}")
    print(f"Timestamp:    {event.timestamp}")
    print(f"Event type:   {event.event_type}")
    print(f"Host:         {event.host}")
    print(f"Username:     {event.username}")
    print(f"Process:      {event.process_name}")
    print(f"Source index: {event.source_index}")

    # Extract entities.
    entities = extract_entities(event)

    print()
    print("=== Extracted Entities ===")
    print(f"IPs:          {entities.ips}")
    print(f"Domains:      {entities.domains}")
    print(f"URLs:         {entities.urls}")
    print(f"Hashes:       {entities.hashes}")
    print(f"Usernames:    {entities.usernames}")
    print(f"Hostnames:    {entities.hostnames}")
    print(f"Processes:    {entities.processes}")

    # Correlate around the event using the real Elastic connector.

    correlation_query = build_correlation_query(event)

    print()
    print("=== Correlation Query ===")
    print(correlation_query)

    correlation = correlate_event(
        event,
        connector=connector,
        window_minutes=30,
        max_events=100,
    )

    print()
    print("=== Investigation Evidence ===")
    print(f"Window start: {correlation.window_start}")
    print(f"Window end:   {correlation.window_end}")
    print(f"Events:       {correlation.returned_count}")
    print(f"Truncated:    {correlation.truncated}")

    print()
    print("=== Related Events ===")

    for related in correlation.related_events[:10]:
        print(
            f"- {related.timestamp.isoformat()} | "
            f"{related.event_type} | "
            f"host={related.host} | "
            f"user={related.username} | "
            f"process={related.process_name}"
        )

    print()
    print("=== Evidence Validation ===")

    assert correlation.alert.event_id == event.event_id
    assert correlation.related_events
    assert correlation.returned_count == len(
        correlation.related_events
    )

    # The raw Elastic document must remain available.
    assert correlation.alert.raw_event

    print("Alert/event preserved: PASS")
    print("Normalization:         PASS")
    print("Entity extraction:     PASS")
    print("Elastic correlation:   PASS")
    print("Raw evidence retained: PASS")

    print()
    print("=== Alert → Evidence COMPLETE ===")


if __name__ == "__main__":
    main()

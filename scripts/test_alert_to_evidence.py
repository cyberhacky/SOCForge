from collectors.elastic import ElasticConnector
from investigation.correlation import (
    build_correlation_query,
    correlate_event,
)
from normalization.elastic import normalize_elastic_event
from normalization.entities import extract_entities


def main() -> None:
    connector = ElasticConnector()

    print("=== SOCForge Alert -> Evidence Test ===")
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

    # Build the deterministic correlation query.
    correlation_query = build_correlation_query(event)

    print()
    print("=== Correlation Query ===")
    print(correlation_query)

    # Correlate the event against real Elastic data.
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
    print("=== Ranked Evidence ===")

    for item in correlation.evidence[:10]:
        relevance = item.relevance

        print(
            f"- score={relevance.score:3d} | "
            f"category={relevance.category:6s} | "
            f"event={item.event.event_id} | "
            f"time={item.event.timestamp.isoformat()}"
        )

        print(
            f"  host={item.event.host} | "
            f"user={item.event.username} | "
            f"process={item.event.process_name}"
        )

        print(
            f"  matched={relevance.matched_entities}"
        )

        for reason in relevance.reasons:
            print(f"  reason={reason}")

    print()
    print("=== Evidence Validation ===")

    # The original alert must be preserved.
    assert correlation.alert.event_id == event.event_id

    # Correlation must return related evidence.
    assert correlation.related_events
    assert correlation.evidence

    # Returned count must match the preserved related events.
    assert correlation.returned_count == len(
        correlation.related_events
    )

    # Every related event must have relevance metadata.
    assert len(correlation.evidence) == len(
        correlation.related_events
    )

    # Every correlated event must remain represented
    # in the ranked evidence.
    related_ids = {
        related.event_id
        for related in correlation.related_events
    }

    evidence_ids = {
        item.event.event_id
        for item in correlation.evidence
    }

    assert evidence_ids == related_ids

    # Evidence must have valid deterministic relevance metadata.
    for item in correlation.evidence:
        assert 0 <= item.relevance.score <= 100

        assert item.relevance.category in {
            "high",
            "medium",
            "low",
        }

        assert item.relevance.reasons

    # Ranked evidence must be ordered highest -> lowest score.
    scores = [
        item.relevance.score
        for item in correlation.evidence
    ]

    assert scores == sorted(
        scores,
        reverse=True,
    )

    # The raw Elastic document must remain available.
    assert correlation.alert.raw_event

    print("Alert/event preserved:       PASS")
    print("Normalization:               PASS")
    print("Entity extraction:           PASS")
    print("Elastic correlation:         PASS")
    print("Relevance evaluation:        PASS")
    print("Evidence ranking:            PASS")
    print("Evidence preservation:       PASS")
    print("Raw evidence retained:       PASS")

    print()
    print("=== Alert -> Evidence COMPLETE ===")


if __name__ == "__main__":
    main()
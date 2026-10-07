from datetime import datetime, timedelta, timezone

from collectors.elastic import ElasticConnector
from investigation.correlation import build_correlation_query
from normalization.elastic import normalize_elastic_event
from normalization.entities import extract_entities


def main() -> None:
    connector = ElasticConnector()

    print("[+] Testing Elasticsearch connection...")
    print(f"[+] Ping: {connector.ping()}")

    print("[+] Retrieving recent Elastic event...")

    hits = connector.search(
        index="*",
        size=1,
    )

    if not hits:
        print("[-] No events were returned from Elasticsearch.")
        return

    hit = hits[0]

    print()
    print("=== RAW ELASTIC EVENT ===")
    print(f"Index : {hit.get('index')}")
    print(f"ID    : {hit.get('id')}")

    event = normalize_elastic_event(hit)
    entities = extract_entities(event)
    event.entities = entities

    print()
    print("=== NORMALIZED EVENT ===")
    print(f"Event ID      : {event.event_id}")
    print(f"Timestamp     : {event.timestamp}")
    print(f"Event Type    : {event.event_type}")
    print(f"Host          : {event.host}")
    print(f"Username      : {event.username}")
    print(f"Source IP     : {event.source_ip}")
    print(f"Destination IP: {event.destination_ip}")
    print(f"Process       : {event.process_name}")

    print()
    print("=== EXTRACTED ENTITIES ===")
    print(f"IPs           : {entities.ips}")
    print(f"Domains       : {entities.domains}")
    print(f"URLs          : {entities.urls}")
    print(f"Hashes        : {entities.hashes}")
    print(f"Usernames     : {entities.usernames}")
    print(f"Hostnames     : {entities.hostnames}")
    print(f"Processes     : {entities.processes}")

    query = build_correlation_query(event)

    print()
    print("=== CORRELATION QUERY ===")
    print(query)

    start_time = event.timestamp - timedelta(minutes=30)
    end_time = event.timestamp + timedelta(minutes=30)

    print()
    print("=== CORRELATED EVENTS ===")

    related = connector.search(
        index="*",
        query=query,
        start_time=start_time,
        end_time=end_time,
        size=100,
    )

    print(f"[+] Retrieved {len(related)} related events")

    for number, related_hit in enumerate(related, start=1):
        related_event = normalize_elastic_event(related_hit)

        print(
            f"{number:03d} | "
            f"{related_event.timestamp.isoformat()} | "
            f"{related_event.event_type} | "
            f"host={related_event.host} | "
            f"user={related_event.username} | "
            f"source_ip={related_event.source_ip} | "
            f"destination_ip={related_event.destination_ip} | "
            f"process={related_event.process_name}"
        )


if __name__ == "__main__":
    main()
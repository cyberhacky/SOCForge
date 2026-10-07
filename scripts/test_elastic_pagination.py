from datetime import datetime, timedelta, timezone

from collectors.elastic import ElasticConnector


def main() -> None:
    connector = ElasticConnector()

    print("=== SOCForge Elastic PIT Pagination Test ===")

    print(f"Ping: {connector.ping()}")

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=15)

    print(f"Start: {start_time.isoformat()}")
    print(f"End:   {end_time.isoformat()}")
    print("Index: *")
    print("Batch size: 25")
    print("Max events: 100")

    result = connector.search_all(
        index="*",
        start_time=start_time,
        end_time=end_time,
        batch_size=25,
        max_events=100,
    )

    print()
    print("=== Result ===")
    print(f"Events returned: {len(result.events)}")
    print(f"Truncated:       {result.truncated}")

    if result.events:
        print()
        print("=== First 5 events ===")

        for event in result.events[:5]:
            source = event.get("source", {})

            print(
                f"- {event.get('id')} | "
                f"{source.get('@timestamp')} | "
                f"{event.get('index')}"
            )

    print()
    print("=== Pagination test complete ===")


if __name__ == "__main__":
    main()
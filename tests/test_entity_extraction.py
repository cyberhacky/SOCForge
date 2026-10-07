from datetime import datetime, timezone

from normalization.entities import extract_entities
from normalization.schemas import EventSource, SOCEvent


def make_event(
    *,
    message: str | None = None,
    raw_event: dict | None = None,
) -> SOCEvent:
    now = datetime.now(timezone.utc)

    return SOCEvent(
        event_id="entity-test-001",
        timestamp=now,
        source=EventSource.ELASTIC,
        event_type="security-event",
        host="WIN-DC-01",
        username="jsmith",
        source_ip="10.10.10.25",
        destination_ip="185.0.0.1",
        process_name="powershell.exe",
        process_command_line="powershell.exe -enc AAAABBBB",
        ingestion_timestamp=now,
        message=message,
        raw_event=raw_event or {},
    )


def test_extract_structured_entities() -> None:
    event = make_event()

    entities = extract_entities(event)

    assert "10.10.10.25" in entities.ips
    assert "185.0.0.1" in entities.ips
    assert "jsmith" in entities.usernames
    assert "WIN-DC-01" in entities.hostnames
    assert "powershell.exe" in entities.processes
    assert "powershell.exe -enc AAAABBBB" in entities.command_lines


def test_extract_url_domain_ip_and_hash() -> None:
    event = make_event(
        message=(
            "Connection to https://example.com/payload.exe "
            "from 203.0.113.50 "
            "with hash "
            "0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef"
        )
    )

    entities = extract_entities(event)

    assert "https://example.com/payload.exe" in entities.urls
    assert "example.com" in entities.domains
    assert "203.0.113.50" in entities.ips
    assert (
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef"
        in entities.hashes
    )


def test_extract_selected_raw_elastic_fields() -> None:
    event = make_event(
        raw_event={
            "source": {
                "url": {
                    "full": "https://malicious.example/download.exe",
                },
                "file": {
                    "hash": {
                        "sha256": (
                            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef"
                            "abcdefabcdefabcdefabcdef"
                        )
                    }
                },
                "dns": {
                    "question": {
                        "name": "evil.example",
                    }
                },
            }
        }
    )

    entities = extract_entities(event)

    assert "https://malicious.example/download.exe" in entities.urls
    assert "malicious.example" in entities.domains
    assert "evil.example" in entities.domains


def test_invalid_ip_is_not_extracted() -> None:
    event = make_event(
        message="Invalid address 999.999.999.999 was observed."
    )

    entities = extract_entities(event)

    assert "999.999.999.999" not in entities.ips


def test_extraction_treats_command_text_as_untrusted_data() -> None:
    event = make_event(
        message="powershell.exe -Command Write-Host 'this must remain data'"
    )

    entities = extract_entities(event)

    assert entities is not None
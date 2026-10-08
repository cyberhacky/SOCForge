from datetime import timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from collectors.elastic import ElasticConnector
from investigation.relevance import (
    EvidenceRelevance,
    evaluate_relevance,
)
from normalization.elastic import normalize_elastic_event
from normalization.schemas import SOCEvent


DEFAULT_WINDOW_MINUTES = 30
DEFAULT_MAX_EVENTS = 1000


class CorrelatedEvidence(BaseModel):
    """
    A correlated event together with deterministic relevance metadata.

    Relevance describes investigative usefulness. It does not determine
    whether the event is malicious.
    """

    model_config = ConfigDict(extra="forbid")

    event: SOCEvent
    relevance: EvidenceRelevance


class CorrelationResult(BaseModel):
    """
    Evidence returned by an Elastic correlation operation.

    `related_events` contains the complete retrieved evidence set.

    `evidence` contains the same events paired with deterministic
    relevance metadata and ordered from most relevant to least relevant.

    `truncated` means the requested result limit was reached and the
    complete evidence set has not been established.
    """

    model_config = ConfigDict(extra="forbid")

    alert: SOCEvent
    related_events: list[SOCEvent] = Field(default_factory=list)

    evidence: list[CorrelatedEvidence] = Field(
        default_factory=list
    )

    window_start: str
    window_end: str

    matched_entities: dict[str, list[str]] = Field(
        default_factory=dict
    )

    returned_count: int = 0
    truncated: bool = False


def _term_should(
    field: str,
    values: list[str],
) -> list[dict[str, Any]]:
    """Build exact-match ECS queries for a field."""
    return [
        {"term": {field: value}}
        for value in values
        if value
    ]


def build_correlation_query(
    event: SOCEvent,
) -> dict[str, Any]:
    """
    Build a structured Elasticsearch query from normalized event entities.

    Event content is treated as untrusted data. Values are inserted into
    structured term queries and are never interpreted as query-string syntax.
    """
    entities = event.entities

    should: list[dict[str, Any]] = []

    # Host
    should.extend(
        _term_should(
            "host.hostname",
            entities.hostnames,
        )
    )

    should.extend(
        _term_should(
            "host.name",
            entities.hostnames,
        )
    )

    # User
    should.extend(
        _term_should(
            "user.name",
            entities.usernames,
        )
    )

    should.extend(
        _term_should(
            "user.full_name",
            entities.usernames,
        )
    )

    # IP
    should.extend(
        _term_should(
            "source.ip",
            entities.ips,
        )
    )

    should.extend(
        _term_should(
            "destination.ip",
            entities.ips,
        )
    )

    # Process
    should.extend(
        _term_should(
            "process.name",
            entities.processes,
        )
    )

    should.extend(
        _term_should(
            "process.executable",
            entities.processes,
        )
    )

    # Domain
    should.extend(
        _term_should(
            "url.domain",
            entities.domains,
        )
    )

    should.extend(
        _term_should(
            "dns.question.name",
            entities.domains,
        )
    )

    should.extend(
        _term_should(
            "destination.domain",
            entities.domains,
        )
    )

    should.extend(
        _term_should(
            "source.domain",
            entities.domains,
        )
    )

    # Hash
    should.extend(
        _term_should(
            "file.hash.md5",
            entities.hashes,
        )
    )

    should.extend(
        _term_should(
            "file.hash.sha1",
            entities.hashes,
        )
    )

    should.extend(
        _term_should(
            "file.hash.sha256",
            entities.hashes,
        )
    )

    if not should:
        return {
            "bool": {
                "must": [
                    {
                        "match_none": {},
                    }
                ]
            }
        }

    return {
        "bool": {
            "should": should,
            "minimum_should_match": 1,
        }
    }


def _matched_entities(
    event: SOCEvent,
) -> dict[str, list[str]]:
    """Return the entity values used for correlation."""
    entities = event.entities

    return {
        "ips": list(entities.ips),
        "domains": list(entities.domains),
        "hashes": list(entities.hashes),
        "usernames": list(entities.usernames),
        "hostnames": list(entities.hostnames),
        "processes": list(entities.processes),
    }


def _build_evidence(
    alert: SOCEvent,
    related_events: list[SOCEvent],
) -> list[CorrelatedEvidence]:
    """
    Attach deterministic relevance metadata to every correlated event.

    No event is discarded at this stage.
    """

    evidence = [
        CorrelatedEvidence(
            event=related_event,
            relevance=evaluate_relevance(
                alert,
                related_event,
            ),
        )
        for related_event in related_events
    ]

    evidence.sort(
        key=lambda item: (
            -item.relevance.score,
            item.event.timestamp,
            item.event.event_id,
        )
    )

    return evidence


def correlate_event(
    event: SOCEvent,
    *,
    connector: ElasticConnector | None = None,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
    max_events: int = DEFAULT_MAX_EVENTS,
) -> CorrelationResult:
    """
    Find Elastic events related to a normalized security event.

    Correlation uses the event timestamp +/- the configured window and
    deterministic ECS entity matching.

    `related_events` preserves the complete retrieved evidence set.

    `evidence` contains the same events with deterministic relevance
    metadata and is ordered from most relevant to least relevant.

    A result is marked `truncated=True` when Elasticsearch reaches the
    configured safety limit.
    """
    if window_minutes < 1:
        raise ValueError(
            "window_minutes must be greater than zero"
        )

    if max_events < 1:
        raise ValueError(
            "max_events must be greater than zero"
        )

    if max_events > 5000:
        raise ValueError(
            "max_events must not exceed 5000"
        )

    if connector is None:
        connector = ElasticConnector()

    timestamp = event.timestamp

    start_time = timestamp - timedelta(
        minutes=window_minutes
    )

    end_time = timestamp + timedelta(
        minutes=window_minutes
    )

    query = build_correlation_query(event)

    search_result = connector.search_all(
        index="*",
        query=query,
        start_time=start_time,
        end_time=end_time,
        batch_size=100,
        max_events=max_events,
    )

    related_events = [
        normalize_elastic_event(hit)
        for hit in search_result.events
    ]

    related_events.sort(
        key=lambda item: item.timestamp
    )

    evidence = _build_evidence(
        event,
        related_events,
    )

    return CorrelationResult(
        alert=event,
        related_events=related_events,
        evidence=evidence,
        window_start=start_time.isoformat(),
        window_end=end_time.isoformat(),
        matched_entities=_matched_entities(event),
        returned_count=len(related_events),
        truncated=search_result.truncated,
    )
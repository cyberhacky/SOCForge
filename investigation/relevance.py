from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from normalization.schemas import SOCEvent


RelevanceCategory = Literal["high", "medium", "low"]


class EvidenceRelevance(BaseModel):
    """
    Deterministic relevance assessment for an event relative to an alert.

    This describes how useful the event is as investigation evidence.
    It does not determine whether the event is malicious.
    """

    model_config = ConfigDict(extra="forbid")

    score: int = Field(ge=0, le=100)
    category: RelevanceCategory
    matched_entities: dict[str, list[str]] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)


_ROUTINE_EVENT_TYPES = {
    "system.cpu",
    "system.memory",
    "system.uptime",
    "system.diskio",
    "system.network",
    "system.process.summary",
    "elastic_agent.fleet_server",
}


def _normalise(value: str | None) -> str | None:
    if value is None:
        return None

    value = value.strip().lower()

    return value or None


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _matching_values(
    alert_values: list[str],
    event_values: list[str],
) -> list[str]:
    alert_normalized = {
        _normalise(value)
        for value in alert_values
        if _normalise(value) is not None
    }

    matches: list[str] = []

    for value in event_values:
        normalized = _normalise(value)

        if normalized is not None and normalized in alert_normalized:
            matches.append(value)

    return _unique(matches)


def _matched_entities(
    alert: SOCEvent,
    event: SOCEvent,
) -> dict[str, list[str]]:
    """
    Find deterministic entity overlap between the alert and evidence event.
    """

    matches: dict[str, list[str]] = {}

    host_values = _matching_values(
        alert.entities.hostnames,
        event.entities.hostnames,
    )

    if alert.host and event.host:
        if _normalise(alert.host) == _normalise(event.host):
            host_values = _unique(host_values + [event.host])

    if host_values:
        matches["host"] = host_values

    username_values = _matching_values(
        alert.entities.usernames,
        event.entities.usernames,
    )

    if alert.username and event.username:
        if _normalise(alert.username) == _normalise(event.username):
            username_values = _unique(
                username_values + [event.username]
            )

    if username_values:
        matches["username"] = username_values

    process_values = _matching_values(
        alert.entities.processes,
        event.entities.processes,
    )

    if alert.process_name and event.process_name:
        if _normalise(alert.process_name) == _normalise(
            event.process_name
        ):
            process_values = _unique(
                process_values + [event.process_name]
            )

    if process_values:
        matches["process"] = process_values

    alert_ips = list(alert.entities.ips)

    if alert.source_ip:
        alert_ips.append(alert.source_ip)

    if alert.destination_ip:
        alert_ips.append(alert.destination_ip)

    event_ips = list(event.entities.ips)

    if event.source_ip:
        event_ips.append(event.source_ip)

    if event.destination_ip:
        event_ips.append(event.destination_ip)

    ip_values = _matching_values(alert_ips, event_ips)

    if ip_values:
        matches["ip"] = ip_values

    domain_values = _matching_values(
        alert.entities.domains,
        event.entities.domains,
    )

    if domain_values:
        matches["domain"] = domain_values

    hash_values = _matching_values(
        alert.entities.hashes,
        event.entities.hashes,
    )

    if hash_values:
        matches["hash"] = hash_values

    return matches


def _timestamp_score(
    alert_timestamp: datetime,
    event_timestamp: datetime,
) -> tuple[int, str]:
    """
    Give more relevance to temporally close events.

    The timestamp contributes to evidence relevance only.
    """

    delta_seconds = abs(
        (event_timestamp - alert_timestamp).total_seconds()
    )

    delta_minutes = delta_seconds / 60

    if delta_minutes <= 2:
        return 10, "event occurred within 2 minutes of the alert"

    if delta_minutes <= 5:
        return 8, "event occurred within 5 minutes of the alert"

    if delta_minutes <= 15:
        return 5, "event occurred within 15 minutes of the alert"

    if delta_minutes <= 30:
        return 2, "event occurred within 30 minutes of the alert"

    return 0, "event is temporally distant from the alert"


def _category(score: int) -> RelevanceCategory:
    if score >= 70:
        return "high"

    if score >= 30:
        return "medium"

    return "low"


def evaluate_relevance(
    alert: SOCEvent,
    event: SOCEvent,
) -> EvidenceRelevance:
    """
    Evaluate how relevant an event is as evidence for an alert.

    This function is deterministic and evidence-oriented.

    It does NOT decide whether either event is malicious.
    """

    if alert.event_id == event.event_id:
        return EvidenceRelevance(
            score=100,
            category="high",
            matched_entities={},
            reasons=["Original alert"],
        )

    matched = _matched_entities(alert, event)

    score = 0
    reasons: list[str] = []

    weights = {
        "host": 20,
        "username": 20,
        "process": 20,
        "ip": 25,
        "domain": 25,
        "hash": 30,
    }

    for entity_type, values in matched.items():
        score += weights.get(entity_type, 0)

        reasons.append(
            f"matched {entity_type}: "
            + ", ".join(values)
        )

    timestamp_points, timestamp_reason = _timestamp_score(
        alert.timestamp,
        event.timestamp,
    )

    score += timestamp_points
    reasons.append(timestamp_reason)

    if event.event_type in _ROUTINE_EVENT_TYPES:
        score = min(score, 50)
        reasons.append(
            "routine system telemetry was capped to avoid "
            "automatically treating it as highly relevant"
        )

    score = min(score, 100)

    if not reasons:
        reasons.append("no strong evidence relationship identified")

    return EvidenceRelevance(
        score=score,
        category=_category(score),
        matched_entities=matched,
        reasons=reasons,
    )
import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from normalization.schemas import EventEntities, SOCEvent


MAX_TEXT_LENGTH = 100_000
MAX_ENTITIES_PER_TYPE = 100

NON_DOMAIN_SUFFIXES = {
    "bat",
    "cmd",
    "dll",
    "exe",
    "msi",
    "ps1",
    "psm1",
    "psd1",
    "scr",
    "sys",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "wsh",
}


IP_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"\[[0-9A-Fa-f:]+\]"
    r"|"
    r"[0-9A-Fa-f:]{2,}"
    r")"
    r"(?![A-Za-z0-9])"
)


URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"`]+",
    re.IGNORECASE,
)


DOMAIN_PATTERN = re.compile(
    r"(?<![@A-Za-z0-9])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}"
    r"(?![A-Za-z0-9-])",
    re.IGNORECASE,
)


HASH_PATTERN = re.compile(
    r"(?<![A-Fa-f0-9])"
    r"(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})"
    r"(?![A-Fa-f0-9])"
)


def _clean_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value:
        return None

    return value[:MAX_TEXT_LENGTH]


def _append_unique(
    values: list[str],
    value: str,
) -> None:
    if value and value not in values and len(values) < MAX_ENTITIES_PER_TYPE:
        values.append(value)


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def _valid_url(value: str) -> bool:
    try:
        parsed = urlparse(value)

        return (
            parsed.scheme.lower() in {"http", "https"}
            and bool(parsed.hostname)
        )
    except ValueError:
        return False


def _valid_domain(value: str) -> bool:
    value = value.rstrip(".").lower()

    if len(value) > 253:
        return False

    if "." not in value:
        return False

    labels = value.split(".")

    if labels[-1] in NON_DOMAIN_SUFFIXES:
        return False

    return all(
        label
        and len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        for label in labels
    )


def _extract_ips(text: str, entities: EventEntities) -> None:
    for match in IP_PATTERN.findall(text):
        candidate = match.strip("[]")

        if _valid_ip(candidate):
            _append_unique(entities.ips, candidate)


def _extract_urls(text: str, entities: EventEntities) -> None:
    for match in URL_PATTERN.findall(text):
        candidate = match.rstrip(".,;:)]}")

        if not _valid_url(candidate):
            continue

        _append_unique(entities.urls, candidate)

        parsed = urlparse(candidate)
        hostname = parsed.hostname

        if hostname and _valid_domain(hostname):
            _append_unique(entities.domains, hostname.lower())

def _extract_domains(text: str, entities: EventEntities) -> None:
    for match in DOMAIN_PATTERN.findall(text):
        candidate = match.rstrip(".").lower()

        if _valid_domain(candidate):
            _append_unique(entities.domains, candidate)


def _extract_hashes(text: str, entities: EventEntities) -> None:
    for match in HASH_PATTERN.findall(text):
        _append_unique(entities.hashes, match.lower())


def _extract_structured_entities(
    event: SOCEvent,
    entities: EventEntities,
) -> None:
    if event.username:
        _append_unique(entities.usernames, event.username)

    if event.host:
        _append_unique(entities.hostnames, event.host)

    if event.process_name:
        _append_unique(entities.processes, event.process_name)

    if event.process_command_line:
        command_line = _clean_text(event.process_command_line)

        if command_line:
            _append_unique(entities.command_lines, command_line)

    for value in (event.source_ip, event.destination_ip):
        if value and _valid_ip(value):
            _append_unique(entities.ips, value)


def _extract_from_text(
    text: str,
    entities: EventEntities,
) -> None:
    text = _clean_text(text)

    if not text:
        return

    _extract_urls(text, entities)
    _extract_ips(text, entities)
    _extract_hashes(text, entities)
    _extract_domains(text, entities)


def _extract_selected_raw_fields(
    raw_event: dict[str, Any],
    entities: EventEntities,
) -> None:
    source = raw_event.get("source", {})

    if not isinstance(source, dict):
        return

    message = source.get("message")
    _extract_from_text(message or "", entities)

    url = source.get("url")

    if isinstance(url, dict):
        for key in ("full", "original", "domain"):
            value = url.get(key)

            if isinstance(value, str):
                if key in {"full", "original"}:
                    _extract_urls(value, entities)
                else:
                    _extract_domains(value, entities)

    destination = source.get("destination")

    if isinstance(destination, dict):
        for key in ("domain", "address"):
            value = destination.get(key)

            if isinstance(value, str):
                if key == "domain":
                    _extract_domains(value, entities)
                elif _valid_ip(value):
                    _append_unique(entities.ips, value)

    source_entity = source.get("source")

    if isinstance(source_entity, dict):
        for key in ("domain", "address"):
            value = source_entity.get(key)

            if isinstance(value, str):
                if key == "domain":
                    _extract_domains(value, entities)
                elif _valid_ip(value):
                    _append_unique(entities.ips, value)

    file_data = source.get("file")

    if isinstance(file_data, dict):
        hashes = file_data.get("hash")

        if isinstance(hashes, dict):
            for value in hashes.values():
                if isinstance(value, str):
                    _extract_hashes(value, entities)

    dns = source.get("dns")

    if isinstance(dns, dict):
        question = dns.get("question")

        if isinstance(question, dict):
            value = question.get("name")

            if isinstance(value, str):
                _extract_domains(value, entities)


def extract_entities(event: SOCEvent) -> EventEntities:
    """
    Extract deterministic security entities from a normalized event.

    Event content is treated strictly as untrusted data. No extracted
    command, URL, or other value is executed or interpreted as an
    instruction.
    """

    entities = EventEntities()

    _extract_structured_entities(event, entities)

    _extract_from_text(event.message or "", entities)

    _extract_selected_raw_fields(event.raw_event, entities)

    return entities

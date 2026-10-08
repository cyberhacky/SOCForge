

import ipaddress
import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


IndicatorType = Literal[
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "md5",
    "sha1",
    "sha256",
]


class EnrichmentStatus(StrEnum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


_HASH_LENGTHS = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
}


def _valid_domain(value: str) -> bool:
    """Accept an ASCII fully qualified domain name."""
    if not value or len(value) > 253 or value.endswith("."):
        return False

    labels = value.split(".")
    if len(labels) < 2:
        return False

    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        is not None
        for label in labels
    )


def _valid_ip(value: str, version: int) -> bool:
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False


class Indicator(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    value: str = Field(min_length=1, max_length=2048)
    type: IndicatorType

    @field_validator("value")
    @classmethod
    def reject_whitespace(cls, value: str) -> str:
        if value != value.strip() or any(char.isspace() for char in value):
            raise ValueError("indicator must not contain whitespace")
        return value

    @model_validator(mode="after")
    def validate_value_matches_type(self):
        value = self.value
        indicator_type = self.type

        if indicator_type == "ipv4" and not _valid_ip(value, 4):
            raise ValueError("value must be a valid IPv4 address")

        if indicator_type == "ipv6" and not _valid_ip(value, 6):
            raise ValueError("value must be a valid IPv6 address")

        if indicator_type == "domain" and not _valid_domain(value):
            raise ValueError("value must be a valid ASCII domain name")

        if indicator_type == "url":
            try:
                parsed = urlsplit(value)
                hostname = parsed.hostname
                # Accessing .port also validates the port syntax.
                _ = parsed.port
            except ValueError as exc:
                raise ValueError("URL is malformed") from exc

            if parsed.scheme.lower() not in {"http", "https"}:
                raise ValueError("URL scheme must be http or https")

            if not parsed.netloc or not hostname:
                raise ValueError("URL must contain a hostname")

            if parsed.username is not None or parsed.password is not None:
                raise ValueError("URL must not contain embedded credentials")

            if not (
                _valid_ip(hostname, 4)
                or _valid_ip(hostname, 6)
                or _valid_domain(hostname)
            ):
                raise ValueError("URL hostname is invalid")

        if indicator_type in _HASH_LENGTHS:
            expected_length = _HASH_LENGTHS[indicator_type]
            if len(value) != expected_length or not re.fullmatch(
                r"[0-9a-fA-F]+", value
            ):
                raise ValueError(
                    f"{indicator_type} must contain exactly "
                    f"{expected_length} hexadecimal characters"
                )

        return self


class EnrichmentResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator: str = Field(min_length=1, max_length=2048)
    type: IndicatorType
    provider: str = Field(min_length=1, max_length=100)
    status: EnrichmentStatus
    result: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    source_reference: str | None = None
    error_code: str | None = None
    raw: dict[str, Any] | None = None

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_timezone_aware(
        cls, value: datetime
    ) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value

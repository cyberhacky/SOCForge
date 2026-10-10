from ipaddress import ip_address

from pydantic import BaseModel, ConfigDict, Field

from enrichment.base import ThreatIntelProvider
from enrichment.models import (
    EnrichmentResult,
    EnrichmentStatus,
    Indicator,
)
from investigation.correlation import CorrelationResult

MAX_SKIPPED_INDICATOR_LENGTH = 256


class SkippedIndicator(BaseModel):
    """An IP candidate that was not submitted to threat intelligence."""

    model_config = ConfigDict(extra="forbid")

    indicator: str = Field(max_length=MAX_SKIPPED_INDICATOR_LENGTH)
    reason: str


class EnrichmentBatchResult(BaseModel):
    """Threat-intelligence results associated with an investigation."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    results: list[EnrichmentResult] = Field(default_factory=list)
    skipped: list[SkippedIndicator] = Field(default_factory=list)


def _collect_ip_candidates(
    correlation: CorrelationResult,
) -> tuple[list[str], list[SkippedIndicator]]:
    """Collect unique IP candidates and safely record oversized values."""

    events = [correlation.alert, *correlation.related_events]
    candidates: dict[str, str] = {}
    oversized: dict[str, SkippedIndicator] = {}

    for event in events:
        values = [
            *event.entities.ips,
            *([event.source_ip] if event.source_ip else []),
            *([event.destination_ip] if event.destination_ip else []),
        ]

        for value in values:
            candidate = value.strip()

            if not candidate:
                continue

            if len(candidate) > MAX_SKIPPED_INDICATOR_LENGTH:
                # Do not retain the full oversized value in the skip record.
                summary = f"oversized candidate ({len(candidate)} characters)"
                oversized.setdefault(
                    summary,
                    SkippedIndicator(
                        indicator=summary,
                        reason="candidate_too_long",
                    ),
                )
                continue

            try:
                parsed = ip_address(candidate)
            except ValueError:
                # Preserve bounded invalid candidates for an auditable skip.
                candidates.setdefault(f"invalid:{candidate}", candidate)
                continue

            candidates.setdefault(parsed.compressed, parsed.compressed)

    return list(candidates.values()), list(oversized.values())


def _provider_error(
    provider_name: str,
    indicator: Indicator,
    *,
    error_code: str = "provider_exception",
    message: str = "Threat-intelligence provider failed unexpectedly.",
) -> EnrichmentResult:
    """Represent a failed or invalid lookup without exposing internals."""

    return EnrichmentResult(
        indicator=indicator.value,
        type=indicator.type,
        provider=provider_name,
        status=EnrichmentStatus.ERROR,
        result=message,
        error_code=error_code,
    )


def _validate_provider_result(
    result: object,
    *,
    provider_name: str,
    indicator: Indicator,
) -> EnrichmentResult:
    """Reject provider responses that do not match the lookup request."""

    if not isinstance(result, EnrichmentResult):
        return _provider_error(
            provider_name,
            indicator,
            error_code="invalid_provider_response",
            message="Provider returned an invalid response type.",
        )

    if (
        result.provider != provider_name
        or result.indicator != indicator.value
        or result.type != indicator.type
    ):
        return _provider_error(
            provider_name,
            indicator,
            error_code="provider_response_mismatch",
            message=(
                "Provider response did not match the requested "
                "provider and indicator."
            ),
        )

    return result


async def enrich_correlation(
    correlation: CorrelationResult,
    provider: ThreatIntelProvider,
) -> EnrichmentBatchResult:
    """
    Enrich globally routable IPs without changing correlation evidence.

    Invalid, oversized, and non-global IP candidates are skipped. Provider
    exceptions and invalid provider responses become explicit error results
    so that subsequent indicators can still be processed.
    """

    try:
        provider_name = provider.name
    except Exception:
        provider_name = ""

    if not isinstance(provider_name, str) or not provider_name.strip():
        provider_name = "unknown_provider"
        provider_identity_valid = False
    else:
        provider_name = provider_name.strip()
        provider_identity_valid = True

    results: list[EnrichmentResult] = []
    skipped: list[SkippedIndicator] = []

    candidates, oversized = _collect_ip_candidates(correlation)
    skipped.extend(oversized)

    for candidate in candidates:
        try:
            parsed = ip_address(candidate)
        except ValueError:
            skipped.append(
                SkippedIndicator(
                    indicator=candidate,
                    reason="invalid_ip_address",
                )
            )
            continue

        if not parsed.is_global:
            skipped.append(
                SkippedIndicator(
                    indicator=parsed.compressed,
                    reason="non_global_ip_not_sent_to_external_provider",
                )
            )
            continue

        indicator_type = "ipv4" if parsed.version == 4 else "ipv6"
        indicator = Indicator(
            value=parsed.compressed,
            type=indicator_type,
        )

        if not provider_identity_valid:
            results.append(
                _provider_error(
                    provider_name,
                    indicator,
                    error_code="provider_identity_unavailable",
                    message="Provider identity is unavailable.",
                )
            )
            continue

        try:
            response = await provider.enrich(indicator)
        except Exception:
            results.append(
                _provider_error(provider_name, indicator)
            )
            continue

        results.append(
            _validate_provider_result(
                response,
                provider_name=provider_name,
                indicator=indicator,
            )
        )

    return EnrichmentBatchResult(
        provider=provider_name,
        results=results,
        skipped=skipped,
    )

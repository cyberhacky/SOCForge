
from typing import Any
import ipaddress
from urllib.parse import quote, urlsplit

import httpx

from enrichment.base import ThreatIntelProvider
from enrichment.models import (
    EnrichmentResult,
    EnrichmentStatus,
    Indicator,
)


def _same_ip_address(returned_ip: str, submitted_ip: str) -> bool:
    """Compare IP addresses by value, not textual representation."""
    try:
        return ipaddress.ip_address(returned_ip) == ipaddress.ip_address(
            submitted_ip
        )
    except ValueError:
        return False


class AbuseIPDBProvider(ThreatIntelProvider):
    """Read-only AbuseIPDB IP reputation lookup provider."""

    def __init__(
        self,
        api_key: str | None,
        base_url: str = "https://api.abuseipdb.com/api/v2",
        timeout_seconds: float = 10.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        try:
            parsed_url = urlsplit(base_url)
            hostname = parsed_url.hostname

            valid_url = (
                parsed_url.scheme.lower() == "https"
                and hostname is not None
                and hostname.lower() == "api.abuseipdb.com"
                and parsed_url.port in (None, 443)
                and parsed_url.username is None
                and parsed_url.password is None
                and not parsed_url.query
                and not parsed_url.fragment
                and parsed_url.path.rstrip("/") == "/api/v2"
            )
        except (AttributeError, ValueError):
            valid_url = False

        if not valid_url:
            raise ValueError(
                "base_url must use the official AbuseIPDB HTTPS API "
                "endpoint without credentials, query parameters, "
                "or a fragment"
            )

        self._api_key = api_key.strip() if api_key else None
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._client = client

    @property
    def name(self) -> str:
        return "abuseipdb"

    def _result(
        self,
        indicator: Indicator,
        status: EnrichmentStatus,
        *,
        result: str | None = None,
        confidence: float | None = None,
        error_code: str | None = None,
        raw: dict[str, Any] | None = None,
    ) -> EnrichmentResult:
        return EnrichmentResult(
            indicator=indicator.value,
            type=indicator.type,
            provider=self.name,
            status=status,
            result=result,
            confidence=confidence,
            source_reference=(
                "https://www.abuseipdb.com/check/"
                + quote(indicator.value, safe="")
            ),
            error_code=error_code,
            raw=raw,
        )

    async def enrich(self, indicator: Indicator) -> EnrichmentResult:
        if indicator.type not in {"ipv4", "ipv6"}:
            return self._result(
                indicator,
                EnrichmentStatus.ERROR,
                error_code="unsupported_indicator_type",
                result="AbuseIPDB supports IP address lookups only.",
            )

        if not self._api_key:
            return self._result(
                indicator,
                EnrichmentStatus.UNAVAILABLE,
                error_code="missing_api_key",
                result="AbuseIPDB API key is not configured.",
            )

        headers = {
            "Accept": "application/json",
            "Key": self._api_key,
        }
        params = {
            "ipAddress": indicator.value,
            "maxAgeInDays": 90,
        }
        url = f"{self._base_url}/check"

        try:
            if self._client is not None:
                response = await self._client.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=self._timeout_seconds,
                )
            else:
                async with httpx.AsyncClient(
                    timeout=self._timeout_seconds
                ) as client:
                    response = await client.get(
                        url,
                        headers=headers,
                        params=params,
                    )
        except httpx.TimeoutException:
            return self._result(
                indicator,
                EnrichmentStatus.UNAVAILABLE,
                error_code="request_timeout",
                result="AbuseIPDB request timed out.",
            )
        except httpx.RequestError:
            return self._result(
                indicator,
                EnrichmentStatus.UNAVAILABLE,
                error_code="network_error",
                result="AbuseIPDB could not be reached.",
            )

        if response.status_code == 429:
            return self._result(
                indicator,
                EnrichmentStatus.UNAVAILABLE,
                error_code="rate_limited",
                result="AbuseIPDB rate limit reached.",
            )

        if response.status_code in {401, 403}:
            return self._result(
                indicator,
                EnrichmentStatus.ERROR,
                error_code="authentication_failed",
                result="AbuseIPDB rejected the API credentials or request.",
            )

        if response.status_code >= 500:
            return self._result(
                indicator,
                EnrichmentStatus.UNAVAILABLE,
                error_code="provider_server_error",
                result="AbuseIPDB returned a server error.",
            )

        if response.status_code != 200:
            return self._result(
                indicator,
                EnrichmentStatus.ERROR,
                error_code="unexpected_http_status",
                result=f"AbuseIPDB returned HTTP {response.status_code}.",
            )

        try:
            payload = response.json()
        except ValueError:
            return self._result(
                indicator,
                EnrichmentStatus.ERROR,
                error_code="invalid_json",
                result="AbuseIPDB returned invalid JSON.",
            )

        if not isinstance(payload, dict):
            return self._result(
                indicator,
                EnrichmentStatus.ERROR,
                error_code="invalid_response",
                result="AbuseIPDB response must be a JSON object.",
            )

        data = payload.get("data")
        if not isinstance(data, dict):
            return self._result(
                indicator,
                EnrichmentStatus.ERROR,
                error_code="invalid_response",
                result="AbuseIPDB response is missing its data object.",
            )

        score = data.get("abuseConfidenceScore")
        reports = data.get("totalReports")
        returned_ip = data.get("ipAddress")

        if (
            not isinstance(score, int)
            or isinstance(score, bool)
            or not 0 <= score <= 100
            or not isinstance(reports, int)
            or isinstance(reports, bool)
            or reports < 0
            or not isinstance(returned_ip, str)
            or not _same_ip_address(returned_ip, indicator.value)
        ):
            return self._result(
                indicator,
                EnrichmentStatus.ERROR,
                error_code="invalid_response",
                result=(
                    "AbuseIPDB returned missing or invalid "
                    "indicator data."
                ),
            )

        if reports == 0 and score != 0:
            return self._result(
                indicator,
                EnrichmentStatus.ERROR,
                error_code="inconsistent_response",
                result=(
                    "AbuseIPDB returned inconsistent report and "
                    "confidence-score values."
                ),
            )

        if reports == 0:
            return self._result(
                indicator,
                EnrichmentStatus.NOT_FOUND,
                confidence=0.0,
                result=(
                    "No reports were returned for this IP within "
                    "the requested lookup window. This does not "
                    "establish that the IP is benign."
                ),
                raw=data,
            )

        return self._result(
            indicator,
            EnrichmentStatus.FOUND,
            confidence=score / 100.0,
            result=(
                f"AbuseIPDB reports {reports} reports and an "
                f"abuse-confidence score of {score}/100."
            ),
            raw=data,
        )

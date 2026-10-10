

import ipaddress

import asyncio

import httpx
import pytest

from enrichment.abuseipdb import AbuseIPDBProvider
from enrichment.models import EnrichmentStatus, Indicator


IP = "8.8.8.8"


def make_provider(handler, api_key="test-key"):
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler)
    )
    provider = AbuseIPDBProvider(
        api_key=api_key,
        client=client,
    )
    return provider, client


def test_successful_lookup():
    async def run():
        def handler(request):
            assert request.url.path.endswith("/check")
            assert request.headers["Key"] == "test-key"
            assert request.url.params["ipAddress"] == IP
            return httpx.Response(
                200,
                json={
                    "data": {
                        "ipAddress": IP,
                        "abuseConfidenceScore": 75,
                        "totalReports": 12,
                    }
                },
            )

        provider, client = make_provider(handler)
        try:
            result = await provider.enrich(
                Indicator(value=IP, type="ipv4")
            )
            assert result.status == EnrichmentStatus.FOUND
            assert result.confidence == 0.75
            assert result.raw["totalReports"] == 12
        finally:
            await client.aclose()

    asyncio.run(run())


def test_no_reports_is_not_proof_of_benign_activity():
    async def run():
        def handler(request):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "ipAddress": IP,
                        "abuseConfidenceScore": 0,
                        "totalReports": 0,
                    }
                },
            )

        provider, client = make_provider(handler)
        try:
            result = await provider.enrich(
                Indicator(value=IP, type="ipv4")
            )
            assert result.status == EnrichmentStatus.NOT_FOUND
            assert "does not establish" in result.result
        finally:
            await client.aclose()

    asyncio.run(run())


def test_missing_api_key_does_not_make_request():
    async def run():
        def handler(request):
            pytest.fail("Request should not be sent without an API key")

        provider, client = make_provider(handler, api_key=None)
        try:
            result = await provider.enrich(
                Indicator(value=IP, type="ipv4")
            )
            assert result.status == EnrichmentStatus.UNAVAILABLE
            assert result.error_code == "missing_api_key"
        finally:
            await client.aclose()

    asyncio.run(run())


def test_rate_limit():
    async def run():
        def handler(request):
            return httpx.Response(429, json={"errors": ["rate limited"]})

        provider, client = make_provider(handler)
        try:
            result = await provider.enrich(
                Indicator(value=IP, type="ipv4")
            )
            assert result.status == EnrichmentStatus.UNAVAILABLE
            assert result.error_code == "rate_limited"
        finally:
            await client.aclose()

    asyncio.run(run())


def test_authentication_failure():
    async def run():
        def handler(request):
            return httpx.Response(401, json={"errors": ["unauthorized"]})

        provider, client = make_provider(handler)
        try:
            result = await provider.enrich(
                Indicator(value=IP, type="ipv4")
            )
            assert result.status == EnrichmentStatus.ERROR
            assert result.error_code == "authentication_failed"
        finally:
            await client.aclose()

    asyncio.run(run())


def test_malformed_response():
    async def run():
        def handler(request):
            return httpx.Response(200, json={"data": {"ipAddress": IP}})

        provider, client = make_provider(handler)
        try:
            result = await provider.enrich(
                Indicator(value=IP, type="ipv4")
            )
            assert result.status == EnrichmentStatus.ERROR
            assert result.error_code == "invalid_response"
        finally:
            await client.aclose()

    asyncio.run(run())


def test_mismatched_returned_ip():
    async def run():
        def handler(request):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "ipAddress": "1.1.1.1",
                        "abuseConfidenceScore": 10,
                        "totalReports": 1,
                    }
                },
            )

        provider, client = make_provider(handler)
        try:
            result = await provider.enrich(
                Indicator(value=IP, type="ipv4")
            )
            assert result.status == EnrichmentStatus.ERROR
            assert result.error_code == "invalid_response"
        finally:
            await client.aclose()

    asyncio.run(run())


def test_network_error():
    async def run():
        def handler(request):
            raise httpx.ConnectError("simulated connection failure")

        provider, client = make_provider(handler)
        try:
            result = await provider.enrich(
                Indicator(value=IP, type="ipv4")
            )
            assert result.status == EnrichmentStatus.UNAVAILABLE
            assert result.error_code == "network_error"
        finally:
            await client.aclose()

    asyncio.run(run())


def test_unsupported_indicator_type():
    async def run():
        def handler(request):
            pytest.fail("Unsupported indicator must not trigger a request")

        provider, client = make_provider(handler)
        try:
            result = await provider.enrich(
                Indicator(value="example.com", type="domain")
            )
            assert result.status == EnrichmentStatus.ERROR
            assert result.error_code == "unsupported_indicator_type"
        finally:
            await client.aclose()

    asyncio.run(run())

def test_timeout():
    async def run():
        def handler(request):
            raise httpx.ReadTimeout(
                "simulated timeout",
                request=request,
            )

        provider, client = make_provider(handler)
        try:
            result = await provider.enrich(
                Indicator(value=IP, type="ipv4")
            )
            assert result.status == EnrichmentStatus.UNAVAILABLE
            assert result.error_code == "request_timeout"
        finally:
            await client.aclose()

    asyncio.run(run())


def test_provider_server_error():
    async def run():
        def handler(request):
            return httpx.Response(503, json={"error": "unavailable"})

        provider, client = make_provider(handler)
        try:
            result = await provider.enrich(
                Indicator(value=IP, type="ipv4")
            )
            assert result.status == EnrichmentStatus.UNAVAILABLE
            assert result.error_code == "provider_server_error"
        finally:
            await client.aclose()

    asyncio.run(run())


def test_invalid_json():
    async def run():
        def handler(request):
            return httpx.Response(
                200,
                content=b"not valid JSON",
                headers={"Content-Type": "application/json"},
            )

        provider, client = make_provider(handler)
        try:
            result = await provider.enrich(
                Indicator(value=IP, type="ipv4")
            )
            assert result.status == EnrichmentStatus.ERROR
            assert result.error_code == "invalid_json"
        finally:
            await client.aclose()

    asyncio.run(run())


def test_out_of_range_confidence_score():
    async def run():
        def handler(request):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "ipAddress": IP,
                        "abuseConfidenceScore": 101,
                        "totalReports": 1,
                    }
                },
            )

        provider, client = make_provider(handler)
        try:
            result = await provider.enrich(
                Indicator(value=IP, type="ipv4")
            )
            assert result.status == EnrichmentStatus.ERROR
            assert result.error_code == "invalid_response"
        finally:
            await client.aclose()

    asyncio.run(run())

def test_rejects_http_base_url():
    try:
        AbuseIPDBProvider(
            api_key="test-key",
            base_url="http://example.test/api/v2",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("HTTP base URL should be rejected")


def test_rejects_embedded_credentials():
    try:
        AbuseIPDBProvider(
            api_key="test-key",
            base_url="https://user:password@example.test/api/v2",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Embedded credentials should be rejected")


def test_rejects_query_parameters():
    try:
        AbuseIPDBProvider(
            api_key="test-key",
            base_url="https://example.test/api/v2?token=secret",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Query parameters should be rejected")

def test_rejects_zero_reports_with_nonzero_score():
    async def run_test():
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "ipAddress": "8.8.8.8",
                        "abuseConfidenceScore": 25,
                        "totalReports": 0,
                    }
                },
            )

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as client:
            provider = AbuseIPDBProvider(
                api_key="test-key",
                client=client,
            )
            indicator = Indicator(value="8.8.8.8", type="ipv4")
            result = await provider.enrich(indicator)

            assert result.status == EnrichmentStatus.ERROR
            assert result.error_code == "inconsistent_response"

    asyncio.run(run_test())

def test_ipv6_equivalent_representation():
    async def run():
        submitted_ip = "2001:db8::1"
        returned_ip = "2001:0db8:0000:0000:0000:0000:0000:0001"

        def handler(request):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "ipAddress": returned_ip,
                        "abuseConfidenceScore": 10,
                        "totalReports": 1,
                    }
                },
            )

        provider, client = make_provider(handler)
        try:
            result = await provider.enrich(
                Indicator(value=submitted_ip, type="ipv6")
            )

            assert result.status == EnrichmentStatus.FOUND
        finally:
            await client.aclose()

    asyncio.run(run())
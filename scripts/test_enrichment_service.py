import asyncio
from datetime import datetime, timezone

from enrichment.base import ThreatIntelProvider
from enrichment.models import (
    EnrichmentResult,
    EnrichmentStatus,
    Indicator,
)
from enrichment.service import (
    MAX_SKIPPED_INDICATOR_LENGTH,
    enrich_correlation,
)
from investigation.correlation import (
    CorrelatedEvidence,
    CorrelationResult,
)
from investigation.relevance import EvidenceRelevance
from normalization.schemas import (
    EventEntities,
    EventSource,
    SOCEvent,
)


TEST_TIME = datetime(2026, 10, 9, 0, 0, tzinfo=timezone.utc)


def make_event(
    event_id: str,
    *,
    ips: list[str] | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
) -> SOCEvent:
    return SOCEvent(
        event_id=event_id,
        timestamp=TEST_TIME,
        source=EventSource.MANUAL,
        event_type="test.event",
        ingestion_timestamp=TEST_TIME,
        source_ip=source_ip,
        destination_ip=destination_ip,
        entities=EventEntities(ips=ips or []),
        raw_event={"test_event": event_id},
    )


def make_correlation(
    alert: SOCEvent,
    related_events: list[SOCEvent] | None = None,
) -> CorrelationResult:
    related_events = related_events or []

    evidence = [
        CorrelatedEvidence(
            event=event,
            relevance=EvidenceRelevance(
                score=40,
                category="medium",
                reasons=["test evidence"],
            ),
        )
        for event in related_events
    ]

    return CorrelationResult(
        alert=alert,
        related_events=related_events,
        evidence=evidence,
        window_start=TEST_TIME.isoformat(),
        window_end=TEST_TIME.isoformat(),
        returned_count=len(related_events),
    )



class FakeProvider(ThreatIntelProvider):
    """Offline provider for deterministic service tests."""

    def __init__(
        self,
        statuses: dict[str, EnrichmentStatus] | None = None,
        fail_on: set[str] | None = None,
        response_overrides: dict[str, object] | None = None,
        provider_name: str = "fake-provider",
        name_error: bool = False,
    ) -> None:
        self.statuses = statuses or {}
        self.fail_on = fail_on or set()
        self.response_overrides = response_overrides or {}
        self.provider_name = provider_name
        self.name_error = name_error
        self.calls: list[Indicator] = []

    @property
    def name(self) -> str:
        if self.name_error:
            raise RuntimeError("Simulated provider identity failure")
        return self.provider_name

    async def enrich(self, indicator: Indicator) -> EnrichmentResult:
        self.calls.append(indicator)

        if indicator.value in self.fail_on:
            raise RuntimeError("Simulated provider failure")

        if indicator.value in self.response_overrides:
            return self.response_overrides[indicator.value]

        status = self.statuses.get(
            indicator.value,
            EnrichmentStatus.FOUND,
        )

        return EnrichmentResult(
            indicator=indicator.value,
            type=indicator.type,
            provider=self.name,
            status=status,
            result=f"Mock result: {status.value}",
            confidence=(
                0.75 if status == EnrichmentStatus.FOUND else None
            ),
        )


def test_deduplicates_ips_across_alert_and_related_events():
    async def run_test():
        alert = make_event(
            "alert-1",
            ips=["8.8.8.8", "1.1.1.1"],
        )
        related = make_event(
            "event-2",
            ips=["8.8.8.8"],
            destination_ip="1.1.1.1",
        )
        provider = FakeProvider()

        result = await enrich_correlation(
            make_correlation(alert, [related]),
            provider,
        )

        assert [item.value for item in provider.calls] == [
            "8.8.8.8",
            "1.1.1.1",
        ]
        assert len(result.results) == 2
        assert result.skipped == []

    asyncio.run(run_test())


def test_skips_non_global_and_invalid_ip_candidates():
    async def run_test():
        alert = make_event(
            "alert-1",
            ips=[
                "10.0.0.1",
                "127.0.0.1",
                "not-an-ip",
            ],
        )
        provider = FakeProvider()

        result = await enrich_correlation(
            make_correlation(alert),
            provider,
        )

        assert provider.calls == []
        assert result.results == []
        assert len(result.skipped) == 3

        reasons = {item.reason for item in result.skipped}
        assert "invalid_ip_address" in reasons
        assert (
            "non_global_ip_not_sent_to_external_provider"
            in reasons
        )

    asyncio.run(run_test())


def test_provider_exception_does_not_stop_later_lookups():
    async def run_test():
        alert = make_event(
            "alert-1",
            ips=["8.8.8.8", "1.1.1.1"],
        )
        provider = FakeProvider(fail_on={"8.8.8.8"})

        result = await enrich_correlation(
            make_correlation(alert),
            provider,
        )

        assert len(provider.calls) == 2
        assert len(result.results) == 2

        first, second = result.results

        assert first.indicator == "8.8.8.8"
        assert first.status == EnrichmentStatus.ERROR
        assert first.error_code == "provider_exception"

        assert second.indicator == "1.1.1.1"
        assert second.status == EnrichmentStatus.FOUND

    asyncio.run(run_test())


def test_distinguishes_not_found_from_unavailable():
    async def run_test():
        alert = make_event(
            "alert-1",
            ips=["8.8.8.8", "1.1.1.1"],
        )
        provider = FakeProvider(
            statuses={
                "8.8.8.8": EnrichmentStatus.NOT_FOUND,
                "1.1.1.1": EnrichmentStatus.UNAVAILABLE,
            }
        )

        result = await enrich_correlation(
            make_correlation(alert),
            provider,
        )

        statuses = {
            item.indicator: item.status
            for item in result.results
        }

        assert statuses["8.8.8.8"] == EnrichmentStatus.NOT_FOUND
        assert statuses["1.1.1.1"] == EnrichmentStatus.UNAVAILABLE

    asyncio.run(run_test())


def test_enrichment_does_not_modify_correlation_evidence():
    async def run_test():
        alert = make_event(
            "alert-1",
            ips=["8.8.8.8"],
        )
        related = make_event(
            "event-2",
            ips=["1.1.1.1"],
        )
        correlation = make_correlation(alert, [related])

        before = correlation.model_dump(mode="json")
        provider = FakeProvider()

        await enrich_correlation(correlation, provider)

        after = correlation.model_dump(mode="json")

        assert after == before

    asyncio.run(run_test())


def test_rejects_response_for_wrong_indicator():
    async def run_test():
        alert = make_event("alert-1", ips=["8.8.8.8", "1.1.1.1"])
        wrong_response = EnrichmentResult(
            indicator="9.9.9.9",
            type="ipv4",
            provider="fake-provider",
            status=EnrichmentStatus.FOUND,
            result="Mock result",
            confidence=0.9,
        )
        provider = FakeProvider(
            response_overrides={"8.8.8.8": wrong_response}
        )

        result = await enrich_correlation(make_correlation(alert), provider)

        assert result.results[0].indicator == "8.8.8.8"
        assert result.results[0].status == EnrichmentStatus.ERROR
        assert result.results[0].error_code == "provider_response_mismatch"
        assert result.results[1].indicator == "1.1.1.1"
        assert result.results[1].status == EnrichmentStatus.FOUND

    asyncio.run(run_test())


def test_rejects_response_from_wrong_provider():
    async def run_test():
        alert = make_event("alert-1", ips=["8.8.8.8"])
        wrong_response = EnrichmentResult(
            indicator="8.8.8.8",
            type="ipv4",
            provider="different-provider",
            status=EnrichmentStatus.FOUND,
            result="Mock result",
            confidence=0.9,
        )
        provider = FakeProvider(
            response_overrides={"8.8.8.8": wrong_response}
        )

        result = await enrich_correlation(make_correlation(alert), provider)

        assert len(result.results) == 1
        assert result.results[0].status == EnrichmentStatus.ERROR
        assert result.results[0].error_code == "provider_response_mismatch"

    asyncio.run(run_test())


def test_rejects_response_with_wrong_indicator_type():
    async def run_test():
        alert = make_event("alert-1", ips=["8.8.8.8"])
        wrong_response = EnrichmentResult(
            indicator="8.8.8.8",
            type="domain",
            provider="fake-provider",
            status=EnrichmentStatus.FOUND,
            result="Mock result",
            confidence=0.9,
        )
        provider = FakeProvider(
            response_overrides={"8.8.8.8": wrong_response}
        )

        result = await enrich_correlation(make_correlation(alert), provider)

        assert result.results[0].status == EnrichmentStatus.ERROR
        assert result.results[0].error_code == "provider_response_mismatch"

    asyncio.run(run_test())


def test_rejects_non_enrichment_result_response():
    async def run_test():
        alert = make_event("alert-1", ips=["8.8.8.8", "1.1.1.1"])
        provider = FakeProvider(
            response_overrides={"8.8.8.8": {"status": "FOUND"}}
        )

        result = await enrich_correlation(make_correlation(alert), provider)

        assert result.results[0].status == EnrichmentStatus.ERROR
        assert result.results[0].error_code == "invalid_provider_response"
        assert result.results[1].status == EnrichmentStatus.FOUND

    asyncio.run(run_test())


def test_invalid_provider_identity_does_not_abort_enrichment():
    async def run_test():
        alert = make_event("alert-1", ips=["8.8.8.8"])
        provider = FakeProvider(name_error=True)

        result = await enrich_correlation(make_correlation(alert), provider)

        assert result.provider == "unknown_provider"
        assert len(result.results) == 1
        assert result.results[0].status == EnrichmentStatus.ERROR
        assert result.results[0].error_code == "provider_identity_unavailable"
        assert provider.calls == []

    asyncio.run(run_test())


def test_oversized_ip_candidate_is_skipped_without_provider_lookup():
    async def run_test():
        oversized_value = "A" * 1000
        alert = make_event("oversized-ip", ips=[oversized_value])
        provider = FakeProvider()

        result = await enrich_correlation(
            make_correlation(alert),
            provider,
        )

        assert len(result.skipped) == 1
        skipped = result.skipped[0]
        assert skipped.reason == "candidate_too_long"
        assert len(skipped.indicator) <= MAX_SKIPPED_INDICATOR_LENGTH
        assert skipped.indicator == "oversized candidate (1000 characters)"
        assert provider.calls == []
        assert result.results == []

    asyncio.run(run_test())

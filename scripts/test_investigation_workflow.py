
import asyncio
from datetime import datetime, timezone

from enrichment.models import EnrichmentResult, EnrichmentStatus
from investigation.correlation import (
    CorrelatedEvidence,
    CorrelationResult,
)
from investigation.relevance import EvidenceRelevance
from investigation.workflow import run_investigation
from normalization.schemas import (
    EventEntities,
    EventSource,
    SOCEvent,
)
from scripts.test_enrichment_service import FakeProvider


TEST_TIME = datetime(2026, 10, 9, 0, 0, tzinfo=timezone.utc)


def make_event(event_id: str, ips: list[str]) -> SOCEvent:
    return SOCEvent(
        event_id=event_id,
        timestamp=TEST_TIME,
        source=EventSource.MANUAL,
        event_type="test.event",
        ingestion_timestamp=TEST_TIME,
        entities=EventEntities(ips=ips),
        raw_event={"event_id": event_id},
    )


def make_correlation(alert: SOCEvent) -> CorrelationResult:
    related = make_event("related-1", ["8.8.8.8"])

    evidence = [
        CorrelatedEvidence(
            event=related,
            relevance=EvidenceRelevance(
                score=45,
                category="medium",
                reasons=["matched ip"],
            ),
        )
    ]

    return CorrelationResult(
        alert=alert,
        related_events=[related],
        evidence=evidence,
        window_start=TEST_TIME.isoformat(),
        window_end=TEST_TIME.isoformat(),
        returned_count=1,
    )


def test_workflow_without_provider_skips_enrichment(monkeypatch):
    async def run_test():
        alert = make_event("alert-1", ["8.8.8.8"])
        correlation = make_correlation(alert)

        def fake_correlate_event(*args, **kwargs):
            return correlation

        monkeypatch.setattr(
            "investigation.workflow.correlate_event",
            fake_correlate_event,
        )

        result = await run_investigation(alert)

        assert result.correlation.alert.event_id == "alert-1"
        assert result.enrichment is None

    asyncio.run(run_test())


def test_workflow_runs_enrichment_when_provider_is_supplied(monkeypatch):
    async def run_test():
        alert = make_event("alert-1", ["8.8.8.8"])
        correlation = make_correlation(alert)
        provider = FakeProvider()

        def fake_correlate_event(*args, **kwargs):
            return correlation

        monkeypatch.setattr(
            "investigation.workflow.correlate_event",
            fake_correlate_event,
        )

        result = await run_investigation(
            alert,
            provider=provider,
        )

        assert result.correlation.alert.event_id == "alert-1"
        assert result.enrichment is not None
        assert len(result.enrichment.results) == 1
        assert result.enrichment.results[0].status == EnrichmentStatus.FOUND

    asyncio.run(run_test())


def test_workflow_preserves_correlation_evidence(monkeypatch):
    async def run_test():
        alert = make_event("alert-1", ["8.8.8.8"])
        correlation = make_correlation(alert)
        before = correlation.model_dump(mode="json")

        def fake_correlate_event(*args, **kwargs):
            return correlation

        monkeypatch.setattr(
            "investigation.workflow.correlate_event",
            fake_correlate_event,
        )

        await run_investigation(
            alert,
            provider=FakeProvider(),
        )

        assert correlation.model_dump(mode="json") == before

    asyncio.run(run_test())


def test_workflow_preserves_correlation_when_provider_is_unavailable(monkeypatch):
    alert = make_event("alert-1", ["8.8.8.8"])
    correlation = make_correlation(alert)

    class UnavailableProvider:
        name = "test-provider"

        async def enrich(self, indicator):
            from enrichment.models import EnrichmentResult, EnrichmentStatus

            return EnrichmentResult(
                indicator=indicator.value,
                type=indicator.type,
                provider=self.name,
                status=EnrichmentStatus.UNAVAILABLE,
                result="Threat intelligence is unavailable.",
                error_code="missing_api_key",
            )

    def fake_correlate_event(*args, **kwargs):
        return correlation

    monkeypatch.setattr(
        "investigation.workflow.correlate_event",
        fake_correlate_event,
    )

    result = asyncio.run(
        run_investigation(alert, provider=UnavailableProvider())
    )

    assert result.correlation.model_dump(mode="json") == (
        correlation.model_dump(mode="json")
    )
    assert result.enrichment is not None
    assert result.enrichment.provider == "test-provider"
    assert len(result.enrichment.results) == 1
    assert result.enrichment.results[0].status == EnrichmentStatus.UNAVAILABLE
    assert result.enrichment.results[0].error_code == "missing_api_key"

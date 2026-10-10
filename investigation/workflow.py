
import asyncio

from pydantic import BaseModel, ConfigDict

from collectors.elastic import ElasticConnector
from enrichment.base import ThreatIntelProvider
from enrichment.service import (
    EnrichmentBatchResult,
    enrich_correlation,
)
from investigation.correlation import (
    CorrelationResult,
    correlate_event,
)
from normalization.schemas import SOCEvent


class InvestigationResult(BaseModel):
    """Combined investigation output with optional threat intelligence."""

    model_config = ConfigDict(extra="forbid")

    correlation: CorrelationResult
    enrichment: EnrichmentBatchResult | None = None


async def run_investigation(
    event: SOCEvent,
    *,
    connector: ElasticConnector | None = None,
    provider: ThreatIntelProvider | None = None,
    window_minutes: int = 30,
    max_events: int = 1000,
) -> InvestigationResult:
    """
    Correlate an event and optionally enrich its IP indicators.

    Correlation runs in a worker thread because the Elastic connector
    is synchronous. Enrichment is optional: without an explicitly
    supplied provider, no threat-intelligence lookups are attempted.
    """

    correlation = await asyncio.to_thread(
        correlate_event,
        event,
        connector=connector,
        window_minutes=window_minutes,
        max_events=max_events,
    )

    enrichment = None

    if provider is not None:
        enrichment = await enrich_correlation(
            correlation,
            provider,
        )

    return InvestigationResult(
        correlation=correlation,
        enrichment=enrichment,
    )

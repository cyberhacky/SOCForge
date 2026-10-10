from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from enrichment.models import EnrichmentStatus, IndicatorType
from enrichment.service import (
    EnrichmentBatchResult,
    SkippedIndicator,
)
from investigation.correlation import (
    CorrelationResult,
    CorrelatedEvidence,
)
from investigation.relevance import EvidenceRelevance
from investigation.workflow import InvestigationResult
from normalization.schemas import (
    EventSeverity,
    EventSource,
    SOCEvent,
)


class PublicEventSummary(BaseModel):
    """Explicitly allowlisted event fields for API responses."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    timestamp: datetime
    source: EventSource
    event_type: str
    severity: EventSeverity
    host: str | None = None
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    process_name: str | None = None


class PublicEvidence(BaseModel):
    """An allowlisted event summary with relevance metadata."""

    model_config = ConfigDict(extra="forbid")

    event: PublicEventSummary
    relevance: EvidenceRelevance


class PublicCorrelationSummary(BaseModel):
    """Correlation results approved for API consumers."""

    model_config = ConfigDict(extra="forbid")

    alert: PublicEventSummary
    related_events: list[PublicEventSummary] = Field(
        default_factory=list
    )
    evidence: list[PublicEvidence] = Field(default_factory=list)
    window_start: str
    window_end: str
    matched_entities: dict[str, list[str]] = Field(
        default_factory=dict
    )
    returned_count: int = 0
    truncated: bool = False


class PublicEnrichmentResult(BaseModel):
    """Threat-intelligence result without its raw provider payload."""

    model_config = ConfigDict(extra="forbid")

    indicator: str
    type: IndicatorType
    provider: str
    status: EnrichmentStatus
    result: str | None = None
    confidence: float | None = None
    timestamp: datetime
    source_reference: str | None = None
    error_code: str | None = None


class PublicEnrichmentBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    results: list[PublicEnrichmentResult] = Field(
        default_factory=list
    )
    skipped: list[SkippedIndicator] = Field(
        default_factory=list
    )


class PublicInvestigationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    correlation: PublicCorrelationSummary
    enrichment: PublicEnrichmentBatch | None = None


def _public_event(event: SOCEvent) -> PublicEventSummary:
    """Copy only explicitly approved fields from an internal event."""

    return PublicEventSummary(
        event_id=event.event_id,
        timestamp=event.timestamp,
        source=event.source,
        event_type=event.event_type,
        severity=event.severity,
        host=event.host,
        username=event.username,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        process_name=event.process_name,
    )


def _public_evidence(
    item: CorrelatedEvidence,
) -> PublicEvidence:
    return PublicEvidence(
        event=_public_event(item.event),
        relevance=item.relevance,
    )


def to_public_investigation(
    result: InvestigationResult,
) -> PublicInvestigationResult:
    """Convert internal investigation results to the public API contract."""

    correlation: CorrelationResult = result.correlation

    public_correlation = PublicCorrelationSummary(
        alert=_public_event(correlation.alert),
        related_events=[
            _public_event(event)
            for event in correlation.related_events
        ],
        evidence=[
            _public_evidence(item)
            for item in correlation.evidence
        ],
        window_start=correlation.window_start,
        window_end=correlation.window_end,
        matched_entities=correlation.matched_entities,
        returned_count=correlation.returned_count,
        truncated=correlation.truncated,
    )

    public_enrichment = None

    if result.enrichment is not None:
        batch: EnrichmentBatchResult = result.enrichment

        public_enrichment = PublicEnrichmentBatch(
            provider=batch.provider,
            results=[
                PublicEnrichmentResult(
                    indicator=item.indicator,
                    type=item.type,
                    provider=item.provider,
                    status=item.status,
                    result=item.result,
                    confidence=item.confidence,
                    timestamp=item.timestamp,
                    source_reference=item.source_reference,
                    error_code=item.error_code,
                )
                for item in batch.results
            ],
            skipped=batch.skipped,
        )

    return PublicInvestigationResult(
        correlation=public_correlation,
        enrichment=public_enrichment,
    )
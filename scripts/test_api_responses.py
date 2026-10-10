from datetime import datetime, timezone

from enrichment.models import EnrichmentResult, EnrichmentStatus
from enrichment.service import EnrichmentBatchResult
from investigation.correlation import (
    CorrelationResult,
    CorrelatedEvidence,
)
from investigation.relevance import EvidenceRelevance
from investigation.workflow import InvestigationResult
from normalization.schemas import SOCEvent
from scripts.test_enrichment_service import make_event
from api.responses import to_public_investigation


TEST_TIME = datetime(2026, 10, 9, 0, 0, tzinfo=timezone.utc)


def _sensitive_event(event_id: str) -> SOCEvent:
    event = make_event(event_id, ips=["8.8.8.8"])

    return event.model_copy(
        update={
            "message": "DO_NOT_LEAK_PRIVATE_MESSAGE",
            "process_command_line": (
                "DO_NOT_LEAK_PRIVATE_COMMAND_LINE"
            ),
            "source_index": "DO_NOT_LEAK_SOURCE_INDEX",
            "source_document_id": "DO_NOT_LEAK_DOCUMENT_ID",
            "raw_event": {
                "marker": "DO_NOT_LEAK_RAW_EVENT",
            },
        }
    )


def _internal_result() -> InvestigationResult:
    alert = _sensitive_event("api-redaction-alert")
    related = _sensitive_event("api-redaction-related")

    relevance = EvidenceRelevance(
        score=75,
        category="high",
        matched_entities={"ip": ["8.8.8.8"]},
        reasons=["matched ip: 8.8.8.8"],
    )

    correlation = CorrelationResult(
        alert=alert,
        related_events=[related],
        evidence=[
            CorrelatedEvidence(
                event=related,
                relevance=relevance,
            )
        ],
        window_start=TEST_TIME.isoformat(),
        window_end=TEST_TIME.isoformat(),
        matched_entities={"ips": ["8.8.8.8"]},
        returned_count=1,
        truncated=False,
    )

    enrichment = EnrichmentBatchResult(
        provider="abuseipdb",
        results=[
            EnrichmentResult(
                indicator="8.8.8.8",
                type="ipv4",
                provider="abuseipdb",
                status=EnrichmentStatus.FOUND,
                result="Threat intelligence match",
                confidence=0.8,
                timestamp=TEST_TIME,
                raw={
                    "marker": "DO_NOT_LEAK_RAW_TI_RESPONSE",
                },
            )
        ],
    )

    return InvestigationResult(
        correlation=correlation,
        enrichment=enrichment,
    )


def test_public_response_excludes_sensitive_event_fields():
    public_result = to_public_investigation(_internal_result())
    serialized = public_result.model_dump_json()

    for marker in (
        "DO_NOT_LEAK_PRIVATE_MESSAGE",
        "DO_NOT_LEAK_PRIVATE_COMMAND_LINE",
        "DO_NOT_LEAK_SOURCE_INDEX",
        "DO_NOT_LEAK_DOCUMENT_ID",
        "DO_NOT_LEAK_RAW_EVENT",
        "DO_NOT_LEAK_RAW_TI_RESPONSE",
    ):
        assert marker not in serialized

    assert "api-redaction-alert" in serialized
    assert "api-redaction-related" in serialized


def test_public_response_preserves_investigation_evidence():
    public_result = to_public_investigation(_internal_result())

    assert public_result.correlation.returned_count == 1
    assert public_result.correlation.truncated is False

    assert len(public_result.correlation.related_events) == 1
    assert len(public_result.correlation.evidence) == 1

    evidence = public_result.correlation.evidence[0]
    assert evidence.relevance.score == 75
    assert evidence.relevance.category == "high"
    assert evidence.relevance.matched_entities == {
        "ip": ["8.8.8.8"]
    }

    assert public_result.enrichment is not None
    assert public_result.enrichment.results[0].status == (
        EnrichmentStatus.FOUND
    )
    assert public_result.enrichment.results[0].confidence == 0.8


def test_public_response_preserves_absence_of_enrichment():
    internal_result = _internal_result().model_copy(
        update={"enrichment": None}
    )

    public_result = to_public_investigation(internal_result)

    assert public_result.enrichment is None

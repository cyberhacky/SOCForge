
from abc import ABC, abstractmethod

from enrichment.models import EnrichmentResult, Indicator


class ThreatIntelProvider(ABC):
    """Interface implemented by each threat-intelligence provider."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the stable provider identifier."""
        raise NotImplementedError

    @abstractmethod
    async def enrich(self, indicator: Indicator) -> EnrichmentResult:
        """Enrich one validated indicator and return a structured result."""
        raise NotImplementedError

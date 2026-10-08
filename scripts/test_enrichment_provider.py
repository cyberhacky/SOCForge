
import asyncio

from enrichment.base import ThreatIntelProvider
from enrichment.models import (
    EnrichmentResult,
    EnrichmentStatus,
    Indicator,
)


class TestProvider(ThreatIntelProvider):
    @property
    def name(self) -> str:
        return "test-provider"

    async def enrich(self, indicator: Indicator) -> EnrichmentResult:
        return EnrichmentResult(
            indicator=indicator.value,
            type=indicator.type,
            provider=self.name,
            status=EnrichmentStatus.NOT_FOUND,
        )


async def main() -> None:
    provider = TestProvider()
    indicator = Indicator(value="185.0.0.1", type="ipv4")

    result = await provider.enrich(indicator)

    assert provider.name == "test-provider"
    assert result.indicator == indicator.value
    assert result.provider == provider.name
    assert result.status == EnrichmentStatus.NOT_FOUND

    print("Provider interface: PASS")
    print("Indicator preserved: PASS")
    print("Result status: PASS")


if __name__ == "__main__":
    asyncio.run(main())

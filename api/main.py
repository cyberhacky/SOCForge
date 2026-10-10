import asyncio
import logging

from fastapi import FastAPI, HTTPException

from api.config import settings
from api.responses import (
    PublicInvestigationResult,
    to_public_investigation,
)
from collectors.elastic import ElasticConnector
from enrichment.abuseipdb import AbuseIPDBProvider
from investigation.workflow import run_investigation
from normalization.schemas import SOCEvent


logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Evidence-first security operations workbench",
)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": settings.app_name.lower().replace(" ", "-"),
        "version": settings.app_version,
    }


@app.post(
    "/investigations",
    response_model=PublicInvestigationResult,
)
async def create_investigation(
    event: SOCEvent,
) -> PublicInvestigationResult:
    """Investigate a normalized event and return sanitized evidence."""

    try:
        connector = ElasticConnector()
    except (ValueError, OSError):
        raise HTTPException(
            status_code=503,
            detail="Elasticsearch is not configured or unavailable.",
        ) from None

    try:
        provider = None

        api_key = settings.abuseipdb_api_key

        if api_key and api_key.strip():
            try:
                provider = AbuseIPDBProvider(
                    api_key=api_key,
                    base_url=settings.abuseipdb_base_url,
                    timeout_seconds=(
                        settings.abuseipdb_timeout_seconds
                    ),
                )
            except ValueError:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "Threat-intelligence provider "
                        "configuration is invalid."
                    ),
                ) from None

        result = await run_investigation(
            event,
            connector=connector,
            provider=provider,
        )

        return to_public_investigation(result)

    except HTTPException:
        raise
    except Exception:
        logger.exception("Investigation failed.")
        raise HTTPException(
            status_code=500,
            detail="Investigation failed.",
        ) from None
    finally:
        try:
            await asyncio.to_thread(connector.close)
        except Exception:
            logger.warning(
                "Failed to close Elasticsearch client."
            )
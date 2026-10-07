from datetime import datetime
from typing import Any

from elasticsearch import Elasticsearch

from api.config import settings


class ElasticConnector:
    """Read raw events from Elasticsearch."""

    def __init__(self) -> None:
        if not settings.elastic_ca_cert:
            raise ValueError("ELASTIC_CA_CERT is required")

        self.client = Elasticsearch(
            settings.elastic_url,
            basic_auth=(
                settings.elastic_username,
                settings.elastic_password,
            )
            if settings.elastic_username and settings.elastic_password
            else None,
            ca_certs=settings.elastic_ca_cert,
        )

    def ping(self) -> bool:
        """Verify connectivity to Elasticsearch."""
        return bool(self.client.ping())

    def search(
        self,
        *,
        index: str = "*",
        query: dict[str, Any] | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        size: int = 100,
    ) -> list[dict[str, Any]]:
        """Retrieve raw Elasticsearch events."""

        if size < 1:
            raise ValueError("size must be greater than zero")

        if size > 1000:
            raise ValueError("size must not exceed 1000")

        must: list[dict[str, Any]] = []

        if query:
            must.append(query)
        else:
            must.append({"match_all": {}})

        if start_time or end_time:
            timestamp_range: dict[str, str] = {}

            if start_time:
                timestamp_range["gte"] = start_time.isoformat()

            if end_time:
                timestamp_range["lte"] = end_time.isoformat()

            must.append(
                {
                    "range": {
                        "@timestamp": timestamp_range,
                    }
                }
            )

        response = self.client.search(
            index=index,
            query={"bool": {"must": must}},
            size=size,
            sort=[
                {
                    "@timestamp": {
                        "order": "desc",
                        "unmapped_type": "date",
                    }
                }
            ],
        )

        return [
            {
                "index": hit.get("_index"),
                "id": hit.get("_id"),
                "score": hit.get("_score"),
                "source": hit.get("_source", {}),
            }
            for hit in response["hits"]["hits"]
        ]
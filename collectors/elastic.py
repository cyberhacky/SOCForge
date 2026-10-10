from datetime import datetime
from typing import Any

from elasticsearch import Elasticsearch

from api.config import settings


class ElasticSearchResult:
    """Result of an Elasticsearch search."""

    def __init__(
        self,
        *,
        events: list[dict[str, Any]],
        truncated: bool,
    ) -> None:
        self.events = events
        self.truncated = truncated


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

    def close(self) -> None:
        """Release the Elasticsearch client's transport resources."""
        self.client.close()

    def ping(self) -> bool:
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
        """
        Search Elasticsearch and return raw hits.

        This preserves the original public search API used by the
        existing normalization and test code.
        """
        result = self.search_with_metadata(
            index=index,
            query=query,
            start_time=start_time,
            end_time=end_time,
            size=size,
        )

        return result.events

    def search_with_metadata(
        self,
        *,
        index: str = "*",
        query: dict[str, Any] | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        size: int = 100,
    ) -> ElasticSearchResult:
        """
        Search Elasticsearch and report whether the result may be truncated.

        A result is considered potentially truncated when Elasticsearch
        returns exactly the requested page size. This does not claim that
        more events exist; it tells callers that completeness has not been
        established.
        """
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
            query={
                "bool": {
                    "must": must,
                }
            },
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

        hits = [
            {
                "index": hit.get("_index"),
                "id": hit.get("_id"),
                "score": hit.get("_score"),
                "source": hit.get("_source", {}),
            }
            for hit in response["hits"]["hits"]
        ]

        return ElasticSearchResult(
            events=hits,
            truncated=len(hits) == size,
        )

    def search_all(
        self,
        *,
        index: str = "*",
        query: dict[str, Any] | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        batch_size: int = 100,
        max_events: int = 5000,
    ) -> ElasticSearchResult:
        """
        Retrieve multiple batches of Elasticsearch events.

        Uses Point-in-Time (PIT) plus search_after so pagination operates
        against a consistent view of the matching Elasticsearch data.

        The search stops when:
        - no more events are returned,
        - a final partial batch is returned, or
        - max_events is reached.

        If max_events is reached, the result is marked truncated because
        additional matching events may still exist.
        """
        if batch_size < 1:
            raise ValueError(
                "batch_size must be greater than zero"
            )

        if batch_size > 1000:
            raise ValueError(
                "batch_size must not exceed 1000"
            )

        if max_events < 1:
            raise ValueError(
                "max_events must be greater than zero"
            )

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

        pit = self.client.open_point_in_time(
            index=index,
            keep_alive="2m",
        )

        pit_id = pit["id"]

        events: list[dict[str, Any]] = []
        search_after: list[Any] | None = None

        try:
            while len(events) < max_events:
                current_size = min(
                    batch_size,
                    max_events - len(events),
                )

                response = self.client.search(
                    pit={
                        "id": pit_id,
                        "keep_alive": "2m",
                    },
                    query={
                        "bool": {
                            "must": must,
                        }
                    },
                    size=current_size,
                    sort=[
                        {
                            "@timestamp": {
                                "order": "asc",
                                "unmapped_type": "date",
                            }
                        },
                        {
                            "_shard_doc": "asc",
                        },
                    ],
                    search_after=search_after,
                )

                hits = response["hits"]["hits"]

                if not hits:
                    return ElasticSearchResult(
                        events=events,
                        truncated=False,
                    )

                for hit in hits:
                    events.append(
                        {
                            "index": hit.get("_index"),
                            "id": hit.get("_id"),
                            "score": hit.get("_score"),
                            "source": hit.get("_source", {}),
                        }
                    )

                if len(hits) < current_size:
                    return ElasticSearchResult(
                        events=events,
                        truncated=False,
                    )

                if len(events) >= max_events:
                    return ElasticSearchResult(
                        events=events[:max_events],
                        truncated=True,
                    )

                search_after = hits[-1].get("sort")

                if not search_after:
                    raise RuntimeError(
                        "Elasticsearch did not return sort values "
                        "required for pagination"
                    )

            return ElasticSearchResult(
                events=events[:max_events],
                truncated=True,
            )

        finally:
            self.client.close_point_in_time(
                id=pit_id,
            )
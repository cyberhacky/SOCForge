from unittest.mock import Mock

import pytest

from collectors.elastic import ElasticConnector, ElasticSearchResult


def make_hit(event_id: str, timestamp: str, sort_values: list) -> dict:
    return {
        "_index": "logs-test",
        "_id": event_id,
        "_score": None,
        "_source": {
            "@timestamp": timestamp,
            "event": {
                "action": "test",
            },
        },
        "sort": sort_values,
    }


@pytest.fixture
def connector() -> ElasticConnector:
    connector = ElasticConnector.__new__(ElasticConnector)
    connector.client = Mock()
    return connector


def test_search_all_combines_multiple_pages(
    connector: ElasticConnector,
) -> None:
    page_one = [
        make_hit(
            "event-1",
            "2026-10-07T10:00:00Z",
            ["2026-10-07T10:00:00Z", 1],
        ),
        make_hit(
            "event-2",
            "2026-10-07T10:01:00Z",
            ["2026-10-07T10:01:00Z", 2],
        ),
    ]

    page_two = [
        make_hit(
            "event-3",
            "2026-10-07T10:02:00Z",
            ["2026-10-07T10:02:00Z", 3],
        ),
    ]

    connector.client.open_point_in_time.return_value = {
        "id": "test-pit-id",
    }

    connector.client.search.side_effect = [
        {
            "hits": {
                "hits": page_one,
            }
        },
        {
            "hits": {
                "hits": page_two,
            }
        },
    ]

    result = connector.search_all(
        index="logs-*",
        batch_size=2,
        max_events=100,
    )

    assert [event["id"] for event in result.events] == [
        "event-1",
        "event-2",
        "event-3",
    ]

    assert result.truncated is False

    assert connector.client.open_point_in_time.call_once_with(
        index="logs-*",
        keep_alive="2m",
    )

    assert connector.client.close_point_in_time.call_once_with(
        id="test-pit-id",
    )

    assert connector.client.search.call_count == 2


def test_search_all_passes_search_after_between_pages(
    connector: ElasticConnector,
) -> None:
    page_one = [
        make_hit(
            "event-1",
            "2026-10-07T10:00:00Z",
            ["2026-10-07T10:00:00Z", 1],
        ),
        make_hit(
            "event-2",
            "2026-10-07T10:01:00Z",
            ["2026-10-07T10:01:00Z", 2],
        ),
    ]

    page_two = [
        make_hit(
            "event-3",
            "2026-10-07T10:02:00Z",
            ["2026-10-07T10:02:00Z", 3],
        ),
    ]

    connector.client.open_point_in_time.return_value = {
        "id": "test-pit-id",
    }

    connector.client.search.side_effect = [
        {"hits": {"hits": page_one}},
        {"hits": {"hits": page_two}},
    ]

    connector.search_all(
        index="logs-*",
        batch_size=2,
        max_events=100,
    )

    first_call = connector.client.search.call_args_list[0]
    second_call = connector.client.search.call_args_list[1]

    assert first_call.kwargs["search_after"] is None
    assert second_call.kwargs["search_after"] == [
        "2026-10-07T10:01:00Z",
        2,
    ]


def test_search_all_stops_on_partial_final_page(
    connector: ElasticConnector,
) -> None:
    page = [
        make_hit(
            "event-1",
            "2026-10-07T10:00:00Z",
            ["2026-10-07T10:00:00Z", 1],
        ),
    ]

    connector.client.open_point_in_time.return_value = {
        "id": "test-pit-id",
    }

    connector.client.search.return_value = {
        "hits": {
            "hits": page,
        }
    }

    result = connector.search_all(
        index="logs-*",
        batch_size=100,
        max_events=1000,
    )

    assert len(result.events) == 1
    assert result.truncated is False
    assert connector.client.search.call_count == 1


def test_search_all_marks_result_truncated_at_safety_limit(
    connector: ElasticConnector,
) -> None:
    page_one = [
        make_hit(
            "event-1",
            "2026-10-07T10:00:00Z",
            ["2026-10-07T10:00:00Z", 1],
        ),
        make_hit(
            "event-2",
            "2026-10-07T10:01:00Z",
            ["2026-10-07T10:01:00Z", 2],
        ),
    ]

    connector.client.open_point_in_time.return_value = {
        "id": "test-pit-id",
    }

    connector.client.search.return_value = {
        "hits": {
            "hits": page_one,
        }
    }

    result = connector.search_all(
        index="logs-*",
        batch_size=2,
        max_events=2,
    )

    assert len(result.events) == 2
    assert result.truncated is True
    assert connector.client.search.call_count == 1


def test_search_all_closes_pit_when_search_fails(
    connector: ElasticConnector,
) -> None:
    connector.client.open_point_in_time.return_value = {
        "id": "test-pit-id",
    }

    connector.client.search.side_effect = RuntimeError(
        "simulated Elasticsearch failure"
    )

    with pytest.raises(RuntimeError, match="simulated Elasticsearch failure"):
        connector.search_all(
            index="logs-*",
            batch_size=100,
            max_events=1000,
        )

    connector.client.close_point_in_time.assert_called_once_with(
        id="test-pit-id",
    )


def test_search_all_rejects_invalid_batch_size(
    connector: ElasticConnector,
) -> None:
    with pytest.raises(ValueError, match="batch_size"):
        connector.search_all(
            batch_size=0,
        )


def test_search_all_rejects_batch_size_above_limit(
    connector: ElasticConnector,
) -> None:
    with pytest.raises(ValueError, match="batch_size"):
        connector.search_all(
            batch_size=1001,
        )


def test_search_all_rejects_invalid_max_events(
    connector: ElasticConnector,
) -> None:
    with pytest.raises(ValueError, match="max_events"):
        connector.search_all(
            max_events=0,
        )
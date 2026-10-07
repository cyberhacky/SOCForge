from unittest.mock import MagicMock, patch

from collectors.elastic import ElasticConnector


@patch("collectors.elastic.settings")
@patch("collectors.elastic.Elasticsearch")
def test_elastic_search_returns_raw_sources(
    mock_elasticsearch: MagicMock,
    mock_settings: MagicMock,
) -> None:
    mock_settings.elastic_url = "https://localhost:9200"
    mock_settings.elastic_username = "test-user"
    mock_settings.elastic_password = "test-password"
    mock_settings.elastic_ca_cert = "test-ca.crt"

    mock_client = mock_elasticsearch.return_value

    mock_client.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_index": "test-index",
                    "_id": "event-1",
                    "_score": 1.0,
                    "_source": {
                        "@timestamp": "2026-10-07T17:04:01Z",
                        "event": {
                            "code": "5379",
                        },
                    },
                }
            ]
        }
    }

    connector = ElasticConnector()

    events = connector.search(index="*")

    assert len(events) == 1
    assert events[0]["index"] == "test-index"
    assert events[0]["id"] == "event-1"
    assert events[0]["score"] == 1.0
    assert events[0]["source"]["event"]["code"] == "5379"

    mock_client.search.assert_called_once()
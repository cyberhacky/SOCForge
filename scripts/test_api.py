
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from pydantic import SecretStr

from api import main
from investigation.workflow import InvestigationResult
from scripts.test_enrichment_service import make_correlation
from scripts.test_enrichment_service import (
    make_event as make_enrichment_event,
)


TEST_TIME = datetime(2026, 10, 9, 0, 0, tzinfo=timezone.utc)
TEST_API_KEY = "socforge-test-key"


def _auth_headers(token: str = TEST_API_KEY) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _configure_api_key(monkeypatch) -> None:
    monkeypatch.setattr(
        main.settings,
        "socforge_api_key",
        SecretStr(TEST_API_KEY),
    )


class FakeConnector:
    """Test double that records Elasticsearch client cleanup."""

    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _event_payload() -> dict:
    event = make_enrichment_event(
        "api-test-alert",
        ips=["8.8.8.8"],
    )
    return event.model_dump(mode="json")


def _investigation_result() -> InvestigationResult:
    event = make_enrichment_event(
        "api-test-alert",
        ips=["8.8.8.8"],
    )
    return InvestigationResult(
        correlation=make_correlation(event)
    )


def test_health_endpoint_remains_available():
    client = TestClient(main.app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_investigation_without_api_key_does_not_construct_provider(
    monkeypatch,
):
    _configure_api_key(monkeypatch)
    monkeypatch.setattr(main.settings, "abuseipdb_api_key", None)

    connector = FakeConnector()
    monkeypatch.setattr(
        main,
        "ElasticConnector",
        lambda: connector,
    )

    def unexpected_provider(*args, **kwargs):
        raise AssertionError("Provider must not be constructed")

    monkeypatch.setattr(
        main,
        "AbuseIPDBProvider",
        unexpected_provider,
    )

    async def fake_run_investigation(event, **kwargs):
        assert kwargs["provider"] is None
        return _investigation_result()

    monkeypatch.setattr(
        main,
        "run_investigation",
        fake_run_investigation,
    )

    client = TestClient(main.app)
    response = client.post(
        "/investigations",
        json=_event_payload(),
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    assert response.json()["enrichment"] is None
    assert connector.closed is True


def test_investigation_constructs_provider_when_key_is_configured(
    monkeypatch,
):
    _configure_api_key(monkeypatch)
    monkeypatch.setattr(
        main.settings,
        "abuseipdb_api_key",
        "test-key",
    )
    monkeypatch.setattr(
        main.settings,
        "abuseipdb_base_url",
        "https://api.abuseipdb.com/api/v2",
    )
    monkeypatch.setattr(
        main.settings,
        "abuseipdb_timeout_seconds",
        5.0,
    )

    connector = FakeConnector()
    monkeypatch.setattr(
        main,
        "ElasticConnector",
        lambda: connector,
    )

    constructed = {}

    class StubProvider:
        def __init__(self, **kwargs):
            constructed.update(kwargs)

    monkeypatch.setattr(
        main,
        "AbuseIPDBProvider",
        StubProvider,
    )

    async def fake_run_investigation(event, **kwargs):
        assert kwargs["provider"] is not None
        return _investigation_result()

    monkeypatch.setattr(
        main,
        "run_investigation",
        fake_run_investigation,
    )

    client = TestClient(main.app)
    response = client.post(
        "/investigations",
        json=_event_payload(),
        headers=_auth_headers(),
    )

    assert response.status_code == 200
    assert constructed["api_key"] == "test-key"
    assert constructed["timeout_seconds"] == 5.0
    assert "test-key" not in response.text
    assert connector.closed is True


def test_invalid_event_body_is_rejected(monkeypatch):
    _configure_api_key(monkeypatch)

    client = TestClient(main.app)
    response = client.post(
        "/investigations",
        json={"event_id": "", "source": "manual"},
        headers=_auth_headers(),
    )

    assert response.status_code == 422


def test_workflow_failure_does_not_expose_exception_details(
    monkeypatch,
):
    _configure_api_key(monkeypatch)

    connector = FakeConnector()
    monkeypatch.setattr(
        main,
        "ElasticConnector",
        lambda: connector,
    )

    async def failing_workflow(event, **kwargs):
        raise RuntimeError("sensitive-internal-detail")

    monkeypatch.setattr(
        main,
        "run_investigation",
        failing_workflow,
    )

    client = TestClient(
        main.app,
        raise_server_exceptions=False,
    )
    response = client.post(
        "/investigations",
        json=_event_payload(),
        headers=_auth_headers(),
    )

    assert response.status_code == 500
    assert "sensitive-internal-detail" not in response.text
    assert connector.closed is True


def test_investigation_without_credentials_returns_401(
    monkeypatch,
):
    _configure_api_key(monkeypatch)

    client = TestClient(main.app)
    response = client.post(
        "/investigations",
        json=_event_payload(),
    )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_investigation_with_invalid_credentials_returns_401(
    monkeypatch,
):
    _configure_api_key(monkeypatch)

    client = TestClient(main.app)
    response = client.post(
        "/investigations",
        json=_event_payload(),
        headers=_auth_headers("wrong-test-key"),
    )

    assert response.status_code == 401
    assert "wrong-test-key" not in response.text


def test_investigation_without_server_key_fails_closed(
    monkeypatch,
):
    monkeypatch.setattr(
        main.settings,
        "socforge_api_key",
        None,
    )

    client = TestClient(main.app)
    response = client.post(
        "/investigations",
        json=_event_payload(),
        headers=_auth_headers(),
    )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "API authentication is not configured."
    )


def test_investigation_with_empty_server_key_fails_closed(
    monkeypatch,
):
    monkeypatch.setattr(
        main.settings,
        "socforge_api_key",
        SecretStr("   "),
    )

    client = TestClient(main.app)
    response = client.post(
        "/investigations",
        json=_event_payload(),
        headers=_auth_headers("   "),
    )

    assert response.status_code == 503

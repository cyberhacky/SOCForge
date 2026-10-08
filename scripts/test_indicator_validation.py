
import pytest
from pydantic import ValidationError

from enrichment.models import Indicator


@pytest.mark.parametrize(
    ("value", "indicator_type"),
    [
        ("185.0.0.1", "ipv4"),
        ("2001:db8::1", "ipv6"),
        ("example.com", "domain"),
        ("https://example.com/path", "url"),
        ("a" * 32, "md5"),
        ("b" * 40, "sha1"),
        ("c" * 64, "sha256"),
    ],
)
def test_valid_indicators(value, indicator_type):
    indicator = Indicator(value=value, type=indicator_type)
    assert indicator.value == value
    assert indicator.type == indicator_type


@pytest.mark.parametrize(
    ("value", "indicator_type"),
    [
        ("999.1.1.1", "ipv4"),
        ("185.0.0.1", "ipv6"),
        ("not a domain", "domain"),
        ("javascript:alert(1)", "url"),
        ("http://user:password@example.com", "url"),
        ("abc123", "sha256"),
        (" example.com", "domain"),
    ],
)
def test_invalid_indicators(value, indicator_type):
    with pytest.raises(ValidationError):
        Indicator(value=value, type=indicator_type)

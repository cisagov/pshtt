"""HTTP scheme case must not alter HTTPS upgrade or downgrade assessment."""

# Standard Python Libraries
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlparse

# Third-Party Libraries
import pytest
import requests

# cisagov Libraries
from pshtt import pshtt
from pshtt.models import Domain, Endpoint


def response(url, status, location=None):
    """Create a real HTTP response without opening a socket."""
    result = requests.Response()
    result.url = url
    result.status_code = status
    result._content = b""
    result._content_consumed = True
    result.raw = SimpleNamespace(closed=True)
    if location is not None:
        result.headers["Location"] = location
    return result


def check_redirect(location, eventual, protocol="http"):
    """Run the actual endpoint-check orchestration with fixed transport results."""
    endpoint = Endpoint(protocol, "root", "example.test")
    initial = response(endpoint.url, 301, location)
    final = eventual if isinstance(eventual, Exception) else response(eventual, 200)
    with patch.object(pshtt, "ping", side_effect=[initial, final]), patch.object(
        pshtt, "https_check"
    ), patch.object(
        pshtt,
        "parent_domain_for",
        side_effect=lambda host: ".".join(host.split(".")[-2:]),
    ):
        pshtt.basic_check(endpoint)
    assert not endpoint.unknown_error
    return endpoint


@pytest.mark.parametrize("scheme", ["https", "HTTPS", "HtTpS", "http", "HTTP", "hTtP"])
def test_immediate_redirect_classification_uses_the_uri_scheme(scheme):
    """Classify immediate HTTP and HTTPS redirects regardless of scheme case."""
    location = scheme + "://example.test/CasePath?Key=Value#Section"
    endpoint = check_redirect(
        location, "https://example.test/CasePath?Key=Value#Section"
    )
    assert endpoint.redirect_immediately_to_https == (scheme.lower() == "https")
    assert endpoint.redirect_immediately_to_http == (scheme.lower() == "http")
    parsed = urlparse(endpoint.redirect_immediately_to)
    assert (parsed.path, parsed.query, parsed.fragment) == (
        "/CasePath",
        "Key=Value",
        "Section",
    )
    assert endpoint.redirect_immediately_to_external is False


@pytest.mark.parametrize("scheme", ["https", "HTTPS", "HtTpS", "http", "HTTP", "hTtP"])
def test_eventual_redirect_classification_uses_the_uri_scheme(scheme):
    """Classify eventual HTTP and HTTPS redirects by their parsed schemes."""
    eventual = scheme + "://www.example.test/CasePath?Key=Value"
    endpoint = check_redirect("/next", eventual)
    assert endpoint.redirect_eventually_to_https == (scheme.lower() == "https")
    assert endpoint.redirect_eventually_to_http == (scheme.lower() == "http")
    assert endpoint.redirect_eventually_to == eventual
    assert endpoint.redirect_eventually_to_subdomain is True


@pytest.mark.parametrize("scheme", ["HTTP", "hTtP"])
def test_https_downgrade_is_reported_for_mixed_case_http(scheme):
    """Detect HTTPS-to-HTTP downgrades with mixed-case HTTP schemes."""
    endpoint = check_redirect(
        scheme + "://example.test/plain", "http://example.test/plain", protocol="https"
    )
    domain = Domain("example.test")
    domain.canonical = domain.https = endpoint
    domain.httpswww = Endpoint("https", "www", "example.test")
    assert pshtt.is_downgrades_https(domain) is True


def test_external_redirect_fallback_preserves_https_classification():
    """Preserve HTTPS flags if an external redirect cannot be followed."""
    endpoint = check_redirect(
        "HTTPS://outside.test/CasePath", requests.ConnectionError("offline fixture")
    )
    assert endpoint.redirect_immediately_to_external is True
    assert endpoint.redirect_eventually_to_https is True
    assert endpoint.redirect_eventually_to == endpoint.redirect_immediately_to


@pytest.mark.parametrize("location", ["/CasePath", "//www.example.test/CasePath"])
def test_relative_redirects_retain_the_original_http_scheme(location):
    """Preserve the originating HTTP scheme for relative redirects."""
    endpoint = check_redirect(location, "http://www.example.test/CasePath")
    assert endpoint.redirect_immediately_to_http is True
    assert endpoint.redirect_immediately_to_https is False

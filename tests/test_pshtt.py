"""Test the core functionality of the library."""

# Standard Python Libraries
import datetime
import unittest
from unittest.mock import MagicMock, call, patch

# Third-Party Libraries
from unittest_parametrize import ParametrizedTestCase, param, parametrize

# cisagov Libraries
from pshtt.models import Domain, Endpoint
from pshtt.pshtt import (
    certificate_is_expired,
    https_check,
    inspect_domains,
    is_live,
    is_strictly_forces_https,
)


class TestLiveliness(unittest.TestCase):
    """Test the liveliness of a domain."""

    def setUp(self):
        """Perform initial setup."""
        base_domain = "example.com"
        self.domain = Domain(base_domain)

        self.domain.http = Endpoint("http", "root", base_domain)
        self.domain.httpwww = Endpoint("http", "www", base_domain)
        self.domain.https = Endpoint("https", "root", base_domain)
        self.domain.httpswww = Endpoint("https", "www", base_domain)

    def test_none(self):
        """Test in an unchecked state."""
        self.assertFalse(is_live(self.domain))

    def test_http_only(self):
        """Test when only HTTP access is live on the base domain name."""
        self.domain.http.live = True

        self.assertTrue(is_live(self.domain))

    def test_https_only(self):
        """Test when only HTTPS access is live on the base domain name."""
        self.domain.https.live = True

        self.assertTrue(is_live(self.domain))

    def test_httpwww_only(self):
        """Test when only HTTP access is live on the www prefixed domain name."""
        self.domain.httpwww.live = True

        self.assertTrue(is_live(self.domain))

    def test_httpswww_only(self):
        """Test when only HTTPS access is live on the www prefixed domain name."""
        self.domain.httpswww.live = True

        self.assertTrue(is_live(self.domain))

    def test_http_both(self):
        """Test when only HTTP access is live on both domain names."""
        self.domain.http.live = True
        self.domain.httpwww.live = True

        self.assertTrue(is_live(self.domain))

    def test_https_both(self):
        """Test when only HTTPS access is live on both domain names."""
        self.domain.https.live = True
        self.domain.httpswww.live = True

        self.assertTrue(is_live(self.domain))

    def test_www_neither(self):
        """Test when both HTTP and HTTPS are live on only the base domain."""
        self.domain.http.live = True
        self.domain.https.live = True

        self.assertTrue(is_live(self.domain))

    def test_www_both(self):
        """Test when both HTTP and HTTPS are live on the www prefixed domain name."""
        self.domain.httpwww.live = True
        self.domain.httpswww.live = True

        self.assertTrue(is_live(self.domain))

    def test_all(self):
        """Test when both HTTP and HTTPS are live on both domain names."""
        self.domain.http.live = True
        self.domain.https.live = True
        self.domain.httpwww.live = True
        self.domain.httpswww.live = True

        self.assertTrue(is_live(self.domain))


class TestHttpsCheckServerLocation(ParametrizedTestCase):
    """Test HTTPS check parses endpoint host/port correctly for sslyze."""

    @patch("pshtt.pshtt.ServerConnectivityTester")
    @patch("pshtt.pshtt.ServerNetworkLocationViaDirectConnection")
    def test_https_check_uses_explicit_port(
        self, mock_server_network_location, mock_server_connectivity_tester
    ):
        """Use the endpoint's explicit port when building sslyze target."""
        endpoint = Endpoint("https", "root", "example.com:9443")

        server_location = MagicMock()
        server_location.ip_address = "127.0.0.1"
        mock_server_network_location.with_ip_address_lookup.return_value = (
            server_location
        )

        tester = MagicMock()
        tester.perform.side_effect = RuntimeError("stop after checking location args")
        mock_server_connectivity_tester.return_value = tester

        # We stop the scan early by raising from perform(); https_check catches
        # that and logs it via logging.exception, which would otherwise dump a
        # traceback into the test output and look like a failure. Capture the
        # expected error log so the output stays clean.
        with self.assertLogs(level="ERROR"):
            https_check(endpoint)

        mock_server_network_location.with_ip_address_lookup.assert_called_once_with(
            hostname="example.com", port=9443
        )

    @parametrize(
        ("port", "protocol"),
        [
            param(80, "http", id="http"),
            param(443, "https", id="https"),
        ],
    )
    @patch("pshtt.pshtt.ServerConnectivityTester")
    @patch("pshtt.pshtt.ServerNetworkLocationViaDirectConnection")
    def test_check_default_web_ports(
        self,
        mock_server_network_location,
        mock_server_connectivity_tester,
        port,
        protocol,
    ):
        """Default to expected default port when endpoint URL has no explicit port."""
        endpoint = Endpoint(protocol, "root", "example.com")

        server_location = MagicMock()
        server_location.ip_address = "127.0.0.1"
        mock_server_network_location.with_ip_address_lookup.return_value = (
            server_location
        )

        tester = MagicMock()
        tester.perform.side_effect = RuntimeError("stop after checking location args")
        mock_server_connectivity_tester.return_value = tester

        # We stop the scan early by raising from perform(); https_check catches
        # that and logs it via logging.exception, which would otherwise dump a
        # traceback into the test output and look like a failure. Capture the
        # expected error log so the output stays clean.
        with self.assertLogs(level="ERROR"):
            https_check(endpoint)

        mock_server_network_location.with_ip_address_lookup.assert_called_once_with(
            hostname="example.com", port=port
        )


class TestCertificateExpiry(ParametrizedTestCase):
    """Test certificate expiration logic uses UTC-aware comparisons."""

    @parametrize(
        "not_valid_after",
        [
            param(
                datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc),
                id="timezone_aware",
            ),
            param(
                datetime.datetime(
                    2026,
                    1,
                    1,
                    12,
                    0,
                    0,
                ),
                id="naive",
            ),
        ],
    )
    def test_not_valid_after_utc_unavailable(self, not_valid_after):
        """Use not_valid_after if not_valid_after_utc is not available."""
        cert = MagicMock()
        cert.not_valid_after_utc = None
        cert.not_valid_after = not_valid_after

        now_utc = datetime.datetime(2026, 1, 1, 11, 0, 0, tzinfo=datetime.timezone.utc)

        self.assertFalse(certificate_is_expired(cert, now_utc))

    @parametrize(
        "not_valid_after_utc",
        [
            param(
                datetime.datetime(2026, 1, 1, 10, 0, 0, tzinfo=datetime.timezone.utc),
                id="timezone_aware",
            ),
            param(
                datetime.datetime(
                    2026,
                    1,
                    1,
                    10,
                    0,
                    0,
                ),
                id="naive",
            ),
        ],
    )
    def test_not_valid_after_utc_available(self, not_valid_after_utc):
        """Use not_valid_after_utc when cryptography exposes it."""
        cert = MagicMock()
        cert.not_valid_after_utc = not_valid_after_utc

        now_utc = datetime.datetime(2026, 1, 1, 11, 0, 0, tzinfo=datetime.timezone.utc)

        self.assertTrue(certificate_is_expired(cert, now_utc))


class TestStrictlyForcesHttps(unittest.TestCase):
    """Test is_strictly_forces_https always returns a bool, never None.

    When an endpoint is live but redirect_immediately_to_https has not been
    determined yet (its default is None), the inner down_or_redirects helper
    formerly evaluated ``False or None`` which Python propagates as None.
    That None then bubbled up through the ``and`` chain so the public field
    "Strictly Forces HTTPS" was reported as null in JSON output.  See #176.
    """

    def setUp(self):
        """Set up a domain with fresh endpoints."""
        base_domain = "example.com"
        self.domain = Domain(base_domain)
        self.domain.http = Endpoint("http", "root", base_domain)
        self.domain.httpwww = Endpoint("http", "www", base_domain)
        self.domain.https = Endpoint("https", "root", base_domain)
        self.domain.httpswww = Endpoint("https", "www", base_domain)

    def test_result_is_bool_when_http_live_and_redirect_unset(self):
        """Return False (not None) when HTTP is live with no redirect configured."""
        self.domain.https.live = True
        self.domain.http.live = True
        # redirect_immediately_to_https stays at its default value of None

        result = is_strictly_forces_https(self.domain)

        self.assertIsInstance(result, bool, "is_strictly_forces_https must return bool")
        self.assertFalse(result)

    def test_result_is_bool_when_all_endpoints_none(self):
        """Return False (not None) when all endpoint attributes are still None."""
        result = is_strictly_forces_https(self.domain)

        self.assertIsInstance(result, bool, "is_strictly_forces_https must return bool")
        self.assertFalse(result)

    def test_strictly_forces_when_http_endpoints_redirect_to_https(self):
        """Return True when HTTPS is live and HTTP endpoints redirect to HTTPS."""
        self.domain.https.live = True
        self.domain.http.live = True
        self.domain.http.redirect_immediately_to_https = True
        self.domain.httpwww.live = True
        self.domain.httpwww.redirect_immediately_to_https = True

        result = is_strictly_forces_https(self.domain)

        self.assertIsInstance(result, bool)
        self.assertTrue(result)


class TestInspectDomains(ParametrizedTestCase):
    """Test input normalization through the library entry point."""

    @parametrize(
        ("domains", "expected"),
        [
            param(["https://www.example.com"], ["example.com"], id="https"),
            param(["http://www.example.com"], ["example.com"], id="http"),
            param(["www.example.com"], ["example.com"], id="www"),
            param(["example.com:8443"], ["example.com:8443"], id="port"),
            param(["www.www.example.com"], ["www.example.com"], id="one_prefix"),
            param(
                ["example.org", "example.com"],
                ["example.org", "example.com"],
                id="order",
            ),
            param([], [], id="empty"),
        ],
    )
    @patch("pshtt.pshtt.initialize_external_data")
    @patch("pshtt.pshtt.inspect", side_effect=lambda domain: domain)
    def test_normalization(self, mock_inspect, mock_initialize, domains, expected):
        """Normalize inputs once without changing their order or the input list."""
        original = domains.copy()
        self.assertEqual(list(inspect_domains(domains, {})), expected)
        self.assertEqual(
            mock_inspect.call_args_list, [call(domain) for domain in expected]
        )
        self.assertEqual(domains, original)

    @patch("pshtt.pshtt.initialize_external_data")
    @patch("pshtt.pshtt.inspect", side_effect=lambda domain: domain)
    def test_sort_normalized_domains(self, mock_inspect, mock_initialize):
        """Sort on normalized names when requested, preserving duplicates."""
        domains = ["example.org", "https://www.example.com", "www.example.com"]
        self.assertEqual(
            list(inspect_domains(domains, {"sorted": True})),
            ["example.com", "example.com", "example.org"],
        )

    @patch("pshtt.pshtt.initialize_external_data")
    @patch("pshtt.pshtt.inspect", side_effect=lambda domain: domain)
    def test_iterable_input(self, mock_inspect, mock_initialize):
        """Accept an iterable of domain names."""
        domains = (domain for domain in ["https://www.example.com", "www.example.org"])
        self.assertEqual(
            list(inspect_domains(domains, {})), ["example.com", "example.org"]
        )

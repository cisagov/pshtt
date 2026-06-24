"""Test the core functionality of the library."""

# Standard Python Libraries
import datetime
import unittest
from unittest.mock import MagicMock, patch

# Third-Party Libraries
from unittest_parametrize import ParametrizedTestCase, param, parametrize

# cisagov Libraries
from pshtt.models import Domain, Endpoint
from pshtt.pshtt import certificate_is_expired, https_check, is_live


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

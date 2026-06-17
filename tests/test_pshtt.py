"""Test the core functionality of the library."""

# Standard Python Libraries
import unittest
from unittest.mock import MagicMock, patch

# cisagov Libraries
from pshtt.models import Domain, Endpoint
from pshtt.pshtt import https_check, is_live


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


class TestHttpsCheckServerLocation(unittest.TestCase):
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

        https_check(endpoint)

        mock_server_network_location.with_ip_address_lookup.assert_called_once_with(
            hostname="example.com", port=9443
        )

    @patch("pshtt.pshtt.ServerConnectivityTester")
    @patch("pshtt.pshtt.ServerNetworkLocationViaDirectConnection")
    def test_https_check_defaults_to_port_443(
        self, mock_server_network_location, mock_server_connectivity_tester
    ):
        """Default to port 443 when endpoint URL has no explicit port."""
        endpoint = Endpoint("https", "root", "example.com")

        server_location = MagicMock()
        server_location.ip_address = "127.0.0.1"
        mock_server_network_location.with_ip_address_lookup.return_value = (
            server_location
        )

        tester = MagicMock()
        tester.perform.side_effect = RuntimeError("stop after checking location args")
        mock_server_connectivity_tester.return_value = tester

        https_check(endpoint)

        mock_server_network_location.with_ip_address_lookup.assert_called_once_with(
            hostname="example.com", port=443
        )

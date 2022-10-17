"""Test the core functionality of the library."""

# Standard Python Libraries
import unittest

# cisagov Libraries
from pshtt.models import Domain, Endpoint
from pshtt.pshtt import is_live


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

"""Test the library's models."""

# Standard Python Libraries
import unittest

# cisagov Libraries
from pshtt import pshtt as api
from pshtt.models import Domain, Endpoint


class TestUsesHTTPS(unittest.TestCase):
    """Test for a domain using HTTPS."""

    def setUp(self):
        """Perform initial setup."""
        base_domain = "example.com"
        self.domain = Domain(base_domain)

        self.domain.http = Endpoint("http", "root", base_domain)
        self.domain.httpwww = Endpoint("http", "www", base_domain)
        self.domain.https = Endpoint("https", "root", base_domain)
        self.domain.httpswww = Endpoint("https", "www", base_domain)

    @unittest.skip("Still working on definition")
    def test_definition(self):
        """Test the definition of a domain using HTTPS."""
        self.domain.https.live = True
        self.domain.https.https_valid = True
        self.domain.https.https_valid = True

        self.assertTrue(api.is_domain_supports_https(self.domain))


class TestBadChain(unittest.TestCase):
    """Test for a bad certificate chain."""

    def setUp(self):
        """Perform initial setup."""
        base_domain = "example.com"
        self.domain = Domain(base_domain)

        self.domain.http = Endpoint("http", "root", base_domain)
        self.domain.httpwww = Endpoint("http", "www", base_domain)
        self.domain.https = Endpoint("https", "root", base_domain)
        self.domain.httpswww = Endpoint("https", "www", base_domain)

    def test_bad_chain_root(self):
        """Test the root domain name."""
        self.domain.https.https_bad_chain = True
        self.domain.canonical = self.domain.https

        self.assertTrue(api.is_bad_chain(self.domain))

    def test_bad_chain_www(self):
        """Test the www prefixed domain name."""
        self.domain.httpswww.https_bad_chain = True
        self.domain.canonical = self.domain.httpswww

        self.assertTrue(api.is_bad_chain(self.domain))

    def test_bad_chain_both(self):
        """Test both the root and www prefixed domain name."""
        self.domain.https.https_bad_chain = True
        self.domain.httpswww.https_bad_chain = True

        self.domain.canonical = self.domain.https
        self.assertTrue(api.is_bad_chain(self.domain))

        self.domain.canonical = self.domain.httpswww
        self.assertTrue(api.is_bad_chain(self.domain))


class TestBadHostname(unittest.TestCase):
    """Verify the bad hostname check."""

    def setUp(self):
        """Perform initial setup."""
        base_domain = "example.com"
        self.domain = Domain(base_domain)

        self.domain.http = Endpoint("http", "root", base_domain)
        self.domain.httpwww = Endpoint("http", "www", base_domain)
        self.domain.https = Endpoint("https", "root", base_domain)
        self.domain.httpswww = Endpoint("https", "www", base_domain)

    def test_bad_hostname_root(self):
        """Test using the base domain name."""
        self.domain.https.https_bad_hostname = True
        self.domain.canonical = self.domain.https

        self.assertTrue(api.is_bad_hostname(self.domain))

    def test_bad_hostname_www(self):
        """Test using the www prefixed domain name."""
        self.domain.httpswww.https_bad_hostname = True
        self.domain.canonical = self.domain.httpswww

        self.assertTrue(api.is_bad_hostname(self.domain))

    def test_bad_hostname_both(self):
        """Test both the root and www prefixed domain name."""
        self.domain.https.https_bad_hostname = True
        self.domain.httpswww.https_bad_hostname = True

        self.domain.canonical = self.domain.https
        self.assertTrue(api.is_bad_hostname(self.domain))

        self.domain.canonical = self.domain.httpswww
        self.assertTrue(api.is_bad_hostname(self.domain))

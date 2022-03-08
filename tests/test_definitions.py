# Standard Python Libraries
import unittest

# cisagov Libraries
from pshtt import pshtt as api
from pshtt.models import Domain, Endpoint


class TestUsesHTTPS(unittest.TestCase):
    def setUp(self):
        base_domain = "example.com"
        self.domain = Domain(base_domain)

        self.domain.http = Endpoint("http", "root", base_domain)
        self.domain.httpwww = Endpoint("http", "www", base_domain)
        self.domain.https = Endpoint("https", "root", base_domain)
        self.domain.httpswww = Endpoint("https", "www", base_domain)

    @unittest.skip("Still working on definition")
    def test_definition(self):
        self.domain.https.live = True
        self.domain.https.https_valid = True
        self.domain.https.https_valid = True

        self.assertTrue(api.is_domain_supports_https(self.domain))


class TestBadChain(unittest.TestCase):
    def setUp(self):
        base_domain = "example.com"
        self.domain = Domain(base_domain)

        self.domain.http = Endpoint("http", "root", base_domain)
        self.domain.httpwww = Endpoint("http", "www", base_domain)
        self.domain.https = Endpoint("https", "root", base_domain)
        self.domain.httpswww = Endpoint("https", "www", base_domain)

    def test_bad_chain_root(self):
        self.domain.https.https_bad_chain = True
        self.domain.canonical = self.domain.https

        self.assertTrue(api.is_bad_chain(self.domain))

    def test_bad_chain_www(self):
        self.domain.httpswww.https_bad_chain = True
        self.domain.canonical = self.domain.httpswww

        self.assertTrue(api.is_bad_chain(self.domain))

    def test_bad_chain_both(self):
        self.domain.https.https_bad_chain = True
        self.domain.httpswww.https_bad_chain = True

        self.domain.canonical = self.domain.https
        self.assertTrue(api.is_bad_chain(self.domain))

        self.domain.canonical = self.domain.httpswww
        self.assertTrue(api.is_bad_chain(self.domain))


class TestBadHostname(unittest.TestCase):
    def setUp(self):
        base_domain = "example.com"
        self.domain = Domain(base_domain)

        self.domain.http = Endpoint("http", "root", base_domain)
        self.domain.httpwww = Endpoint("http", "www", base_domain)
        self.domain.https = Endpoint("https", "root", base_domain)
        self.domain.httpswww = Endpoint("https", "www", base_domain)

    def test_bad_hostname_root(self):
        self.domain.https.https_bad_hostname = True
        self.domain.canonical = self.domain.https

        self.assertTrue(api.is_bad_hostname(self.domain))

    def test_bad_hostname_www(self):
        self.domain.httpswww.https_bad_hostname = True
        self.domain.canonical = self.domain.httpswww

        self.assertTrue(api.is_bad_hostname(self.domain))

    def test_bad_hostname_both(self):
        self.domain.https.https_bad_hostname = True
        self.domain.httpswww.https_bad_hostname = True

        self.domain.canonical = self.domain.https
        self.assertTrue(api.is_bad_hostname(self.domain))

        self.domain.canonical = self.domain.httpswww
        self.assertTrue(api.is_bad_hostname(self.domain))

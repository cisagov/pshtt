"""Test bad SSL results from a domain."""

# Standard Python Libraries
import unittest

# cisagov Libraries
from pshtt.models import Domain, Endpoint
from pshtt.pshtt import basic_check, hsts_check


def inspect(base_domain):
    """Populate a domain model with the provided domain."""
    domain = Domain(base_domain)
    domain.http = Endpoint("http", "root", base_domain)
    domain.httpwww = Endpoint("http", "www", base_domain)
    domain.https = Endpoint("https", "root", base_domain)
    domain.httpswww = Endpoint("https", "www", base_domain)

    return domain

    # Analyze HTTP endpoint responsiveness and behavior.
    basic_check(domain.http)
    basic_check(domain.httpwww)
    basic_check(domain.https)
    basic_check(domain.httpswww)

    # Analyze HSTS header, if present, on each HTTPS endpoint.
    hsts_check(domain.https)
    hsts_check(domain.httpswww)

    return domain


@unittest.skip("Disable live tests against badssl for now")
class TestCertificate(unittest.TestCase):
    """Test different bad certificate results."""

    def test_https_expired(self):
        """Test when the certificate has expired."""
        domain = inspect("expired.badssl.com")
        basic_check(domain.https)

        self.assertTrue(domain.https.https_expired_cert)

    def test_https_bad_hostname(self):
        """Test when the certificate has a bad hostname."""
        domain = inspect("wrong.host.badssl.com")
        basic_check(domain.https)

        self.assertTrue(domain.https.https_bad_hostname)

    def test_https_bad_chain(self):
        """Test when there is a bad chain of trust for a certificate."""
        domain = inspect("untrusted-root.badssl.com")
        basic_check(domain.https)

        self.assertTrue(domain.https.https_bad_chain)

    def test_https_self_signed_cert(self):
        """Test when a certificate is self-signed."""
        domain = inspect("self-signed.badssl.com")
        basic_check(domain.https)

        self.assertTrue(domain.https.https_self_signed_cert)

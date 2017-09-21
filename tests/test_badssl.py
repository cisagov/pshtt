import unittest

from pshtt.models import Domain, Endpoint
from pshtt.pshtt import basic_check, hsts_check


def inspect(base_domain):
    """
    Mostly copied from pshtt.pshtt.inspect()
    """
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


class TestCertificate(unittest.TestCase):
    def test_https_expired(self):
        domain = inspect('expired.badssl.com')
        basic_check(domain.https)

        self.assertTrue(domain.https.https_expired_cert)

    def test_https_bad_hostname(self):
        domain = inspect('wrong.host.badssl.com')
        basic_check(domain.https)

        self.assertTrue(domain.https.https_bad_hostname)

    def test_https_bad_chain(self):
        domain = inspect('untrusted-root.badssl.com')
        basic_check(domain.https)

        self.assertTrue(domain.https.https_bad_chain)

    def test_https_self_signed_cert(self):
        domain = inspect('self-signed.badssl.com')
        basic_check(domain.https)

        self.assertTrue(domain.https.https_self_signed_cert)


if __name__ == '__main__':
    unittest.main()

import os
import sys
import tempfile
import unittest

from pshtt.models import Domain, Endpoint
from pshtt import pshtt as _pshtt
from pshtt.cli import to_csv


class FakeSuffixList(object):
    def get_public_suffix(self, hostname, *args, **kwargs):
        return hostname


# Artificially setup the the preload and suffix lists
# This should be irrelevant after #126 is decided upon / merged
_pshtt.suffix_list = FakeSuffixList()
_pshtt.preload_list = []
_pshtt.preload_pending = []


class TestToCSV(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base_domain = 'example.com'

        domain = Domain(base_domain)
        domain.http = Endpoint("http", "root", base_domain)
        domain.httpwww = Endpoint("http", "www", base_domain)
        domain.https = Endpoint("https", "root", base_domain)
        domain.httpswww = Endpoint("https", "www", base_domain)

        cls.results = _pshtt.result_for(domain)
        cls.temp_filename = os.path.join(tempfile.gettempdir(), 'results.csv')

    @unittest.skipIf(sys.version_info[0] < 3, 'Python 3 test only')
    def test_no_results(self):
        to_csv([], self.temp_filename)

        with open(self.temp_filename) as fh:
            content = fh.read()

            expected = 'Domain,Base Domain,Canonical URL,Live,Redirect,Redirect To,Valid HTTPS,Defaults to HTTPS,Downgrades HTTPS,Strictly Forces HTTPS,HTTPS Bad Chain,HTTPS Bad Hostname,HTTPS Expired Cert,HTTPS Self Signed Cert,HSTS,HSTS Header,HSTS Max Age,HSTS Entire Domain,HSTS Preload Ready,HSTS Preload Pending,HSTS Preloaded,Base Domain HSTS Preloaded,Domain Supports HTTPS,Domain Enforces HTTPS,Domain Uses Strong HSTS,Unknown Error\n'

            self.assertEqual(content, expected)

    @unittest.skipIf(sys.version_info[0] < 3, 'Python 3 test only')
    def test_single_result(self):
        to_csv([self.results], self.temp_filename)

        with open(self.temp_filename) as fh:
            content = fh.read()

            expected = ''
            expected += 'Domain,Base Domain,Canonical URL,Live,Redirect,Redirect To,Valid HTTPS,Defaults to HTTPS,Downgrades HTTPS,Strictly Forces HTTPS,HTTPS Bad Chain,HTTPS Bad Hostname,HTTPS Expired Cert,HTTPS Self Signed Cert,HSTS,HSTS Header,HSTS Max Age,HSTS Entire Domain,HSTS Preload Ready,HSTS Preload Pending,HSTS Preloaded,Base Domain HSTS Preloaded,Domain Supports HTTPS,Domain Enforces HTTPS,Domain Uses Strong HSTS,Unknown Error\n'
            expected += 'example.com,example.com,http://example.com,False,False,,False,False,False,False,False,False,False,False,False,,,False,False,False,False,False,False,False,False,False\n'

            self.assertEqual(content, expected)

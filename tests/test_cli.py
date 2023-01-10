"""Test the command line interface functionality of the library."""

# Standard Python Libraries
import os
import sys
import tempfile
import unittest

# cisagov Libraries
from pshtt import pshtt as _pshtt
from pshtt.cli import to_csv
from pshtt.models import Domain, Endpoint


class FakeSuffixList:
    """Test against a fake suffix list."""

    def get_public_suffix(self, hostname, *args, **kwargs):
        """Return the public suffix of a hostname."""
        return hostname


# Artificially setup the the preload and suffix lists
# This should be irrelevant after #126 is decided upon / merged
_pshtt.SUFFIX_LIST = FakeSuffixList()
_pshtt.PRELOAD_LIST = []
_pshtt.PRELOAD_PENDING = []


class TestToCSV(unittest.TestCase):
    """Test the CSV output of the command line interface."""

    @classmethod
    def setUpClass(cls):
        """Perform initial setup."""
        base_domain = "example.com"

        domain = Domain(base_domain)
        domain.http = Endpoint("http", "root", base_domain)
        domain.httpwww = Endpoint("http", "www", base_domain)
        domain.https = Endpoint("https", "root", base_domain)
        domain.httpswww = Endpoint("https", "www", base_domain)

        cls.results = _pshtt.result_for(domain)
        cls.temp_filename = os.path.join(tempfile.gettempdir(), "results.csv")

    @unittest.skipIf(sys.version_info[0] < 3, "Python 3 test only")
    def test_no_results(self):
        """Test when there are no results."""
        to_csv([], self.temp_filename)

        with open(self.temp_filename) as fh:
            content = fh.read()

        expected = ",".join(_pshtt.HEADERS) + "\n"

        self.assertEqual(content, expected)

    @unittest.skipIf(sys.version_info[0] < 3, "Python 3 test only")
    def test_single_result(self):
        """Test a single domain result."""
        to_csv([self.results], self.temp_filename)

        with open(self.temp_filename) as fh:
            content = fh.read()

        domain_data = [
            ("Domain", "example.com"),
            ("Base Domain", "example.com"),
            ("Canonical URL", "http://example.com"),
            ("Live", "False"),
            ("HTTPS Live", "False"),
            ("HTTPS Full Connection", "False"),
            ("HTTPS Client Auth Required", "False"),
            ("Redirect", "False"),
            ("Redirect To", ""),
            ("Valid HTTPS", "False"),
            ("HTTPS Publicly Trusted", "False"),
            ("HTTPS Custom Truststore Trusted", "False"),
            ("Defaults to HTTPS", "False"),
            ("Downgrades HTTPS", "False"),
            ("Strictly Forces HTTPS", "False"),
            ("HTTPS Bad Chain", "False"),
            ("HTTPS Bad Hostname", "False"),
            ("HTTPS Expired Cert", "False"),
            ("HTTPS Self Signed Cert", "False"),
            ("HSTS", ""),
            ("HSTS Header", ""),
            ("HSTS Max Age", ""),
            ("HSTS Entire Domain", ""),
            ("HSTS Preload Ready", "False"),
            ("HSTS Preload Pending", "False"),
            ("HSTS Preloaded", "False"),
            ("Base Domain HSTS Preloaded", "False"),
            ("Domain Supports HTTPS", "False"),
            ("Domain Enforces HTTPS", "False"),
            ("Domain Uses Strong HSTS", ""),
            ("IP", ""),
            ("Server Header", ""),
            ("Server Version", ""),
            ("HTTPS Cert Chain Length", ""),
            ("HTTPS Probably Missing Intermediate Cert", "False"),
            ("Notes", ""),
            ("Unknown Error", "False"),
        ]

        self.maxDiff = None

        header = ",".join(t[0] for t in domain_data)
        values = ",".join(t[1] for t in domain_data)
        expected = header + "\n" + values + "\n"
        self.assertEqual(content, expected)

        # Sanity check that this hard coded data has the same headers as defined
        # in the package. This should never fail, as the above assert should
        # catch any changes in the header columns.
        self.assertEqual(header, ",".join(_pshtt.HEADERS))

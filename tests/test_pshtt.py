import unittest

from pshtt.models import Domain, Endpoint
from pshtt.pshtt import is_live, hsts_check, is_redirect_or_down, is_redirect


class TestLiveliness(unittest.TestCase):
    def setUp(self):
        base_domain = 'example.com'
        self.domain = Domain(base_domain)

        self.domain.http = Endpoint("http", "root", base_domain)
        self.domain.httpwww = Endpoint("http", "www", base_domain)
        self.domain.https = Endpoint("https", "root", base_domain)
        self.domain.httpswww = Endpoint("https", "www", base_domain)

    def test_none(self):
        self.assertFalse(is_live(self.domain))

    def test_http_only(self):
        self.domain.http.live = True

        self.assertTrue(is_live(self.domain))

    def test_https_only(self):
        self.domain.https.live = True

        self.assertTrue(is_live(self.domain))

    def test_httpwww_only(self):
        self.domain.httpwww.live = True

        self.assertTrue(is_live(self.domain))

    def test_httpswww_only(self):
        self.domain.httpswww.live = True

        self.assertTrue(is_live(self.domain))

    def test_http_both(self):
        self.domain.http.live = True
        self.domain.httpwww.live = True

        self.assertTrue(is_live(self.domain))

    def test_https_both(self):
        self.domain.https.live = True
        self.domain.httpswww.live = True

        self.assertTrue(is_live(self.domain))

    def test_www_neither(self):
        self.domain.http.live = True
        self.domain.https.live = True

        self.assertTrue(is_live(self.domain))

    def test_www_both(self):
        self.domain.httpwww.live = True
        self.domain.httpswww.live = True

        self.assertTrue(is_live(self.domain))

    def test_all(self):
        self.domain.http.live = True
        self.domain.https.live = True
        self.domain.httpwww.live = True
        self.domain.httpswww.live = True

        self.assertTrue(is_live(self.domain))

    #
    # Checks for hsts_check()
    #
    def test_hsts_check_bad_hostname(self):
        self.domain.https.https_bad_hostname = True
        hsts_check(self.domain.https)
        self.assertFalse(self.domain.https.hsts)

    def test_hsts_check_empty_header(self):
        hsts_check(self.domain.https)
        self.assertFalse(self.domain.https.hsts)

    def test_hsts_check_max_age_good_value(self):
        self.domain.https.headers["Strict-Transport-Security"] = "max-age=31536000"
        hsts_check(self.domain.https)
        self.assertTrue(self.domain.https.hsts_max_age == 31536000)

    def test_hsts_check_max_age_none(self):
        self.domain.https.headers["Strict-Transport-Security"] = "includeSubDomains"
        hsts_check(self.domain.https)
        self.assertFalse(self.domain.https.hsts)

    def test_hsts_check_max_age_negative(self):
        self.domain.https.headers["Strict-Transport-Security"] = "max-age=-1"
        hsts_check(self.domain.https)
        self.assertFalse(self.domain.https.hsts)

    def test_hsts_check_has_includeSubDomains(self):
        self.domain.https.headers["Strict-Transport-Security"] = "max-age=31536000;includeSubDomains"
        hsts_check(self.domain.https)
        self.assertTrue(self.domain.https.hsts_all_subdomains)

    def test_hsts_check_no_includeSubDomains(self):
        self.domain.https.headers["Strict-Transport-Security"] = "max-age=31536000"
        hsts_check(self.domain.https)
        self.assertFalse(self.domain.https.hsts_all_subdomains)

    def test_hsts_check_has_preload(self):
        self.domain.https.headers["Strict-Transport-Security"] = "max-age=31536000;preload"
        hsts_check(self.domain.https)
        self.assertTrue(self.domain.https.hsts_preload)

    def test_hsts_check_no_preload(self):
        self.domain.https.headers["Strict-Transport-Security"] = "max-age=31536000"
        hsts_check(self.domain.https)
        self.assertFalse(self.domain.https.hsts_preload)

    #
    # Checks for is_redirect_or_down()
    #
    def test_is_redirect_or_down_1(self):
        self.assertTrue(is_redirect_or_down(self.domain.http))

    def test_is_redirect_or_down_2(self):
        self.domain.http.redirect_eventually_to_external = True
        self.domain.http.live = True
        self.assertTrue(is_redirect_or_down(self.domain.http))

    def test_is_redirect_or_down_3(self):
        self.domain.http.live = True
        self.assertFalse(is_redirect_or_down(self.domain.http))

    def test_is_redirect_or_down_4(self):
        self.domain.https.live = True
        self.domain.https.https_bad_hostname = True
        self.assertTrue(is_redirect_or_down(self.domain.https))

    def test_is_redirect_or_down_5(self):
        self.domain.http.live = True
        self.domain.http.status = 200
        self.assertFalse(is_redirect_or_down(self.domain.http))

    def test_is_redirect_or_down_6(self):
        self.domain.http.live = True
        self.domain.http.status = 404
        self.assertTrue(is_redirect_or_down(self.domain.http))


    #
    # Checks for is_redirect()
    #
    def test_is_redirect_1(self):
        self.assertFalse(is_redirect(self.domain.http))

    def test_is_redirect_2(self):
        self.domain.http.redirect_eventually_to_external = True
        self.assertTrue(is_redirect(self.domain.http))

if __name__ == '__main__':
    unittest.main()

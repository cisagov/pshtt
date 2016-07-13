#!/usr/bin/python
import httplib
import urllib2

class Domain:

    def __init__(self, base_domain):
        self.domain = ""
        self.base_domain = base_domain
        self.canonical = ""
        self.https_domain = ""
        self.live = ""
        self.redirect = ""
        self.redirect_to = ""
        self.valid_https = ""
        self.defaults_to_https = ""
        self.downgrades_https = ""
        self.strictly_forces_https = ""
        self.https_bad_chain = ""
        self.https_bad_hostname = ""
        self.hsts = ""
        self.hsts_header = ""
        self.hsts_max_age = ""
        self.hsts_all_subdomains = ""
        self.hsts_preload_ready = ""
        self.hsts_preloaded = ""
        self.broken_root = ""
        self.broken_www = ""

    def __str__(self):
        return ("Domain: " + str(self.domain) + " \n" +
                "Base Domain: " + str(self.base_domain) + "\n"+
                "Canonical: " + self.canonical + "\n"+
                "HTTPS Domain:" + self.https_domain + "\n" +
                "Live: " + self.live + "\n"+
                "Redirect: " + self.redirect + "\n"+
                "Redirect To: " + self.redirect_to + "\n" +
                "Valid HTTPS: " + self.valid_https + "\n" +
                "Defaults HTTPS: " + self.defaults_to_https + "\n" +
                "Downgrades HTTPS: " + self.downgrades_https + "\n" +
                "Strictly Forces HTTPS: " + self.strictly_forces_https + "\n" +
                "HTTPS Bad Chain: " + self.https_bad_chain + "\n" +
                "HTTPS Bad Host Name: " + self.https_bad_hostname + "\n" +
                "HSTS: " + self.hsts + "\n" +
                "HSTS Header: " + self.hsts_header + "\n" +
                "HSTS Max Age: " + self.hsts_max_age + "\n" +
                "HSTS All Subdomains: " + self.hsts_all_subdomains + "\n" +
                "HSTS Preload Ready: " + self.hsts_preload_ready + "\n" +
                "HSTS Preloaded: " + self.hsts_preloaded + "\n" +
                "Broken Root: " + self.broken_root + "\n" +
                "Broken www: " + self.broken_www + "\n")

    def output_to_csv(self):
        return (str(self.domain) + "," +
                str(self.base_domain) + ","+
                self.canonical + ","+
                self.live + ","+
                self.redirect + ","+
                self.redirect_to + "," +
                self.https_domain + "," +
                self.valid_https + "," +
                self.defaults_to_https + "," +
                self.downgrades_https + "," +
                self.strictly_forces_https + "," +
                self.https_bad_chain + "," +
                self.https_bad_hostname + "," +
                self.hsts + "," +
                self.hsts_header + "," +
                self.hsts_max_age + "," +
                self.hsts_all_subdomains + "," +
                self.hsts_preload_ready + "," +
                self.hsts_preloaded + "," +
                self.broken_root + "," +
                self.broken_www + "\n")




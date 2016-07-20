#!/usr/bin/python
import httplib
import urllib2

class port443:

    def __init__(self, domain, base_domain):
        self.domain = domain
        self.base_domain = base_domain
        self.canonical = ""
        self.live = False
        self.redirect = False
        self.redirect_to = ""
        self.https_bad_chain = False
        self.https_bad_hostname = False
        self.hsts = False
        self.hsts_header = ""
        self.hsts_max_age = ""
        self.hsts_all_subdomains = False
        self.hsts_preloaded = False
        self.expired_cert = False

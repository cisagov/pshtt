
class Domain:

    def __init__(self, domain):
        self.domain = domain

        # 4 endpoints for each domain.
        self.http = None
        self.httpwww = None
        self.https = None
        self.httpswww = None

        # Filled in after analyzing each endpoint.
        self.canonical = None

    def to_object(self):
        return {
            'https': self.https.to_object(),
            'httpswww': self.httpswww.to_object(),
            'http': self.http.to_object(),
            'httpwww': self.httpwww.to_object()
        }


class Endpoint:

    def __init__(self, protocol, host, base_domain):
        # Basic endpoint description
        self.protocol = protocol
        self.host = host
        self.base_domain = base_domain
        self.url = self.url_for(protocol, host, base_domain)

        # all HTTP/HTTPS endpoints have these
        self.headers = {}
        self.status = None
        self.live = False
        self.redirect = False
        self.redirect_immediately_to = None
        self.redirect_to = None

        # Only HTTPS endpoints have these.
        # Initialize all of them to None, so that it's
        # discernible if they don't get explicitly set.
        self.https_bad_chain = None
        self.https_bad_hostname = None
        self.https_expired_cert = None
        self.hsts = None
        self.hsts_header = None
        self.hsts_max_age = None
        self.hsts_all_subdomains = None
        self.hsts_preload = None
        self.hsts_preloaded = None

    def url_for(self, protocol, host, base_domain):
        if host == "root":
            prefix = ""
        elif host == "www":
            prefix = "www."

        return "%s://%s%s" % (protocol, prefix, base_domain)

    # The fields we want to serialize to JSON.
    def to_object(self):
        obj = {
            'url': self.url,
            'headers': self.headers,
            'status': self.status,
            'live': self.live,
            'redirect': self.redirect,
            'redirect_to': self.redirect_to,
            'redirect_immediately_to': self.redirect_immediately_to
        }

        if self.protocol == "https":
            obj['https_bad_chain'] = self.https_bad_chain
            obj['https_bad_hostname'] = self.https_bad_hostname
            obj['https_expired_cert'] = self.https_expired_cert
            obj['hsts'] = self.hsts
            obj['hsts_header'] = self.hsts_header
            obj['hsts_max_age'] = self.hsts_max_age
            obj['hsts_all_subdomains'] = self.hsts_all_subdomains
            obj['hsts_preload'] = self.hsts_preload

        return obj

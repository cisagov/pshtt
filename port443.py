
class port443:

    def __init__(self, endpoint, base_domain):
        self.endpoint = endpoint
        self.base_domain = base_domain
        self.headers = {}
        self.status = None
        self.live = False
        self.redirect = False
        self.redirect_immediately_to = None
        self.redirect_to = None
        self.https_bad_chain = False
        self.https_bad_hostname = False
        self.https_expired_cert = False
        self.hsts = False
        self.hsts_header = None
        self.hsts_max_age = None
        self.hsts_all_subdomains = False
        self.hsts_preload = False
        self.hsts_preloaded = False
        self.weak_signature = False

    # The fields we want to save as extended metadata.
    def to_object(self):
        return {
            'endpoint': self.endpoint,
            'headers': self.headers,
            'status': self.status,
            'live': self.live,
            'redirect': self.redirect,
            'redirect_to': self.redirect_to,
            'redirect_immediately_to': self.redirect_immediately_to,
            'https_bad_chain': self.https_bad_chain,
            'https_bad_hostname': self.https_bad_hostname,
            'https_expired_cert': self.https_expired_cert,
            'hsts': self.hsts,
            'hsts_header': self.hsts_header,
            'hsts_max_age': self.hsts_max_age,
            'hsts_all_subdomains': self.hsts_all_subdomains,
            'hsts_preload': self.hsts_preload,
            'weak_signature': self.weak_signature
        }

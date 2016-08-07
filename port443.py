
class port443:

    def __init__(self, endpoint, base_domain):
        self.endpoint = endpoint
        self.base_domain = base_domain
        self.canonical = ""
        self.live = False
        self.redirect = False
        self.redirect_to = ""
        self.https_bad_chain = False
        self.https_bad_hostname = False
        self.https_expired_cert = False
        self.hsts = False
        self.hsts_header = ""
        self.hsts_max_age = ""
        self.hsts_all_subdomains = False
        self.hsts_preload = False
        self.hsts_preloaded = False
        self.weak_signature = False

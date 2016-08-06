
class port80:

    def __init__(self, domain, base_domain):
        self.domain = domain
        self.base_domain = base_domain
        self.canonical = ""
        self.live = False
        self.redirect = False
        self.redirect_to = ""

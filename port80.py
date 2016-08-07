
class port80:

    def __init__(self, endpoint, base_domain):
        self.endpoint = endpoint
        self.base_domain = base_domain
        self.canonical = ""
        self.live = False
        self.redirect = False
        self.redirect_to = ""

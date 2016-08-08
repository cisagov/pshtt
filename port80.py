
class port80:

    def __init__(self, endpoint, base_domain):
        self.endpoint = endpoint
        self.base_domain = base_domain
        self.headers = {}
        self.status = None
        self.live = False
        self.redirect = False
        self.redirect_immediately_to = None
        self.redirect_to = None

    # The fields we want to save as extended metadata.
    def to_object(self):
        return {
            'endpoint': self.endpoint,
            'headers': self.headers,
            'status': self.status,
            'live': self.live,
            'redirect': self.redirect,
            'redirect_to': self.redirect_to,
            'redirect_immediately_to': self.redirect_immediately_to
        }


class Domain(object):

    def __init__(self, domain):
        self.domain = domain

        # 4 endpoints for each domain.
        self.http = None
        self.httpwww = None
        self.https = None
        self.httpswww = None
        self.unknown_error = False

        # Filled in after analyzing each endpoint.
        self.canonical = None

    def to_object(self):
        return {
            'https': self.https.to_object(),
            'httpswww': self.httpswww.to_object(),
            'http': self.http.to_object(),
            'httpwww': self.httpwww.to_object()
        }


class Endpoint(object):

    def __init__(self, protocol, host, base_domain):
        # Basic endpoint description
        self.protocol = protocol
        self.host = host  # "www" or "root"
        self.base_domain = base_domain
        self.url = self.url_for(protocol, host, base_domain)

        # all HTTP/HTTPS endpoints have these
        self.headers = {}  # will be replaced with a requests.structures.CaseInsensitiveDict
        self.status = None
        self.live = None
        self.ip = None
        self.redirect = None
        self.server_header = None
        self.server_version = None
        self.unknown_error = False
        self.notes = ""

        # If an endpoint redirects, characterize the redirect behavior
        self.redirect_immediately_to = None
        self.redirect_immediately_to_www = None
        self.redirect_immediately_to_https = None
        self.redirect_immediately_to_http = None
        self.redirect_immediately_to_external = None
        self.redirect_immediately_to_subdomain = None
        self.redirect_eventually_to = None
        self.redirect_eventually_to_https = None
        self.redirect_eventually_to_http = None
        self.redirect_eventually_to_external = None
        self.redirect_eventually_to_subdomain = None

        # Only HTTPS endpoints have these.
        # Initialize all of them to None, so that it's
        # discernible if they don't get explicitly set.
        self.https_full_connection = None
        self.https_client_auth_required = False
        self.https_valid = None
        self.https_public_trusted = None
        self.https_custom_trusted = None
        self.https_bad_chain = None
        self.https_bad_hostname = None
        self.https_expired_cert = None
        self.https_self_signed_cert = None
        self.https_cert_chain_len = None
        self.https_missing_intermediate_cert = None
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
            'headers': dict(self.headers),
            'status': self.status,
            'ip': self.ip,
            'live': self.live,
            'redirect': self.redirect,
            'redirect_eventually_to': self.redirect_eventually_to,
            'redirect_immediately_to': self.redirect_immediately_to,
            'redirect_immediately_to_www': self.redirect_immediately_to_www,
            'redirect_immediately_to_https': self.redirect_immediately_to_https,
            'redirect_immediately_to_http': self.redirect_immediately_to_http,
            'redirect_immediately_to_external': self.redirect_immediately_to_external,
            'redirect_immediately_to_subdomain': self.redirect_immediately_to_subdomain,
            'redirect_eventually_to_https': self.redirect_eventually_to_https,
            'redirect_eventually_to_http': self.redirect_eventually_to_http,
            'redirect_eventually_to_external': self.redirect_eventually_to_external,
            'redirect_eventually_to_subdomain': self.redirect_eventually_to_subdomain,
            'server_header': self.server_header,
            'server_version': self.server_version,
            'notes': self.notes,
            'unknown_error': self.unknown_error,
        }

        if self.protocol == "https":
            obj['https_full_connection'] = self.https_full_connection
            obj['https_client_auth_required'] = self.https_client_auth_required
            obj['https_valid'] = self.https_valid
            obj['https_public_trusted'] = self.https_public_trusted
            obj['https_custom_trusted'] = self.https_custom_trusted
            obj['https_bad_chain'] = self.https_bad_chain
            obj['https_bad_hostname'] = self.https_bad_hostname
            obj['https_expired_cert'] = self.https_expired_cert
            obj['https_self_signed_cert'] = self.https_self_signed_cert
            obj['https_cert_chain_len'] = self.https_cert_chain_len
            obj['https_missing_intermediate_cert'] = self.https_missing_intermediate_cert
            obj['hsts'] = self.hsts
            obj['hsts_header'] = self.hsts_header
            obj['hsts_max_age'] = self.hsts_max_age
            obj['hsts_all_subdomains'] = self.hsts_all_subdomains
            obj['hsts_preload'] = self.hsts_preload

        return obj

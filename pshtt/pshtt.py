#!/usr/bin/env python

import requests
# import requests_cache
import re
import base64
import json
import csv
import os
import utils
import logging

try:
    from urllib import parse as urlparse  # Python 3
except ImportError:
    import urlparse  # Python 2

import nassl
import sslyze
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin

from models import Domain, Endpoint

# We're going to be making requests with certificate validation disabled.
requests.packages.urllib3.disable_warnings()

# whether/where to cache, set via --cache
WEB_CACHE = None

# Default, overrideable via --user-agent
USER_AGENT = "pshtt, https scanning"

# Defaults to 1 second, overrideable via --timeout
TIMEOUT = 1

# The fields we're collecting, will be keys in JSON and
# column headers in CSV.
HEADERS = [
    "Domain", "Base Domain", "Canonical URL", "Live", "Redirect", "Redirect To",
    "Valid HTTPS", "Defaults to HTTPS", "Downgrades HTTPS", "Strictly Forces HTTPS",
    "HTTPS Bad Chain", "HTTPS Bad Hostname", "HTTPS Expired Cert",
    "HSTS", "HSTS Header", "HSTS Max Age", "HSTS Entire Domain",
    "HSTS Preload Ready", "HSTS Preloaded"
]

PRELOAD_CACHE = None
preload_list = None


def inspect(base_domain):
    domain = Domain(base_domain)
    domain.http = Endpoint("http", "root", base_domain)
    domain.httpwww = Endpoint("http", "www", base_domain)
    domain.https = Endpoint("https", "root", base_domain)
    domain.httpswww = Endpoint("https", "www", base_domain)

    # Analyze HTTP endpoint responsiveness and behavior.
    basic_check(domain.http)
    basic_check(domain.httpwww)
    basic_check(domain.https)
    basic_check(domain.httpswww)

    # Analyze HSTS header, if present, on each HTTPS endpoint.
    hsts_check(domain.https)
    hsts_check(domain.httpswww)

    return result_for(domain)


def result_for(domain):

    # print(utils.json_for(domain.to_object()))

    # Because it will inform many other judgments, first identify
    # an acceptable "canonical" URL for the domain.
    domain.canonical = canonical_endpoint(domain.http, domain.httpwww, domain.https, domain.httpswww)

    # First, the basic fields the CSV will use.
    result = {
        'Domain': domain.domain,
        'Base Domain': parent_domain_for(domain.domain),
        'Canonical URL': domain.canonical.url,
        'Live': is_live(domain),
        'Redirect': is_redirect(domain),
        'Redirect To': redirects_to(domain),

        'Valid HTTPS': is_valid_https(domain),
        'Defaults to HTTPS': is_defaults_to_https(domain),
        'Downgrades HTTPS': is_downgrades_https(domain),
        'Strictly Forces HTTPS': is_strictly_forces_https(domain),

        'HTTPS Bad Chain': is_bad_chain(domain),
        'HTTPS Bad Hostname': is_bad_hostname(domain),
        'HTTPS Expired Cert': is_expired_cert(domain),

        'HSTS': is_hsts(domain),
        'HSTS Header': hsts_header(domain),
        'HSTS Max Age': hsts_max_age(domain),
        'HSTS Entire Domain': is_hsts_entire_domain(domain),
        'HSTS Preload Ready': is_hsts_preload_ready(domain),
        'HSTS Preloaded': is_hsts_preloaded(domain)
    }

    # But also capture the extended data for those who want it.
    result['endpoints'] = domain.to_object()

    return result


def ping(url, allow_redirects=False, verify=True):
    return requests.get(
        url,

        allow_redirects=allow_redirects,

        # Validate certificates.
        verify=verify,

        # set by --user_agent
        headers={'User-Agent': USER_AGENT},

        # set by --timeout
        timeout=TIMEOUT
    )


def basic_check(endpoint):
    logging.debug("pinging %s..." % endpoint.url)

    # Test the endpoint. At first:
    #
    # * Don't follow redirects. (Will only follow if necessary.)
    #   If it's a 3XX, we'll ping again to follow redirects. This is
    #   necessary to reliably scope any errors (e.g. TLS errors) to
    #   the original endpoint.
    #
    # * Validate certificates. (Will figure out error if necessary.)
    try:

        req = ping(endpoint.url)

        endpoint.live = True
        if endpoint.protocol == "https":
            endpoint.https_valid = True

    except requests.exceptions.SSLError:
        # Retry with certificate validation disabled.
        try:
            req = ping(endpoint.url, verify=False)
        except requests.exceptions.SSLError:
            # If it's a protocol error or other, it's not live.
            endpoint.live = False
            logging.warn("Unexpected SSL protocol (or other) error during retry.")
            return
        except requests.exceptions.RequestException:
            endpoint.live = False
            logging.warn("Unexpected requests exception during retry. Printing error:")
            logging.warn(utils.format_last_exception())
            return

        # If it was a certificate error of any kind, it's live.
        endpoint.live = True

        # Figure out the error(s).
        https_check(endpoint)

    except requests.exceptions.ConnectionError:
        endpoint.live = False
        logging.warn("Failed to connect.")
        return

    # And this is the parent of ConnectionError and other things.
    # For example, "too many redirects".
    # See https://github.com/kennethreitz/requests/blob/master/requests/exceptions.py
    except requests.exceptions.RequestException:
        endpoint.live = False
        logging.warn("Unexpected other requests exception.")
        return

    # Endpoint is live, analyze the response.
    endpoint.headers = req.headers

    endpoint.status = req.status_code
    if str(endpoint.status).startswith('3'):
        endpoint.redirect = True

    if endpoint.redirect:

        location_header = req.headers.get('Location')
        # Absolute redirects (e.g. "https://example.com/Index.aspx")
        if location_header.startswith("http:") or location_header.startswith("https:"):
            immediate = location_header

        # Relative redirects (e.g. "Location: /Index.aspx").
        # Construct absolute URI, relative to original request.
        else:
            immediate = urlparse.urljoin(endpoint.url, location_header)

        # Chase down the ultimate destination, ignoring any certificate warnings.
        ultimate_req = None
        try:
            ultimate_req = ping(endpoint.url, allow_redirects=True, verify=False)
        except requests.exceptions.RequestException:
            # Swallow connection errors, but we won't be saving redirect info.
            pass

        # Now establish whether the redirects were:
        # * internal (same exact hostname),
        # * within the zone (any subdomain within the parent domain)
        # * external (on some other parent domain)

        # The hostname of the endpoint (e.g. "www.agency.gov")
        subdomain_original = urlparse.urlparse(endpoint.url).hostname
        # The parent domain of the endpoint (e.g. "agency.gov")
        base_original = parent_domain_for(subdomain_original)

        # The hostname of the immediate redirect.
        # The parent domain of the immediate redirect.
        subdomain_immediate = urlparse.urlparse(immediate).hostname
        base_immediate = parent_domain_for(subdomain_immediate)

        endpoint.redirect_immediately_to = immediate
        endpoint.redirect_immediately_to_www = re.match(r'^https?://www\.', immediate)
        endpoint.redirect_immediately_to_https = immediate.startswith("https://")
        endpoint.redirect_immediately_to_http = immediate.startswith("http://")
        endpoint.redirect_immediately_to_external = (base_original != base_immediate)
        endpoint.redirect_immediately_to_subdomain = (
            (base_original == base_immediate) and
            (subdomain_original != subdomain_immediate)
        )

        if ultimate_req is not None:
            # For ultimate destination, use the URL we arrived at,
            # not Location header. Auto-resolves relative redirects.
            eventual = ultimate_req.url

            # The hostname of the eventual destination.
            # The parent domain of the eventual destination.
            subdomain_eventual = urlparse.urlparse(eventual).hostname
            base_eventual = parent_domain_for(subdomain_eventual)

            endpoint.redirect_eventually_to = eventual
            endpoint.redirect_eventually_to_https = eventual.startswith("https://")
            endpoint.redirect_eventually_to_http = eventual.startswith("http://")
            endpoint.redirect_eventually_to_external = (base_original != base_eventual)
            endpoint.redirect_eventually_to_subdomain = (
                (base_original == base_eventual) and
                (subdomain_original != subdomain_eventual)
            )


# Given an endpoint and its detected headers, extract and parse
# any present HSTS header, decide what HSTS properties are there.
def hsts_check(endpoint):
    # Disqualify domains with a bad host, they won't work as valid HSTS.
    if endpoint.https_bad_hostname:
        endpoint.hsts = False
        return

    header = endpoint.headers.get("Strict-Transport-Security")

    if header is None:
        endpoint.hsts = False
        return

    endpoint.hsts = True
    endpoint.hsts_header = header

    # Set max age to the string after max-age
    # TODO: make this more resilient to pathological HSTS headers.

    # handle multiple HSTS headers, requests comma-separates them
    first_pass = re.split(',\s?', header)[0]
    second_pass = re.sub('\'', '', first_pass)

    temp = re.split(';\s?', second_pass)

    if "max-age" in header.lower():
        endpoint.hsts_max_age = int(temp[0][len("max-age="):])

    if endpoint.hsts_max_age <= 0:
        endpoint.hsts = False
        return

    # check if hsts includes sub domains
    if 'includesubdomains' in header.lower():
        endpoint.hsts_all_subdomains = True

    # Check is hsts has the preload flag
    if 'preload' in header.lower():
        endpoint.hsts_preload = True


# Uses sslyze to figure out the reason the endpoint wouldn't verify.
def https_check(endpoint):
    logging.debug("sslyzing %s..." % endpoint.url)

    # remove the https:// from prefix for sslyze
    hostname = endpoint.url[8:]
    server_info = ServerConnectivityInfo(hostname=hostname, port=443)

    try:
        server_info.test_connectivity_to_server()
    except sslyze.server_connectivity.ServerConnectivityError:
        logging.warn("Error in sslyze server connectivity check")
        return

    cert_plugin = CertificateInfoPlugin()
    try:
        cert_plugin_result = cert_plugin.process_task(server_info, 'certinfo_basic')
    except nassl._nassl.OpenSSLError:
        logging.warn("Error in sslyze cert info plugin")
        return
    except nassl.x509_certificate.X509HostnameValidationError:
        logging.warn("Error parsing x.509 certificate.")
        return

    try:
        cert_response = cert_plugin_result.as_text()
    except TypeError:
        logging.warn("sslyze exception parsing issuer, see https://github.com/nabla-c0d3/sslyze/issues/167")
        return

    # Debugging
    # for msg in cert_response:
    #     print(msg)

    # A certificate can have multiple issues.
    for msg in cert_response:

        # Check for certificate expiration.
        if (
            (("Mozilla NSS CA Store") in msg) and
            (("FAILED") in msg) and
            (("certificate has expired") in msg)
        ):
            endpoint.https_expired_cert = True

        # Check for whether there's a valid chain to Mozilla.
        # Note: this will also catch expired certs, but this is okay.
        if (
            (("Mozilla NSS CA Store") in msg) and
            (("FAILED") in msg) and
            (("Certificate is NOT Trusted") in msg)
        ):
            endpoint.https_bad_chain = True

        # Check for whether the hostname validates.
        if (
            (("Hostname Validation") in msg) and
            (("FAILED") in msg) and
            (("Certificate does NOT match") in msg)
        ):
            endpoint.https_bad_hostname = True


##
# Given behavior for the 4 endpoints, make a best guess
# as to which is the "canonical" site for the domain.
#
# Most of the domain-level decisions rely on this guess in some way.
##
def canonical_endpoint(http, httpwww, https, httpswww):

    # A domain is "canonically" at www if:
    #  * at least one of its www endpoints responds
    #  * both root endpoints are either down or redirect *somewhere*
    #  * either both root endpoints are down, *or* at least one
    #    root endpoint redirect should immediately go to
    #    an *internal* www endpoint
    # This is meant to affirm situations like:
    #   http:// -> https:// -> https://www
    #   https:// -> http:// -> https://www
    # and meant to avoid affirming situations like:
    #   http:// -> http://non-www,
    #   http://www -> http://non-www
    # or like:
    #   https:// -> 200, http:// -> http://www

    at_least_one_www_used = httpswww.live or httpwww.live

    def root_unused(endpoint):
        return (
            endpoint.redirect or
            (not endpoint.live) or
            endpoint.https_bad_hostname or  # harmless for http endpoints
            (not str(endpoint.status).startswith("2"))
        )

    def root_down(endpoint):
        return (
            (not endpoint.live) or
            endpoint.https_bad_hostname or
            (not str(endpoint.status).startswith("2"))
        )

    def goes_to_www(endpoint):
        return (
            endpoint.redirect_immediately_to_www and
            (not endpoint.redirect_immediately_to_external)
        )

    all_roots_unused = root_unused(https) and root_unused(http)

    all_roots_down = root_down(https) and root_down(http)

    is_www = (
        at_least_one_www_used and
        all_roots_unused and (
            all_roots_down or
            goes_to_www(https) or
            goes_to_www(http)
        )
    )

    # A domain is "canonically" at https if:
    #  * at least one of its https endpoints is live and
    #    doesn't have an invalid hostname
    #  * both http endpoints are either down or redirect *somewhere*
    #  * at least one http endpoint redirects immediately to
    #    an *internal* https endpoint
    # This is meant to affirm situations like:
    #   http:// -> http://www -> https://
    #   https:// -> http:// -> https://www
    # and meant to avoid affirming situations like:
    #   http:// -> http://non-www
    #   http://www -> http://non-www
    # or:
    #   http:// -> 200, http://www -> https://www
    #
    # It allows a site to be canonically HTTPS if the cert has
    # a valid hostname but invalid chain issues.

    def https_used(endpoint):
        return endpoint.live and (not endpoint.https_bad_hostname)

    def http_unused(endpoint):
        return (
            endpoint.redirect or
            (not endpoint.live) or
            (not str(endpoint.status).startswith("2"))
        )

    def http_upgrades(endpoint):
        return (
            endpoint.redirect_immediately_to_https and
            (not endpoint.redirect_immediately_to_external)
        )

    at_least_one_https_endpoint = https_used(https) or https_used(httpswww)
    all_http_unused = http_unused(http) and http_unused(httpwww)
    at_least_one_http_upgrades = http_upgrades(http) or http_upgrades(httpwww)

    is_https = (
        at_least_one_https_endpoint and
        all_http_unused and
        at_least_one_http_upgrades
    )

    if is_www and is_https:
        return httpswww
    elif is_www and (not is_https):
        return httpwww
    elif (not is_www) and is_https:
        return https
    elif (not is_www) and (not is_https):
        return http


##
# Judgment calls based on observed endpoint data.
##


# Domain is "live" if *any* endpoint is live.
def is_live(domain):
    http, httpwww, https, httpswww = domain.http, domain.httpwww, domain.https, domain.httpswww

    return http.live or httpwww.live or https.live or httpswww.live


# Domain is "a redirect domain" if at least one endpoint is
# a redirect, and all endpoints are either redirects or down.
def is_redirect(domain):
    http, httpwww, https, httpswww = domain.http, domain.httpwww, domain.https, domain.httpswww

    # TODO: make sub-function of the conditional below.
    # def is_redirect_or_down(endpoint):

    return is_live(domain) and (
        (
            https.redirect_eventually_to_external or
            (not https.live) or
            https.https_bad_hostname or
            https.status >= 400
        ) and
        (
            httpswww.redirect_eventually_to_external or
            (not httpswww.live) or
            httpswww.https_bad_hostname or
            httpswww.status >= 400
        ) and
        (
            httpwww.redirect_eventually_to_external or
            (not httpwww.live) or
            httpwww.status >= 400
        ) and
        (
            http.redirect_eventually_to_external or
            (not http.live) or
            http.status >= 400
        ))


# If a domain is a "redirect domain", where does it redirect to?
def redirects_to(domain):
    canonical = domain.canonical

    if is_redirect(domain):
        return canonical.redirect_eventually_to
    else:
        return None


# A domain has "valid HTTPS" if it responds on port 443 at its canonical
# hostname with an unexpired valid certificate for the hostname.
def is_valid_https(domain):
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    # Evaluate the HTTPS version of the canonical hostname
    if canonical.host == "root":
        evaluate = https
    else:
        evaluate = httpswww

    return evaluate.live and evaluate.https_valid


# A domain "defaults to HTTPS" if its canonical endpoint uses HTTPS.
def is_defaults_to_https(domain):
    canonical = domain.canonical

    return (canonical.protocol == "https")


# Domain downgrades if HTTPS is supported in some way, but
# its canonical HTTPS endpoint immediately redirects internally to HTTP.
def is_downgrades_https(domain):
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    # The domain "supports" HTTPS if any HTTPS endpoint responds with
    # a certificate valid for its hostname.
    supports_https = (
        https.live and (not https.https_bad_hostname)
    ) or (
        httpswww.live and (not httpswww.https_bad_hostname)
    )

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return (
        supports_https and
        canonical_https.redirect_immediately_to_http and
        (not canonical_https.redirect_immediately_to_external)
    )


# A domain "Strictly Forces HTTPS" if one of the HTTPS endpoints is
# "live", and if both *HTTP* endpoints are either:
#
#  * down, or
#  * redirect immediately to an HTTPS URI.
#
# This is different than whether a domain "Defaults" to HTTPS.
#
# * An HTTP redirect can go to HTTPS on another domain, as long
#   as it's immediate.
# * A domain with an invalid cert can still be enforcing HTTPS.
def is_strictly_forces_https(domain):
    http, httpwww, https, httpswww = domain.http, domain.httpwww, domain.https, domain.httpswww

    def down_or_redirects(endpoint):
        return ((not endpoint.live) or endpoint.redirect_immediately_to_https)

    https_somewhere = https.live or httpswww.live
    all_http_unused = down_or_redirects(http) and down_or_redirects(httpwww)

    return https_somewhere and all_http_unused


# Domain has a bad chain if either https endpoints contain a bad chain
def is_bad_chain(domain):
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.https_bad_chain


# Domain has a bad hostname if either https endpoint fails hostname validation
def is_bad_hostname(domain):
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.https_bad_hostname


# Returns if the either https endpoint has an expired cert
def is_expired_cert(domain):
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.https_expired_cert


# Domain has HSTS if its canonical HTTPS endpoint has HSTS.
def is_hsts(domain):
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.hsts


# Domain's HSTS header is its canonical endpoint's header.
def hsts_header(domain):
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.hsts_header


# Domain's HSTS max-age is its canonical endpoint's max-age.
def hsts_max_age(domain):
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.hsts_max_age


# Whether a domain's ROOT endpoint includes all subdomains.
def is_hsts_entire_domain(domain):
    https = domain.https

    return https.hsts_all_subdomains


# Whether a domain's ROOT endpoint is preload-ready.
def is_hsts_preload_ready(domain):
    https = domain.https

    eighteen_weeks = ((https.hsts_max_age is not None) and (https.hsts_max_age >= 10886400))
    preload_ready = (eighteen_weeks and https.hsts_all_subdomains and https.hsts_preload)

    return preload_ready


# Whether a domain is contained in Chrome's HSTS preload list.
def is_hsts_preloaded(domain):
    return domain.domain in preload_list


# For "x.y.domain.gov", return "domain.gov".
# TODO: use Public Suffix list to do this properly.
def parent_domain_for(hostname):
    return str.join(".", hostname.split(".")[-2:])


def create_preload_list():
    preload_json = None

    if PRELOAD_CACHE and os.path.exists(PRELOAD_CACHE):
        logging.debug("Using cached Chrome preload list.")
        preload_json = json.loads(open(PRELOAD_CACHE).read())
    else:
        logging.debug("Fetching Chrome preload list from source...")

        # Downloads the chromium preloaded domain list and sets it to a global set
        file_url = 'https://chromium.googlesource.com/chromium/src/net/+/master/http/transport_security_state_static.json?format=TEXT'

        # TODO: proper try/except around this network request
        request = requests.get(file_url)
        raw = request.content

        # To avoid parsing the contents of the file out of the source tree viewer's
        # HTML, we download it as a raw file. googlesource.com Base64-encodes the
        # file to avoid potential content injection issues, so we need to decode it
        # before using it. https://code.google.com/p/gitiles/issues/detail?id=7
        raw = base64.b64decode(raw).decode('utf-8')

        # The .json file contains '//' comments, which are not actually valid JSON,
        # and confuse Python's JSON decoder. Begone, foul comments!
        raw = ''.join([re.sub(r'^\s*//.*$', '', line)
                       for line in raw.splitlines()])

        preload_json = json.loads(raw)

        if PRELOAD_CACHE:
            logging.debug("Caching preload list at %s" % PRELOAD_CACHE)
            utils.write(utils.json_for(preload_json), PRELOAD_CACHE)

    # For our purposes, we only care about entries that includeSubDomains
    fully_preloaded = []
    for entry in preload_json['entries']:
        if entry.get('include_subdomains', False) is True:
            fully_preloaded.append(entry['name'])

    return fully_preloaded


# Output a CSV string for an array of results, with a
# header row, and with header fields in the desired order.
def csv_for(results, out_filename):
    out_file = open(out_filename, 'w')
    writer = csv.writer(out_file)

    writer.writerow(HEADERS)

    for result in results:
        row = []
        for header in HEADERS:
            if (header != "HSTS Header") and (header != "HSTS Max Age") and (header != "Redirect To"):
                if result[header] is None:
                    result[header] = False
            row.append(result[header])
        writer.writerow(row)

    out_file.close()


def inspect_domains(domains, options):
    # Override timeout, user agent, preload cache.
    global TIMEOUT, USER_AGENT, PRELOAD_CACHE, WEB_CACHE
    if options.get('timeout'):
        TIMEOUT = int(options['timeout'])
    if options.get('user_agent'):
        USER_AGENT = options['user_agent']
    if options.get('preload_cache'):
        PRELOAD_CACHE = options['preload_cache']
    if options.get('cache'):
        # TODO: requests-cache has a blocking bug for us, now
        # that we're tweaking allow_redirects and verify parameters.
        # Caching disabled until bug is fixed, or routed around.
        #
        # https://github.com/reclosedev/requests-cache/issues/70
        #
        # cache_dir = ".cache"
        # utils.mkdir_p(cache_dir)
        # requests_cache.install_cache("%s/cache" % cache_dir)
        logging.warn("WARNING: Caching disabled.")

    # Download HSTS preload list, caches locally.
    global preload_list
    preload_list = create_preload_list()

    # For every given domain, get inspect data.
    results = []
    for domain in domains:
        results.append(inspect(domain))

    return results

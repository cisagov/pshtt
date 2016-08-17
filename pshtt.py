#!/usr/bin/env python

import requests
import requests_cache
import re
import datetime
from time import strptime
import base64
import json
import csv
import os
import utils
import logging

try:
    from urllib import parse as urlparse # Python 3
except ImportError:
    import urlparse # Python 2

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
    "Domain", "Canonical URL", "Live", "Redirect",
    "Valid HTTPS", "Defaults HTTPS", "Downgrades HTTPS",
    "Strictly Forces HTTPS", "HTTPS Bad Chain", "HTTPS Bad Host Name",
    "Expired Cert", "HSTS", "HSTS Header",
    "HSTS Max Age", "HSTS All Subdomains", "HSTS Preload",
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
    canonical = canonical_endpoint(domain.http, domain.httpwww, domain.https, domain.httpswww)

    # First, the basic fields the CSV will use.
    result = {
        'Domain': domain.domain,
        'Canonical URL': canonical.url,
        'Live': is_live(domain.http, domain.httpwww, domain.https, domain.httpswww),
        'Redirect': is_redirect(domain.http, domain.httpwww, domain.https, domain.httpswww),
        'Valid HTTPS': is_valid_https(domain.http, domain.httpwww, domain.https, domain.httpswww),
        'Defaults HTTPS': is_defaults_to_https(domain.http, domain.httpwww, domain.https, domain.httpswww),
        'Downgrades HTTPS': is_downgrades_https(domain.http, domain.httpwww, domain.https, domain.httpswww),
        'Strictly Forces HTTPS': is_strictly_forces_https(domain.http, domain.httpwww, domain.https, domain.httpswww),
        'HTTPS Bad Chain': is_bad_chain(domain.http, domain.httpwww, domain.https, domain.httpswww),
        'HTTPS Bad Host Name': is_bad_hostname(domain.http, domain.httpwww, domain.https, domain.httpswww),
        'Expired Cert': is_expired_cert(domain.http, domain.httpwww, domain.https, domain.httpswww),
        'HSTS': is_hsts(domain.http, domain.httpwww, domain.https, domain.httpswww),
        'HSTS Header': hsts_header(domain.http, domain.httpwww, domain.https, domain.httpswww),
        'HSTS Max Age': hsts_max_age(domain.http, domain.httpwww, domain.https, domain.httpswww),
        'HSTS All Subdomains': is_hsts_all_subdomains(domain.http, domain.httpwww, domain.https, domain.httpswww),
        'HSTS Preload': is_hsts_preload(domain.http, domain.httpwww, domain.https, domain.httpswww),
        'HSTS Preload Ready': is_hsts_preload_ready(domain.http, domain.httpwww, domain.https, domain.httpswww),

        # Doesn't use endpoint behavior.
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
        data={'User-Agent': USER_AGENT},

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

    except requests.exceptions.SSLError:
        # Retry with certificate validation disabled.
        try:
            req = ping(endpoint.url, verify=False)
        except requests.exceptions.SSLError:
            # If it's a protocol error or other, it's not live.
            endpoint.live = False
            return

        # If it was a certificate error of any kind, it's live.
        # Figure out the error(s).
        https_check(endpoint)

    # This needs to go last, as a parent error class.
    except requests.exceptions.ConnectionError:
        endpoint.live = False
        return


    # Endpoint is live, analyze the response.
    endpoint.live = True
    endpoint.headers = dict(req.headers)

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
        # TODO: try/except block on this request, and have checks expect possible None.
        ultimate_req = ping(endpoint.url, allow_redirects=True, verify=False)

        # For ultimate destination, use the URL we arrived at,
        # not Location header. Auto-resolves relative redirects.
        eventual = ultimate_req.url

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

        # The hostname of the eventual destination.
        # The parent domain of the eventual destination.
        subdomain_eventual = urlparse.urlparse(eventual).hostname
        base_eventual = parent_domain_for(subdomain_eventual)


        endpoint.redirect_immediately_to = immediate
        endpoint.redirect_immediately_to_www = re.match(r'^https?://www\.', immediate)
        endpoint.redirect_immediately_to_https = immediate.startswith("https://")
        endpoint.redirect_immediately_to_external = (base_original != base_immediate)
        endpoint.redirect_immediately_to_subdomain = (
            (base_original == base_immediate) and
            (subdomain_original != subdomain_immediate)
        )

        endpoint.redirect_eventually_to = eventual
        endpoint.redirect_eventually_to_https = eventual.startswith("https://")
        endpoint.redirect_eventually_to_external = (base_original != base_eventual)
        endpoint.redirect_eventually_to_subdomain = (
            (base_original == base_eventual) and
            (subdomain_original != subdomain_eventual)
        )


# Given an endpoint and its detected headers, extract and parse
# any present HSTS header, decide what HSTS properties are there.
def hsts_check(endpoint):
    header = endpoint.headers.get("Strict-Transport-Security")

    if header is None:
        endpoint.hsts = False
        return

    endpoint.hsts = True
    endpoint.hsts_header = header

    # Set max age to the string after max-age
    temp = header.split()
    endpoint.hsts_max_age = temp[0][len("max-age="):]

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
    server_info.test_connectivity_to_server()

    cert_plugin = CertificateInfoPlugin()
    cert_plugin_result = cert_plugin.process_task(server_info, 'certinfo_basic')

    # A certificate can have multiple issues.
    for msg in cert_plugin_result.as_text():

        # Check for certifcate expiration.
        if (
            (("Mozilla NSS CA Store") in msg) and
            (("FAILED") in msg) and
            (("certificate has expired") in msg)
            ):
            endpoint.https_expired_cert = True

        # Check for whether there's a valid chain to Mozilla.
        if (
            (("Mozilla NSS CA Store") in msg) and
            (("FAILED") in msg) and
            (("unable to get local issuer certificate") in msg)
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

    is_www = (
      (
        httpswww.live or httpwww.live
      ) and (
        (
          https.redirect or
          (not https.live) or
          https.https_bad_hostname or
          (not str(https.status).startswith("2"))
        ) and (
          http.redirect or
          (not http.live) or
          (not str(http.status).startswith("2"))
        )
      ) and (
        (
          (
            (not https.live) or
            https.https_bad_hostname or
            (not str(https.status).startswith("2"))
          ) and
          (
            (not http.live) or
            (not str(http.status).startswith("2"))
          )
        ) or
        (
          https.redirect_immediately_to_www and
          (not https.redirect_immediately_to_external)
        ) or
        (
          http.redirect_immediately_to_www and
          (not http.redirect_immediately_to_external)
        )
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

    is_https = (
      (
        (https.live and (not https.https_bad_hostname)) or
        (httpswww.live and (not https.https_bad_hostname))
      ) and (
        (
          http.redirect or
          (not http.live) or
          (not str(http.status).startswith("2"))
        ) and (
          httpwww.redirect or
          (not httpwww.live) or
          (not str(httpwww.status).startswith("2"))
        )
      ) and (
        (
          http.redirect_immediately_to_https and
          (not http.redirect_immediately_to_external)
        ) or (
          httpwww.redirect_immediately_to_https and
          (not httpwww.redirect_immediately_to_external)
        )
      )
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


# Domain is live if *any* endpoint is live.
def is_live(http, httpwww, https, httpswww):
    return http.live or httpwww.live or https.live or httpswww.live


# TODO: Loosen this definition to check if:
# at least one endpoint is a redirect, and
# all endpoints are either redirects or down.
def is_redirect(http, httpwww, https, httpswww):
    return http.redirect or httpwww.redirect or https.redirect or httpswww.redirect


def is_valid_https(http, httpwww, https, httpswww):
    # One of the HTTPS endpoints has to be up,
    # and has to have a cert for a valid hostname,
    # and has to not downgrade the user to HTTP (either doesn't redirect, or if it does redirect it stays at HTTPS).
    # TODO: only evaluate canonical endpoint.

    def supports_https(endpoint):
        return endpoint.live and \
            (not endpoint.https_bad_hostname) and \
            (not (endpoint.redirect and (endpoint.redirect_immediately_to[:5] != "https")))

    return supports_https(https) or supports_https(httpswww)


# Domain defaults to https if http endpoint forwards to https
def is_defaults_to_https(http, httpwww, https, httpswww):
    if http.redirect or httpwww.redirect:
        return (http.redirect and (http.redirect_eventually_to[:5] == "https")) or (httpwww.redirect and (httpwww.redirect_eventually_to[:5] == "https"))
    else:
        return False


# Domain downgrades if https endpoint redirects to http
def is_downgrades_https(http, httpwww, https, httpswww):
    return (https.redirect and (https.redirect_eventually_to[:5] == "http:")) or (httpswww.redirect and (httpswww.redirect_eventually_to[:5] == "http:"))


# A domain strictly forces https if https is live and http is not,
# if both http forward to https endpoints or if one http forwards to https and the other is not live
def is_strictly_forces_https(http, httpwww, https, httpswww):
    if ((not http.live) and (not httpwww.live)) and (https.live or httpswww.live):
        return True
    elif (http.redirect and (http.redirect_eventually_to[:5] == "https")) and (httpwww.redirect and (httpwww.redirect_eventually_to[:5] == "https")):
        return True
    elif (http.redirect and (http.redirect_eventually_to[:5] == "https")) and (not httpwww.live):
        return True
    elif (httpwww.redirect and (httpwww.redirect_eventually_to[:5] == "https")) and (not http.live):
        return True
    else:
        return False


# Domain has a bad chain if either https endpoints contain a bad chain
def is_bad_chain(http, httpwww, https, httpswww):
    return https.https_bad_chain or httpswww.https_bad_chain


# Domain has a bad hostname if either https endpoint fails hostname validation
def is_bad_hostname(http, httpwww, https, httpswww):
    return https.https_bad_hostname or httpswww.https_bad_hostname


# Domain has hsts ONLY if the https (and not the www subdomain) has strict transport in the header
def is_hsts(http, httpwww, https, httpswww):
    return https.hsts


def hsts_header(http, httpwww, https, httpswww):
    if https.hsts:
        return https.hsts_header
    else:
        return None


def hsts_max_age(http, httpwww, https, httpswww):
    if https.hsts:
        return https.hsts_max_age
    else:
        return None


def is_hsts_all_subdomains(http, httpwww, https, httpswww):
    # Returns if the https endpoint has "includesubdomains"
    return https.hsts_all_subdomains


def is_hsts_preload_ready(http, httpwww, https, httpswww):
    # returns if the hsts header exists, has a max age, includes subdomains, and includes preload
    return (https.hsts and https.hsts_max_age != "" and https.hsts_all_subdomains and https.hsts_preload)


def is_hsts_preload(http, httpwww, https, httpswww):
    # Returns if https endpoint has preload in hsts header
    return https.hsts_preload


def is_expired_cert(http, httpwww, https, httpswww):
    # Returns if the either https endpoint has an expired cert
    return https.https_expired_cert or httpswww.https_expired_cert


def is_hsts_preloaded(domain):
    # Returns if a domain is on the Chromium preload list
    return domain in preload_list


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

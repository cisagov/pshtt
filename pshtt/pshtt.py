#!/usr/bin/env python

from . import utils
from .models import Domain, Endpoint
from publicsuffix import PublicSuffixList
from publicsuffix import fetch

import requests
import re
import base64
import json
import os
import logging
import sys
import codecs
import OpenSSL

try:
    from urllib import parse as urlparse  # Python 3
except ImportError:
    import urlparse  # Python 2

try:
    from urllib.error import URLError
except ImportError:
    from urllib2 import URLError

import sslyze
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError
import sslyze.synchronous_scanner

# We're going to be making requests with certificate validation disabled.
requests.packages.urllib3.disable_warnings()

# Default, overrideable via --user-agent
USER_AGENT = "pshtt, https scanning"

# Defaults to 10 second, overrideable via --timeout
TIMEOUT = 10

# The fields we're collecting, will be keys in JSON and
# column headers in CSV.
HEADERS = [
    "Domain", "Base Domain", "Canonical URL", "Live", "Redirect", "Redirect To",
    "Valid HTTPS", "Defaults to HTTPS", "Downgrades HTTPS", "Strictly Forces HTTPS",
    "HTTPS Bad Chain", "HTTPS Bad Hostname", "HTTPS Expired Cert",
    "HTTPS Self Signed Cert",
    "HSTS", "HSTS Header", "HSTS Max Age", "HSTS Entire Domain",
    "HSTS Preload Ready", "HSTS Preload Pending", "HSTS Preloaded",
    "Base Domain HSTS Preloaded", "Domain Supports HTTPS",
    "Domain Enforces HTTPS", "Domain Uses Strong HSTS", "Unknown Error",
]

# Used for caching the HSTS preload list from Chromium's source.
cache_preload_list_default = "preloaded.json"
preload_list = None

# Used for caching the HSTS pending preload list from hstspreload.org.
cache_preload_pending_default = "preload-pending.json"
preload_pending = None

# Used for determining base domain via Mozilla's public suffix list.
cache_suffix_list_default = "public-suffix-list.txt"
suffix_list = None

# Directory to cache all third party responses, if set by user.
THIRD_PARTIES_CACHE = None

# Set if user wants to use a custom CA bundle
CA_FILE = None
STORE = "Mozilla"


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
        'HTTPS Self Signed Cert': is_self_signed_cert(domain),

        'HSTS': is_hsts(domain),
        'HSTS Header': hsts_header(domain),
        'HSTS Max Age': hsts_max_age(domain),
        'HSTS Entire Domain': is_hsts_entire_domain(domain),
        'HSTS Preload Ready': is_hsts_preload_ready(domain),
        'HSTS Preload Pending': is_hsts_preload_pending(domain),
        'HSTS Preloaded': is_hsts_preloaded(domain),
        'Base Domain HSTS Preloaded': is_parent_hsts_preloaded(domain),

        'Domain Supports HTTPS': is_domain_supports_https(domain),
        'Domain Enforces HTTPS': is_domain_enforces_https(domain),
        'Domain Uses Strong HSTS': is_domain_strong_hsts(domain),

        'Unknown Error': did_domain_error(domain),
    }

    # But also capture the extended data for those who want it.
    result['endpoints'] = domain.to_object()

    # Convert Header fields from None to False, except for:
    # - "HSTS Header"
    # - "HSTS Max Age"
    # - "Redirect To"
    for header in HEADERS:
        if header in ("HSTS Header", "HSTS Max Age", "Redirect To"):
            continue

        if result[header] is None:
            result[header] = False

    return result


def ping(url, allow_redirects=False, verify=True):
    """
    If there is a custom CA file and we want to verify
    use that instead when pinging with requests

    By changing the verify param from a boolean to a .pem file, the
    requests module will use the .pem to validate HTTPS connections.

    Note that we are using the streaming variant of the
    python-requests library here and we are not actually reading the
    content of the request.  As a result, the close() method MUST be
    called on the Request object returned by this method.  That is the
    ONLY way the connection can be closed and released back into the
    pool.  One way to ensure this happens is to use the "with" Python
    construct.

    If we ever begin reading response bodies, they will need to be
    explicitly read from Response.content, and we will also want to
    use conditional logic to read from response bodies where they
    exist and are useful. We'll also need to watch for Content-Type
    values like multipart/x-mixed-replace;boundary=ffserver that
    indicate that the response body will stream indefinitely.
    """
    if CA_FILE and verify:
        verify = CA_FILE

    return requests.get(
        url,

        allow_redirects=allow_redirects,

        # Validate certificates.
        verify=verify,

        # Setting this to true delays the retrieval of the content
        # until we access Response.content.  Since we aren't
        # interested in the actual content of the request, this will
        # save us time and bandwidth.
        #
        # This will also stop pshtt from hanging on URLs that stream
        # neverending data, like webcams.  See issue #138:
        # https://github.com/dhs-ncats/pshtt/issues/138
        stream=True,

        # set by --user_agent
        headers={'User-Agent': USER_AGENT},

        # set by --timeout
        timeout=TIMEOUT
    )


def basic_check(endpoint):
    """
    Test the endpoint. At first:

    * Don't follow redirects. (Will only follow if necessary.)
      If it's a 3XX, we'll ping again to follow redirects. This is
      necessary to reliably scope any errors (e.g. TLS errors) to
      the original endpoint.

    * Validate certificates. (Will figure out error if necessary.)
    """

    utils.debug("Pinging %s..." % endpoint.url, divider=True)

    try:
        with ping(endpoint.url) as req:
            endpoint.live = True
            if endpoint.protocol == "https":
                endpoint.https_valid = True

    except requests.exceptions.SSLError as err:
        logging.warn("Error validating certificate.")
        utils.debug("{0}".format(err))

        # Retry with certificate validation disabled.
        try:
            with ping(endpoint.url, verify=False) as req:
                pass
        except requests.exceptions.SSLError as err:
            # If it's a protocol error or other, it's not live.
            endpoint.live = False
            logging.warn("Unexpected SSL protocol (or other) error during retry.")
            utils.debug("{0}".format(err))
            return
        except requests.exceptions.RequestException as err:
            endpoint.live = False
            logging.warn("Unexpected requests exception during retry.")
            utils.debug("{0}".format(err))
            return
        except OpenSSL.SSL.Error as err:
            endpoint.live = False
            logging.warn("Unexpected OpenSSL exception during retry.")
            utils.debug("{0}".format(err))
            return
        except Exception as err:
            endpoint.unknown_error = True
            logging.warn("Unexpected other unknown exception during requests retry.")
            utils.debug("{0}".format(err))
            return

        # If it was a certificate error of any kind, it's live.
        endpoint.live = True

        # Figure out the error(s).
        https_check(endpoint)

    except requests.exceptions.ConnectionError as err:
        endpoint.live = False
        utils.debug("{0}".format(err))
        return

    # And this is the parent of ConnectionError and other things.
    # For example, "too many redirects".
    # See https://github.com/kennethreitz/requests/blob/master/requests/exceptions.py
    except requests.exceptions.RequestException as err:
        endpoint.live = False
        logging.warn("Unexpected other requests exception.")
        utils.debug("{0}".format(err))
        return

    except Exception as err:
        endpoint.unknown_error = True
        logging.warn("Unexpected other unknown exception during initial request.")
        utils.debug("{0}".format(err))
        return

    # Endpoint is live, analyze the response.
    endpoint.headers = req.headers

    endpoint.status = req.status_code

    if (req.headers.get('Location') is not None) and str(endpoint.status).startswith('3'):
        endpoint.redirect = True

    if endpoint.redirect:
        try:
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
        except Exception as err:
            endpoint.unknown_error = True
            logging.warn("Unexpected other unknown exception when handling Requests Header.")
            utils.debug("{0}".format(err))
            pass

        try:
            with ping(endpoint.url, allow_redirects=True, verify=False) as ultimate_req:
                pass
        except requests.exceptions.RequestException:
            # Swallow connection errors, but we won't be saving redirect info.
            pass
        except Exception as err:
            endpoint.unknown_error = True
            logging.warn("Unexpected other unknown exception when handling redirect.")
            utils.debug("{0}".format(err))
            return

        try:
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
            endpoint.redirect_immediately_to_https = immediate.startswith("https://")
            endpoint.redirect_immediately_to_http = immediate.startswith("http://")
            endpoint.redirect_immediately_to_external = (base_original != base_immediate)
            endpoint.redirect_immediately_to_subdomain = (
                (base_original == base_immediate) and
                (subdomain_original != subdomain_immediate)
            )

            # We're interested in whether an endpoint redirects to the www version
            # of itself (not whether it redirects to www prepended to any other
            # hostname, even within the same parent domain).
            endpoint.redirect_immediately_to_www = (
                subdomain_immediate == ("www.%s" % subdomain_original)
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

            # If we were able to make the first redirect, but not the ultimate redirect,
            # and if the immediate redirect is external, then it's accurate enough to
            # say that the eventual redirect is the immediate redirect, since you're capturing
            # the domain it's going to.
            # This also avoids "punishing" the domain for configuration issues of the site
            # it redirects to.
            elif endpoint.redirect_immediately_to_external:
                endpoint.redirect_eventually_to = endpoint.redirect_immediately_to
                endpoint.redirect_eventually_to_https = endpoint.redirect_immediately_to_https
                endpoint.redirect_eventually_to_http = endpoint.redirect_immediately_to_http
                endpoint.redirect_eventually_to_external = endpoint.redirect_immediately_to_external
                endpoint.redirect_eventually_to_subdomain = endpoint.redirect_immediately_to_subdomain
        except Exception as err:
            endpoint.unknown_error = True
            logging.warn("Unexpected other unknown exception when establishing redirects.")
            utils.debug("{0}".format(err))
            pass


def hsts_check(endpoint):
    """
    Given an endpoint and its detected headers, extract and parse
    any present HSTS header, decide what HSTS properties are there.

    Disqualify domains with a bad host, they won't work as valid HSTS.
    """
    try:
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
        first_pass = re.split(r',\s?', header)[0]
        second_pass = re.sub(r'\'', '', first_pass)

        temp = re.split(r';\s?', second_pass)

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
    except Exception as err:
        endpoint.unknown_error = True
        logging.warn("Unknown exception when handling HSTS check.")
        utils.debug("{0}".format(err))
        return


def https_check(endpoint):
    """
    Uses sslyze to figure out the reason the endpoint wouldn't verify.
    """
    utils.debug("sslyzing %s..." % endpoint.url)

    # remove the https:// from prefix for sslyze
    try:
        hostname = endpoint.url[8:]
        server_tester = ServerConnectivityTester(hostname=hostname, port=443)
        server_info = server_tester.perform()
    except ServerConnectivityError as err:
        logging.warn("Error in sslyze server connectivity check when connecting to {}".format(err.server_info.hostname))
        utils.debug("{0}".format(err))
        return
    except Exception as err:
        endpoint.unknown_error = True
        logging.warn("Unknown exception in sslyze server connectivity check.")
        utils.debug("{0}".format(err))
        return

    try:
        command = sslyze.plugins.certificate_info_plugin.CertificateInfoScanCommand(ca_file=CA_FILE)
        scanner = sslyze.synchronous_scanner.SynchronousScanner()
        cert_plugin_result = scanner.run_scan_command(server_info, command)
    except Exception as err:
        endpoint.unknown_error = True
        logging.warn("Unknown exception in sslyze scanner.")
        utils.debug("{0}".format(err))
        return

    try:
        cert_response = cert_plugin_result.as_text()
    except AttributeError:
        logging.warn("Known error in sslyze 1.X with EC public keys. See https://github.com/nabla-c0d3/sslyze/issues/215")
        return None
    except Exception as err:
        endpoint.unknown_error = True
        logging.warn("Unknown exception in cert plugin.")
        utils.debug("{0}".format(err))
        return

    # Debugging
    # for msg in cert_response:
    #     print(msg)

    # Default endpoint assessments to False until proven True.
    endpoint.https_expired_cert = False
    endpoint.https_self_signed_cert = False
    endpoint.https_bad_chain = False
    endpoint.https_bad_hostname = False

    # STORE will be either "Mozilla" or "Custom"
    # depending on what the user chose.

    # A certificate can have multiple issues.
    for msg in cert_response:

        # Check for missing SAN.
        if (
            (("DNS Subject Alternative Names") in msg) and
            (("[]") in msg)
        ):
            endpoint.https_bad_hostname = True

        # Check for certificate expiration.
        if (
            (STORE in msg) and
            (("FAILED") in msg) and
            (("certificate has expired") in msg)
        ):
            endpoint.https_expired_cert = True

        # Check to see if the cert is self-signed
        if (
            (STORE in msg) and
            (("FAILED") in msg) and
            (("self signed certificate") in msg)
        ):
            endpoint.https_self_signed_cert = True

        # Check to see if there is a bad chain

        # NOTE: If this is the only flag that's set, it's probably
        # an incomplete chain
        # If this isnt the only flag that is set, it's might be
        # because there is another error. More debugging would
        # need to be done at this point, but not through sslyze
        # because sslyze doesn't have enough granularity

        if (
            (STORE in msg) and
            (("FAILED") in msg) and
            (
                (("unable to get local issuer certificate") in msg) or
                (("self signed certificate") in msg)
            )
        ):
            endpoint.https_bad_chain = True

        # Check for whether the hostname validates.
        if (
            (("Hostname Validation") in msg) and
            (("FAILED") in msg) and
            (("Certificate does NOT match") in msg)
        ):
            endpoint.https_bad_hostname = True


def canonical_endpoint(http, httpwww, https, httpswww):
    """
    Given behavior for the 4 endpoints, make a best guess
    as to which is the "canonical" site for the domain.

    Most of the domain-level decisions rely on this guess in some way.

    A domain is "canonically" at www if:
     * at least one of its www endpoints responds
     * both root endpoints are either down or redirect *somewhere*
     * either both root endpoints are down, *or* at least one
       root endpoint redirect should immediately go to
       an *internal* www endpoint
    This is meant to affirm situations like:
      http:// -> https:// -> https://www
      https:// -> http:// -> https://www
    and meant to avoid affirming situations like:
      http:// -> http://non-www,
      http://www -> http://non-www
    or like:
      https:// -> 200, http:// -> http://www
    """

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
            (
                (not str(endpoint.status).startswith("2")) and
                (not str(endpoint.status).startswith("3"))
            )
        )

    all_roots_unused = root_unused(https) and root_unused(http)

    all_roots_down = root_down(https) and root_down(http)

    is_www = (
        at_least_one_www_used and
        all_roots_unused and (
            all_roots_down or
            https.redirect_immediately_to_www or
            http.redirect_immediately_to_www
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
    both_http_down = (not http.live) and (not httpwww.live)
    at_least_one_http_upgrades = http_upgrades(http) or http_upgrades(httpwww)

    is_https = (
        at_least_one_https_endpoint and
        all_http_unused and
        (
            both_http_down or at_least_one_http_upgrades
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


def is_live(domain):
    """
    Domain is "live" if *any* endpoint is live.
    """
    http, httpwww, https, httpswww = domain.http, domain.httpwww, domain.https, domain.httpswww

    return http.live or httpwww.live or https.live or httpswww.live


def is_redirect(domain):
    """
    Domain is "a redirect domain" if at least one endpoint is
    a redirect, and all endpoints are either redirects or down.
    """
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


def redirects_to(domain):
    """
    If a domain is a "redirect domain", where does it redirect to?
    """
    canonical = domain.canonical

    if is_redirect(domain):
        return canonical.redirect_eventually_to
    else:
        return None


def is_valid_https(domain):
    """
    A domain has "valid HTTPS" if it responds on port 443 at its canonical
    hostname with an unexpired valid certificate for the hostname.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    # Evaluate the HTTPS version of the canonical hostname
    if canonical.host == "root":
        evaluate = https
    else:
        evaluate = httpswww

    return evaluate.live and evaluate.https_valid


def is_defaults_to_https(domain):
    """
    A domain "defaults to HTTPS" if its canonical endpoint uses HTTPS.
    """
    canonical = domain.canonical

    return (canonical.protocol == "https")


def is_downgrades_https(domain):
    """
    Domain downgrades if HTTPS is supported in some way, but
    its canonical HTTPS endpoint immediately redirects internally to HTTP.
    """
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

    # Explicitly convert to bool to avoid unintentionally returning None,
    # which may happen if the site doesn't redirect.
    return bool(
        supports_https and
        canonical_https.redirect_immediately_to_http and
        (not canonical_https.redirect_immediately_to_external)
    )


def is_strictly_forces_https(domain):
    """
    A domain "Strictly Forces HTTPS" if one of the HTTPS endpoints is
    "live", and if both *HTTP* endpoints are either:

     * down, or
     * redirect immediately to an HTTPS URI.

    This is different than whether a domain "Defaults" to HTTPS.

    * An HTTP redirect can go to HTTPS on another domain, as long
      as it's immediate.
    * A domain with an invalid cert can still be enforcing HTTPS.
    """
    http, httpwww, https, httpswww = domain.http, domain.httpwww, domain.https, domain.httpswww

    def down_or_redirects(endpoint):
        return ((not endpoint.live) or endpoint.redirect_immediately_to_https)

    https_somewhere = https.live or httpswww.live
    all_http_unused = down_or_redirects(http) and down_or_redirects(httpwww)

    return https_somewhere and all_http_unused


def is_bad_chain(domain):
    """
    Domain has a bad chain if either https endpoints contain a bad chain
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.https_bad_chain


def is_bad_hostname(domain):
    """
    Domain has a bad hostname if either https endpoint fails hostname validation
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.https_bad_hostname


def is_expired_cert(domain):
    """
    Returns if the either https endpoint has an expired cert
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.https_expired_cert


def is_self_signed_cert(domain):
    """
    Returns if the either https endpoint has a self-signed cert cert
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.https_self_signed_cert


def is_hsts(domain):
    """
    Domain has HSTS if its canonical HTTPS endpoint has HSTS.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.hsts


def hsts_header(domain):
    """
    Domain's HSTS header is its canonical endpoint's header.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.hsts_header


def hsts_max_age(domain):
    """
    Domain's HSTS max-age is its canonical endpoint's max-age.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.hsts_max_age


def is_hsts_entire_domain(domain):
    """
    Whether a domain's ROOT endpoint includes all subdomains.
    """
    https = domain.https

    return https.hsts_all_subdomains


def is_hsts_preload_ready(domain):
    """
    Whether a domain's ROOT endpoint is preload-ready.
    """
    https = domain.https

    eighteen_weeks = ((https.hsts_max_age is not None) and (https.hsts_max_age >= 10886400))
    preload_ready = (eighteen_weeks and https.hsts_all_subdomains and https.hsts_preload)

    return preload_ready


def is_hsts_preload_pending(domain):
    """
    Whether a domain is formally pending inclusion in Chrome's HSTS preload
    list.

    If preload_pending is None, the caches have not been initialized, so do
    that.
    """
    if preload_pending is None:
        logging.error('`preload_pending` has not yet been initialized!')
        raise RuntimeError(
            '`initialize_external_data()` must be called explicitly before '
            'using this function'
        )

    return domain.domain in preload_pending


def is_hsts_preloaded(domain):
    """
    Whether a domain is contained in Chrome's HSTS preload list.

    If preload_list is None, the caches have not been initialized, so do that.
    """
    if preload_list is None:
        logging.error('`preload_list` has not yet been initialized!')
        raise RuntimeError(
            '`initialize_external_data()` must be called explicitly before '
            'using this function'
        )

    return domain.domain in preload_list


def is_parent_hsts_preloaded(domain):
    """
    Whether a domain's parent domain is in Chrome's HSTS preload list.
    """
    return is_hsts_preloaded(Domain(parent_domain_for(domain.domain)))


def parent_domain_for(hostname):
    """
    For "x.y.domain.gov", return "domain.gov".

    If suffix_list is None, the caches have not been initialized, so do that.
    """
    if suffix_list is None:
        logging.error('`suffix_list` has not yet been initialized!')
        raise RuntimeError(
            '`initialize_external_data()` must be called explicitly before '
            'using this function'
        )

    return suffix_list.get_public_suffix(hostname)


def is_domain_supports_https(domain):
    """
    A domain 'Supports HTTPS' when it doesn't downgrade and has valid HTTPS,
    or when it doesn't downgrade and has a bad chain but not a bad hostname.
    Domains with a bad chain "support" HTTPS but user-side errors should be expected.
    """
    return (
        (not is_downgrades_https(domain)) and
        is_valid_https(domain)
    ) or (
        (not is_downgrades_https(domain)) and
        is_bad_chain(domain) and
        (not is_bad_hostname(domain))
    )


def is_domain_enforces_https(domain):
    """A domain that 'Enforces HTTPS' must 'Support HTTPS' and default to
    HTTPS.  For websites (where Redirect is false) they are allowed to
    eventually redirect to an https:// URI. For "redirect domains"
    (domains where the Redirect value is true) they must immediately
    redirect clients to an https:// URI (even if that URI is on
    another domain) in order to be said to enforce HTTPS.
    """
    return is_domain_supports_https(domain) and (
        is_defaults_to_https(domain) or (
            is_strictly_forces_https(domain) and is_redirect(domain)
        )
    )


def is_domain_strong_hsts(domain):
    if is_hsts(domain) and hsts_max_age(domain):
        return (
            is_hsts(domain) and
            hsts_max_age(domain) >= 31536000
        )
    else:
        return None


def did_domain_error(domain):
    """
    Checks if the domain had an Unknown error somewhere
    The main purpos of this is to flag any odd websites for
    further debugging with other tools.
    """
    http, httpwww, https, httpswww = domain.http, domain.httpwww, domain.https, domain.httpswww

    return (
        http.unknown_error or httpwww.unknown_error or
        https.unknown_error or httpswww.unknown_error
    )


def load_preload_pending():
    """
    Fetch the Chrome preload pending list.
    """

    utils.debug("Fetching hstspreload.org pending list...", divider=True)
    pending_url = "https://hstspreload.org/api/v2/pending"

    try:
        request = requests.get(pending_url)
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as err:
        logging.warn('Failed to fetch pending preload list: {}'.format(pending_url))
        logging.debug('{}'.format(err))
        return []

    # TODO: abstract Py 2/3 check out to utils
    if sys.version_info[0] < 3:
        raw = request.content
    else:
        raw = str(request.content, 'utf-8')

    pending_json = json.loads(raw)

    pending = []
    for entry in pending_json:
        if entry.get('include_subdomains', False) is True:
            pending.append(entry['name'])

    return pending


def load_preload_list():
    preload_json = None

    utils.debug("Fetching Chrome preload list from source...", divider=True)

    # Downloads the chromium preloaded domain list and sets it to a global set
    file_url = 'https://chromium.googlesource.com/chromium/src/net/+/master/http/transport_security_state_static.json?format=TEXT'

    try:
        request = requests.get(file_url)
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as err:
        logging.warn('Failed to fetch preload list: {}'.format(file_url))
        logging.debug('{}'.format(err))
        return []

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

    # For our purposes, we only care about entries that includeSubDomains
    fully_preloaded = []
    for entry in preload_json['entries']:
        if entry.get('include_subdomains', False) is True:
            fully_preloaded.append(entry['name'])

    return fully_preloaded


# Returns an instantiated PublicSuffixList object, and the
# list of lines read from the file.
def load_suffix_list():
    # File does not exist, download current list and cache it at given location.
    utils.debug("Downloading the Public Suffix List...", divider=True)
    try:
        cache_file = fetch()
    except URLError as err:
        logging.warn("Unable to download the Public Suffix List...")
        utils.debug("{}".format(err))
        return []
    content = cache_file.readlines()
    suffixes = PublicSuffixList(content)
    return suffixes, content


def initialize_external_data(
    init_preload_list=None,
    init_preload_pending=None,
    init_suffix_list=None
):
    """
    This function serves to load all of third party external data.

    This can be called explicitly by a library, as part of the setup needed
    before calling other library functions, or called as part of running
    inspect_domains() or CLI operation.

    If values are passed in to this function, they will be assigned to
    be the cached values. This allows a caller of the Python API to manage
    cached data in a customized way.

    It also potentially allows clients to pass in subsets of these lists,
    for testing or novel performance reasons.

    Otherwise, if the --cache-third-parties=[DIR] flag specifies a directory,
    all downloaded third party data will be cached in a directory, and
    used from cache on the next pshtt run instead of hitting the network.

    If no values are passed in, and no --cache-third-parties flag is used,
    then no cached third party data will be created or used, and pshtt will
    download the latest data from those third party sources.
    """
    global preload_list, preload_pending, suffix_list

    # The preload list should be sent in as a list of domains.
    if init_preload_list is not None:
        preload_list = init_preload_list

    # The preload_pending list should be sent in as a list of domains.
    if init_preload_pending is not None:
        preload_pending = init_preload_pending

    # The public suffix list should be sent in as a list of file lines.
    if init_suffix_list is not None:
        suffix_list = PublicSuffixList(init_suffix_list)

    # If there's a specified cache dir, prepare paths.
    # Only used when no data has been set yet for a source.
    if THIRD_PARTIES_CACHE:
        cache_preload_list = os.path.join(THIRD_PARTIES_CACHE, cache_preload_list_default)
        cache_preload_pending = os.path.join(THIRD_PARTIES_CACHE, cache_preload_pending_default)
        cache_suffix_list = os.path.join(THIRD_PARTIES_CACHE, cache_suffix_list_default)
    else:
        cache_preload_list, cache_preload_pending, cache_suffix_list = None, None, None

    # Load Chrome's latest versioned HSTS preload list.
    if preload_list is None:
        if cache_preload_list and os.path.exists(cache_preload_list):
            utils.debug("Using cached Chrome preload list.", divider=True)
            preload_list = json.loads(open(cache_preload_list).read())
        else:
            preload_list = load_preload_list()

            if cache_preload_list:
                utils.debug("Caching preload list at %s" % cache_preload_list, divider=True)
                utils.write(utils.json_for(preload_list), cache_preload_list)

    # Load Chrome's current HSTS pending preload list.
    if preload_pending is None:
        if cache_preload_pending and os.path.exists(cache_preload_pending):
            utils.debug("Using cached hstspreload.org pending list.", divider=True)
            preload_pending = json.loads(open(cache_preload_pending).read())
        else:
            preload_pending = load_preload_pending()

            if cache_preload_pending:
                utils.debug("Caching preload pending list at %s" % cache_preload_pending, divider=True)
                utils.write(utils.json_for(preload_pending), cache_preload_pending)

    # Load Mozilla's current Public Suffix list.
    if suffix_list is None:
        if cache_suffix_list and os.path.exists(cache_suffix_list):
            utils.debug("Using cached suffix list.", divider=True)
            cache_file = codecs.open(cache_suffix_list, encoding='utf-8')
            suffix_list = PublicSuffixList(cache_file)
        else:
            suffix_list, raw_content = load_suffix_list()

            if cache_suffix_list:
                utils.debug("Caching suffix list at %s" % cache_suffix_list, divider=True)
                utils.write(''.join(raw_content), cache_suffix_list)


def inspect_domains(domains, options):
    # Override timeout, user agent, preload cache, default CA bundle
    global TIMEOUT, USER_AGENT, THIRD_PARTIES_CACHE, CA_FILE, STORE

    if options.get('timeout'):
        TIMEOUT = int(options['timeout'])
    if options.get('user_agent'):
        USER_AGENT = options['user_agent']

    # Supported cache flag, a directory to store all third party requests.
    if options.get('cache-third-parties'):
        THIRD_PARTIES_CACHE = options['cache-third-parties']

    if options.get('ca_file'):
        CA_FILE = options['ca_file']
        # By default, the store that we want to check is the Mozilla store
        # However, if a user wants to use their own CA bundle, check the
        # "Custom" Option from the sslyze output.
        STORE = "Custom"

    # If this has been run once already by a Python API client, it
    # can be safely run without hitting the network or disk again,
    # and without overriding the data the Python user set for them.
    initialize_external_data()

    # For every given domain, get inspect data.
    for domain in domains:
        yield inspect(domain)

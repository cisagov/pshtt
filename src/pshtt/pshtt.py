"""Provide the core functionality of the pshtt library."""

# Standard Python Libraries
import base64
import codecs
import datetime
import json
import logging
import os
from pathlib import Path  # Python3
import re
import sys
from urllib import parse as urlparse

# Third-Party Libraries
import OpenSSL
from publicsuffixlist.compat import PublicSuffixList  # type: ignore
from publicsuffixlist.update import updatePSL  # type: ignore
import requests
from sslyze import (  # type: ignore
    Scanner,
    ServerConnectivityTester,
    ServerNetworkLocationViaDirectConnection,
    ServerScanRequest,
)
from sslyze.errors import ConnectionToServerFailed  # type: ignore
from sslyze.plugins.certificate_info.implementation import (  # type: ignore
    CertificateInfoExtraArguments,
)
from sslyze.plugins.scan_commands import ScanCommand  # type: ignore
import urllib3

from . import utils
from .models import Domain, Endpoint

# We're going to be making requests with certificate validation
# disabled.  Commented next line due to pylint warning that urllib3 is
# not in requests.packages
# requests.packages.urllib3.disable_warnings()
urllib3.disable_warnings()

# Default, overrideable via --user-agent
USER_AGENT = "pshtt, https scanning"

# Defaults to 5 second, overrideable via --timeout
TIMEOUT = 5

# The fields we're collecting, will be keys in JSON and
# column headers in CSV.
HEADERS = [
    "Domain",
    "Base Domain",
    "Canonical URL",
    "Live",
    "HTTPS Live",
    "HTTPS Full Connection",
    "HTTPS Client Auth Required",
    "Redirect",
    "Redirect To",
    "Status",
    "Valid HTTPS",
    "HTTPS Publicly Trusted",
    "HTTPS Custom Truststore Trusted",
    "Defaults to HTTPS",
    "Downgrades HTTPS",
    "Strictly Forces HTTPS",
    "HTTPS Bad Chain",
    "HTTPS Bad Hostname",
    "HTTPS Expired Cert",
    "HTTPS Self Signed Cert",
    "HSTS",
    "HSTS Header",
    "HSTS Max Age",
    "HSTS Entire Domain",
    "HSTS Preload Ready",
    "HSTS Preload Pending",
    "HSTS Preloaded",
    "Base Domain HSTS Preloaded",
    "Domain Supports HTTPS",
    "Domain Enforces HTTPS",
    "Domain Uses Strong HSTS",
    "IP",
    "Server Header",
    "Server Version",
    "HTTPS Cert Chain Length",
    "HTTPS Probably Missing Intermediate Cert",
    "Notes",
    "Unknown Error",
]

# Used for caching the HSTS preload list from Chromium's source.
CACHE_PRELOAD_LIST_DEFAULT = "preloaded.json"
PRELOAD_LIST = None

# Used for caching the HSTS pending preload list from hstspreload.org.
CACHE_PRELOAD_PENDING_DEFAULT = "preload-pending.json"
PRELOAD_PENDING = None

# Used for determining base domain via Mozilla's public suffix list.
CACHE_SUFFIX_LIST_DEFAULT = "public-suffix-list.txt"
SUFFIX_LIST = None

# Directory to cache all third party responses, if set by user.
THIRD_PARTIES_CACHE = None

# Set if user wants to use a custom CA bundle
CA_FILE = None
STORE = "Mozilla"
PT_INT_CA_FILE = None


def inspect(base_domain):
    """Inpsect the provided domain."""
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
    """Get the results for the provided domain."""
    # print(utils.json_for(domain.to_object()))

    # Because it will inform many other judgments, first identify
    # an acceptable "canonical" URL for the domain.
    domain.canonical = canonical_endpoint(
        domain.http, domain.httpwww, domain.https, domain.httpswww
    )

    # First, the basic fields the CSV will use.
    result = {
        "Domain": domain.domain,
        "Base Domain": parent_domain_for(domain.domain),
        "Canonical URL": domain.canonical.url,
        "Live": is_live(domain),
        "Redirect": is_redirect_domain(domain),
        "Redirect To": redirects_to(domain),
        "Status": domain.canonical.status, 
        "HTTPS Live": is_https_live(domain),
        "HTTPS Full Connection": is_full_connection(domain),
        "HTTPS Client Auth Required": is_client_auth_required(domain),
        "Valid HTTPS": is_valid_https(domain),
        "HTTPS Publicly Trusted": is_publicly_trusted(domain),
        "HTTPS Custom Truststore Trusted": is_custom_trusted(domain),
        "Defaults to HTTPS": is_defaults_to_https(domain),
        "Downgrades HTTPS": is_downgrades_https(domain),
        "Strictly Forces HTTPS": is_strictly_forces_https(domain),
        "HTTPS Bad Chain": is_bad_chain(domain),
        "HTTPS Bad Hostname": is_bad_hostname(domain),
        "HTTPS Expired Cert": is_expired_cert(domain),
        "HTTPS Self Signed Cert": is_self_signed_cert(domain),
        "HTTPS Cert Chain Length": cert_chain_length(domain),
        "HTTPS Probably Missing Intermediate Cert": is_missing_intermediate_cert(
            domain
        ),
        "HSTS": is_hsts(domain),
        "HSTS Header": hsts_header(domain),
        "HSTS Max Age": hsts_max_age(domain),
        "HSTS Entire Domain": is_hsts_entire_domain(domain),
        "HSTS Preload Ready": is_hsts_preload_ready(domain),
        "HSTS Preload Pending": is_hsts_preload_pending(domain),
        "HSTS Preloaded": is_hsts_preloaded(domain),
        "Base Domain HSTS Preloaded": is_parent_hsts_preloaded(domain),
        "Domain Supports HTTPS": is_domain_supports_https(domain),
        "Domain Enforces HTTPS": is_domain_enforces_https(domain),
        "Domain Uses Strong HSTS": is_domain_strong_hsts(domain),
        "IP": get_domain_ip(domain),
        "Server Header": get_domain_server_header(domain),
        "Server Version": get_domain_server_version(domain),
        "Notes": get_domain_notes(domain),
        "Unknown Error": did_domain_error(domain),
    }

    # But also capture the extended data for those who want it.
    result["endpoints"] = domain.to_object()

    # This bit is complicated because of the continue statements,
    # perhaps overly so.  For instance, the continue statement
    # following the "if header in ..." statement after "if not
    # result['HTTPS Full Connection]" means that the final if
    # statement that sets None values to False does not apply to those
    # fields.  This code should be rewritten to more clear, or at
    # least commented so that it is clearer what is happening to the
    # various fields.  There is some implied logic due to the continue
    # statements that is tricky, at least at first glance.
    #
    # Also, the comment before "for header in HEADERS" is not accurate
    # for the same reason.
    #
    # - jsf9k

    # Convert Header fields from None to False, except for:
    # - "HSTS Header"
    # - "HSTS Max Age"
    # - "Redirect To"
    for header in HEADERS:
        if header in ("HSTS Header", "HSTS Max Age", "Redirect To"):
            continue

        if not result["HTTPS Full Connection"]:
            if header in (
                "HSTS",
                "HSTS Header",
                "HSTS Max Age",
                "HSTS Entire Domain",
                "HSTS Preload Ready",
                "Domain Uses Strong HSTS",
            ):
                continue

        if (
            header
            in ("IP", "Server Header", "Server Version", "HTTPS Cert Chain Length")
            and result[header] is None
        ):
            continue

        if header in (
            "Valid HTTPS",
            "HTTPS Publicly Trusted",
            "HTTPS Custom Truststore Trusted",
        ):
            if not result["HTTPS Live"]:
                result[header] = False
            continue

        if result[header] is None:
            result[header] = False

    return result


def ping(url, allow_redirects=False, verify=True):
    """Attempt to reach the given URL.

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
        headers={"User-Agent": USER_AGENT},
        # set by --timeout
        timeout=TIMEOUT,
    )


def basic_check(endpoint):
    """Test the endpoint.

    At first:
    * Don't follow redirects. (Will only follow if necessary.)
      If it's a 3XX, we'll ping again to follow redirects. This is
      necessary to reliably scope any errors (e.g. TLS errors) to
      the original endpoint.

    * Validate certificates. (Will figure out error if necessary.)
    """
    utils.debug("Pinging %s...", endpoint.url, divider=True)

    req = None

    try:
        with ping(endpoint.url) as req:
            endpoint.live = True
            if endpoint.protocol == "https":
                endpoint.https_full_connection = True
                endpoint.https_valid = True

    except requests.exceptions.SSLError as err:
        if "bad handshake" in str(err) and (
            "sslv3 alert handshake failure" in str(err) or "Unexpected EOF" in str(err)
        ):
            logging.exception(
                "%s: Error completing TLS handshake usually due to required client authentication.",
                endpoint.url,
            )
            utils.debug("%s: %s", endpoint.url, err)
            endpoint.live = True
            if endpoint.protocol == "https":
                # The https can still be valid with a handshake error,
                # sslyze will run later and check if it is not valid
                endpoint.https_valid = True
                endpoint.https_full_connection = False

        else:
            logging.exception(
                "%s: Error connecting over SSL/TLS or validating certificate.",
                endpoint.url,
            )
            utils.debug("%s: %s", endpoint.url, err)
            # Retry with certificate validation disabled.
            try:
                with ping(endpoint.url, verify=False) as req:
                    endpoint.live = True
                    if endpoint.protocol == "https":
                        endpoint.https_full_connection = True
                        # sslyze later will actually check if the cert is valid
                        endpoint.https_valid = True
            except requests.exceptions.SSLError as err:
                # If it's a protocol error or other, it's not a full connection,
                # but it is live.
                endpoint.live = True
                if endpoint.protocol == "https":
                    endpoint.https_full_connection = False
                    # HTTPS may still be valid, sslyze will double-check later
                    endpoint.https_valid = True
                logging.exception(
                    "%s: Unexpected SSL protocol (or other) error during retry.",
                    endpoint.url,
                )
                utils.debug("%s: %s", endpoint.url, err)
                # continue on to SSLyze to check the connection
            except requests.exceptions.RequestException as err:
                endpoint.live = False
                logging.exception(
                    "%s: Unexpected requests exception during retry.", endpoint.url
                )
                utils.debug("%s: %s", endpoint.url, err)
                return
            except OpenSSL.SSL.Error as err:
                endpoint.live = False
                logging.exception(
                    "%s: Unexpected OpenSSL exception during retry.", endpoint.url
                )
                utils.debug("%s: %s", endpoint.url, err)
                return
            except Exception as err:
                endpoint.unknown_error = True
                logging.exception(
                    "%s: Unexpected other unknown exception during requests retry.",
                    endpoint.url,
                )
                utils.debug("%s: %s", endpoint.url, err)
                return

        # If it was a certificate error of any kind, it's live,
        # unless SSLyze encounters a connection error later
        endpoint.live = True

    except requests.exceptions.ConnectionError as err:
        # We can get this for some endpoints that are actually live,
        # so if it's https let's try sslyze to be sure
        if endpoint.protocol == "https":
            # https check later will set whether the endpoint is live and valid
            endpoint.https_full_connection = False
            endpoint.https_valid = True
        else:
            endpoint.live = False
        logging.exception("%s: Error connecting.", endpoint.url)
        utils.debug("%s: %s", endpoint.url, err)

    # And this is the parent of ConnectionError and other things.
    # For example, "too many redirects".
    # See https://github.com/kennethreitz/requests/blob/master/requests/exceptions.py
    except requests.exceptions.RequestException as err:
        endpoint.live = False
        logging.exception("%s: Unexpected other requests exception.", endpoint.url)
        utils.debug("%s: %s", endpoint.url, err)
        return

    except Exception as err:
        endpoint.unknown_error = True
        logging.exception(
            "%s: Unexpected other unknown exception during initial request.",
            endpoint.url,
        )
        utils.debug("%s: %s", endpoint.url, err)
        return

    # Run SSLyze to see if there are any errors
    if endpoint.protocol == "https":
        https_check(endpoint)
        # Double-check in case sslyze failed the first time, but the regular conneciton succeeded
        if endpoint.live is False and req is not None:
            logging.warning(
                "%s: Trying sslyze again since it connected once already.", endpoint.url
            )
            endpoint.live = True
            endpoint.https_valid = True
            https_check(endpoint)
            if endpoint.live is False:
                # sslyze failed so back everything out and don't continue analyzing the existing response
                req = None
                endpoint.https_valid = False
                endpoint.https_full_connection = False

    if req is None:
        # Ensure that full_connection is set to False if we didn't get a response
        if endpoint.protocol == "https":
            endpoint.https_full_connection = False
        return

    # try to get IP address if we can
    try:
        if req.raw.closed is False:
            ip = req.raw._connection.sock.socket.getpeername()[0]
            if endpoint.ip is None:
                endpoint.ip = ip
            else:
                if endpoint.ip != ip:
                    utils.debug(
                        "%s: Endpoint IP is already %s, but requests IP is %s.",
                        endpoint.url,
                        endpoint.ip,
                        ip,
                    )
    except Exception:
        # if the socket has already closed, it will throw an exception, but this is just best effort, so ignore it
        logging.exception("Error closing socket")

    # Endpoint is live, analyze the response.
    endpoint.headers = req.headers

    endpoint.status = req.status_code

    if req.headers.get("Server") is not None:
        endpoint.server_header = req.headers.get("Server")
        # *** in the future add logic to convert header to server version if known

    if (req.headers.get("Location") is not None) and str(endpoint.status).startswith(
        "3"
    ):
        endpoint.redirect = True
        logging.warning("%s: Found redirect.", endpoint.url)

    if endpoint.redirect:
        try:
            location_header = req.headers.get("Location")
            # Absolute redirects (e.g. "https://example.com/Index.aspx")
            if location_header.startswith("http:") or location_header.startswith(
                "https:"
            ):
                immediate = location_header

            # Relative redirects (e.g. "Location: /Index.aspx").
            # Construct absolute URI, relative to original request.
            else:
                immediate = urlparse.urljoin(endpoint.url, location_header)

            # Chase down the ultimate destination, ignoring any certificate warnings.
            ultimate_req = None
        except Exception as err:
            endpoint.unknown_error = True
            logging.exception(
                "%s: Unexpected other unknown exception when handling Requests Header.",
                endpoint.url,
            )
            utils.debug("%s %s", endpoint.url, err)

        try:
            with ping(endpoint.url, allow_redirects=True, verify=False) as ultimate_req:
                pass
        except (requests.exceptions.RequestException, OpenSSL.SSL.Error):
            # Swallow connection errors, but we won't be saving redirect info.
            logging.exception("Connection error")
        except Exception as err:
            endpoint.unknown_error = True
            logging.exception(
                "%s: Unexpected other unknown exception when handling redirect.",
                endpoint.url,
            )
            utils.debug("%s: %s", endpoint.url, err)
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
            endpoint.redirect_immediately_to_external = base_original != base_immediate
            endpoint.redirect_immediately_to_subdomain = (
                base_original == base_immediate
            ) and (subdomain_original != subdomain_immediate)

            # We're interested in whether an endpoint redirects to the www version
            # of itself (not whether it redirects to www prepended to any other
            # hostname, even within the same parent domain).
            endpoint.redirect_immediately_to_www = subdomain_immediate == (
                f"www.{subdomain_original}"
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
                endpoint.redirect_eventually_to_external = (
                    base_original != base_eventual
                )
                endpoint.redirect_eventually_to_subdomain = (
                    base_original == base_eventual
                ) and (subdomain_original != subdomain_eventual)

            # If we were able to make the first redirect, but not the ultimate redirect,
            # and if the immediate redirect is external, then it's accurate enough to
            # say that the eventual redirect is the immediate redirect, since you're capturing
            # the domain it's going to.
            # This also avoids "punishing" the domain for configuration issues of the site
            # it redirects to.
            elif endpoint.redirect_immediately_to_external:
                endpoint.redirect_eventually_to = endpoint.redirect_immediately_to
                endpoint.redirect_eventually_to_https = (
                    endpoint.redirect_immediately_to_https
                )
                endpoint.redirect_eventually_to_http = (
                    endpoint.redirect_immediately_to_http
                )
                endpoint.redirect_eventually_to_external = (
                    endpoint.redirect_immediately_to_external
                )
                endpoint.redirect_eventually_to_subdomain = (
                    endpoint.redirect_immediately_to_subdomain
                )
        except Exception as err:
            endpoint.unknown_error = True
            logging.exception(
                "%s: Unexpected other unknown exception when establishing redirects.",
                endpoint.url,
            )
            utils.debug("%s: %s", endpoint.url, err)


def hsts_check(endpoint):
    """Perform an HSTS check of the given endpoint.

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
        first_pass = re.split(r",\s?", header)[0]
        second_pass = re.sub(r"\'", "", first_pass)

        temp = re.split(r";\s?", second_pass)

        if "max-age" in header.lower():
            endpoint.hsts_max_age = int(temp[0][len("max-age=") :])

        if endpoint.hsts_max_age is None or endpoint.hsts_max_age <= 0:
            endpoint.hsts = False
            return

        # check if hsts includes sub domains
        if "includesubdomains" in header.lower():
            endpoint.hsts_all_subdomains = True

        # Check is hsts has the preload flag
        if "preload" in header.lower():
            endpoint.hsts_preload = True
    except Exception as err:
        endpoint.unknown_error = True
        logging.exception(
            "%s: Unknown exception when handling HSTS check.", endpoint.url
        )
        utils.debug("%s: %s", endpoint.url, err)
        return


def https_check(endpoint):
    """Use sslyze to figure out the reason an endpoint failed to verify."""
    utils.debug("sslyzing %s...", endpoint.url)

    # remove the https:// from prefix for sslyze
    try:
        hostname = endpoint.url[8:]
        server_location = (
            ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
                hostname=hostname, port=443
            )
        )
        server_tester = ServerConnectivityTester()
        server_info = server_tester.perform(server_location)
        endpoint.live = True
        ip = server_location.ip_address
        if endpoint.ip is None:
            endpoint.ip = ip
        else:
            if endpoint.ip != ip:
                utils.debug(
                    "%s: Endpoint IP is already %s, but requests IP is %s.",
                    endpoint.url,
                    endpoint.ip,
                    ip,
                )
        if server_info.tls_probing_result.client_auth_requirement.name == "REQUIRED":
            endpoint.https_client_auth_required = True
            logging.warning("%s: Client Authentication REQUIRED", endpoint.url)
    except ConnectionToServerFailed as err:
        endpoint.live = False
        endpoint.https_valid = False
        logging.exception(
            "%s: Error in sslyze server connectivity check when connecting to %s",
            endpoint.url,
            err.server_location.hostname,
        )
        utils.debug("%s: %s", endpoint.url, err)
        return
    except Exception as err:
        endpoint.unknown_error = True
        logging.exception(
            "%s: Unknown exception in sslyze server connectivity check.", endpoint.url
        )
        utils.debug("%s: %s", endpoint.url, err)
        return

    try:
        cert_plugin_result = None
        scanner = Scanner()
        command = ScanCommand.CERTIFICATE_INFO
        if CA_FILE is not None:
            command_extra_args = {
                command: CertificateInfoExtraArguments(custom_ca_file=Path(CA_FILE))
            }
            scan_request = ServerScanRequest(
                server_info=server_info,
                scan_commands_extra_arguments=command_extra_args,
                scan_commands=[command],
            )
        else:
            scan_request = ServerScanRequest(
                server_info=server_info, scan_commands=[command]
            )
        scanner.queue_scan(scan_request)
        # Retrieve results from generator object
        scan_result = [x for x in scanner.get_results()][0]
        cert_plugin_result = scan_result.scan_commands_results[
            ScanCommand.CERTIFICATE_INFO
        ]
    except Exception as err:
        try:
            if "timed out" in str(err):
                logging.exception(
                    "%s: Retrying sslyze scanner certificate plugin.", endpoint.url
                )
                scanner.queue_scan(scan_request)
                # Consume the generator object and retrieve the first result
                scan_result = [x for x in scanner.get_results()][0]
                cert_plugin_result = scan_result.scan_commands_results[
                    ScanCommand.CERTIFICATE_INFO
                ]
            else:
                logging.exception(
                    "%s: Unknown exception in sslyze scanner certificate plugin.",
                    endpoint.url,
                )
                utils.debug("%s: %s", endpoint.url, err)
                endpoint.unknown_error = True
                # We could make this False, but there was an error so
                # we don't know
                endpoint.https_valid = None
                return
        except Exception:
            logging.exception(
                "%s: Unknown exception in sslyze scanner certificate plugin.",
                endpoint.url,
            )
            utils.debug("%s: %s", endpoint.url, err)
            endpoint.unknown_error = True
            # We could make this False, but there was an error so we
            # don't know
            endpoint.https_valid = None
            return

    try:
        # Default endpoint assessments to False until proven True.
        endpoint.https_expired_cert = False
        endpoint.https_self_signed_cert = False
        endpoint.https_bad_chain = False
        endpoint.https_bad_hostname = False

        # Default trust to False until proven True
        public_trust = True
        custom_trust = True
        public_not_trusted_names = []
        for certificate_deployment in cert_plugin_result.certificate_deployments:
            validation_results = certificate_deployment.path_validation_results
            for result in validation_results:
                if result.was_validation_successful:
                    # We're assuming that it is trusted to start with
                    pass
                else:
                    if "Custom" in result.trust_store.name:
                        custom_trust = False
                    else:
                        public_trust = False
                        public_not_trusted_names.append(result.trust_store.name)

                if STORE in result.trust_store.name:
                    cert_chain = result.verified_certificate_chain
                    leaf_cert = cert_chain[0]

                    # Check for leaf certificate expiration/self-signature.
                    if leaf_cert.not_valid_after < datetime.datetime.now():
                        endpoint.https_expired_cert = True

                    # Check to see if the cert is self-signed
                    if leaf_cert.issuer == leaf_cert.subject:
                        endpoint.https_self_signed_cert = True

                    # Check certificate chain till the second last element
                    # The last cert being the root cert is self signed and
                    # hence the self signed check is not valid
                    # NOTE: If this is the only flag that's set, it's probably
                    # an incomplete chain
                    # If this isn't the only flag that is set, it might be
                    # because there is another error. More debugging would
                    # need to be done at this point, but not through sslyze
                    # because sslyze doesn't have enough granularity
                    for cert in cert_chain[:-1]:
                        # Check for certificate expiration
                        if cert.not_valid_after < datetime.datetime.now():
                            endpoint.https_bad_chain = True

                        # Check to see if the cert is self-signed
                        if cert.issuer == cert.subject or not cert.issuer:
                            endpoint.https_bad_chain = True

                    # If leaf certificate subject does NOT match hostname, bad hostname
                    # NOTE: Since sslyze 3.0.0, ever since JSON output for certinfo,
                    # SAN(s) are checked as part of _certificate_matches_hostname which
                    # called as part of leaf_certificate_subject_matches_hostname
                    if (
                        not certificate_deployment.leaf_certificate_subject_matches_hostname
                    ):
                        endpoint.https_bad_hostname = True

        if public_trust:
            logging.warning(
                "%s: Publicly trusted by common trust stores.", endpoint.url
            )
        else:
            logging.warning(
                "%s: Not publicly trusted - not trusted by %s.",
                endpoint.url,
                ", ".join(public_not_trusted_names),
            )
        if CA_FILE is not None:
            if custom_trust:
                logging.warning("%s: Trusted by custom trust store.", endpoint.url)
            else:
                logging.warning("%s: Not trusted by custom trust store.", endpoint.url)
        else:
            custom_trust = None
        endpoint.https_public_trusted = public_trust
        endpoint.https_custom_trusted = custom_trust
    except Exception as err:
        # Ignore exception
        logging.exception(
            "%s: Unknown exception examining certificate deployment.", endpoint.url
        )
        utils.debug(
            "%s: Unknown exception examining certificate deployment: %s",
            endpoint.url,
            err,
        )

    try:
        endpoint.https_cert_chain_len = 0
        for certificate_deployment in cert_plugin_result.certificate_deployments:
            endpoint.https_cert_chain_len += len(
                certificate_deployment.received_certificate_chain
            )
        if endpoint.https_self_signed_cert is False and (
            endpoint.https_cert_chain_len < 2
        ):
            # *** TODO check that it is not a bad hostname and that the root cert is trusted before suggesting that it is an intermediate cert issue.
            endpoint.https_missing_intermediate_cert = True
            has_verified_cert_chain = True
            for certificate_deployment in cert_plugin_result.certificate_deployments:
                if certificate_deployment.verified_certificate_chain is None:
                    has_verified_cert_chain = False
            if not has_verified_cert_chain:
                logging.warning(
                    "%s: Untrusted certificate chain, probably due to missing intermediate certificate.",
                    endpoint.url,
                )
                utils.debug(
                    "%s: Only %s certificates in certificate chain received.",
                    endpoint.url,
                    endpoint.https_cert_chain_len,
                )
            elif custom_trust is True and public_trust is False:
                # recheck public trust using custom public trust store with manually added intermediate certificates
                if PT_INT_CA_FILE is not None:
                    try:
                        cert_plugin_result = None
                        scanner = Scanner()
                        command = ScanCommand.CERTIFICATE_INFO
                        command_extra_args = {
                            command: CertificateInfoExtraArguments(
                                custom_ca_file=Path(PT_INT_CA_FILE)
                            )
                        }
                        scan_request = ServerScanRequest(
                            server_info=server_info,
                            scan_commands_extra_arguments=command_extra_args,
                            scan_commands=[command],
                        )
                        scanner.queue_scan(scan_request)
                        # Consume the generator object and retrieve the first result
                        scan_result = [x for x in scanner.get_results()][0]
                        cert_plugin_result = scan_result.scan_commands_results[
                            ScanCommand.CERTIFICATE_INFO
                        ]
                        has_verified_cert_chain = True
                        for (
                            certificate_deployment
                        ) in cert_plugin_result.certificate_deployments:
                            if (
                                certificate_deployment.verified_certificate_chain
                                is None
                            ):
                                has_verified_cert_chain = False
                        if has_verified_cert_chain:
                            public_trust = True
                            endpoint.https_public_trusted = public_trust
                            logging.warning(
                                "%s: Trusted by special public trust store with intermediate certificates.",
                                endpoint.url,
                            )
                    except Exception:
                        logging.exception("Error while rechecking public trust")
        else:
            endpoint.https_missing_intermediate_cert = False
    except Exception:
        logging.exception("Error while determining length of certificate chain")

    # If anything is wrong then https is not valid
    if (
        endpoint.https_expired_cert
        or endpoint.https_self_signed_cert
        or endpoint.https_bad_chain
        or endpoint.https_bad_hostname
    ):
        endpoint.https_valid = False


def canonical_endpoint(http, httpwww, https, httpswww):
    """Make a best guess for the "canonical" endpoint of a domain.

    Given behavior for the four endpoints, make a best guess
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
            endpoint.redirect
            or not endpoint.live
            or endpoint.https_bad_hostname  # harmless for http endpoints
            or not str(endpoint.status).startswith("2")
        )

    def root_down(endpoint):
        return (
            not endpoint.live
            or endpoint.https_bad_hostname
            or (
                not str(endpoint.status).startswith("2")
                and not str(endpoint.status).startswith("3")
            )
        )

    all_roots_unused = root_unused(https) and root_unused(http)

    all_roots_down = root_down(https) and root_down(http)

    is_www = (
        at_least_one_www_used
        and all_roots_unused
        and (
            all_roots_down
            or https.redirect_immediately_to_www
            or http.redirect_immediately_to_www
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
        return endpoint.live and not endpoint.https_bad_hostname

    def http_unused(endpoint):
        return (
            endpoint.redirect
            or not endpoint.live
            or not str(endpoint.status).startswith("2")
        )

    def http_upgrades(endpoint):
        return endpoint.redirect_immediately_to_https and (
            not endpoint.redirect_immediately_to_external
        )

    at_least_one_https_endpoint = https_used(https) or https_used(httpswww)
    all_http_unused = http_unused(http) and http_unused(httpwww)
    both_http_down = not http.live and not httpwww.live
    at_least_one_http_upgrades = http_upgrades(http) or http_upgrades(httpwww)

    is_https = (
        at_least_one_https_endpoint
        and all_http_unused
        and (both_http_down or at_least_one_http_upgrades)
    )

    if is_www and is_https:
        return httpswww
    if is_www and not is_https:
        return httpwww
    if not is_www and is_https:
        return https
    if not is_www and not is_https:
        return http


##
# Judgment calls based on observed endpoint data.
##


def is_live(domain):
    """Check if a domain has any live endpoints."""
    http, httpwww, https, httpswww = (
        domain.http,
        domain.httpwww,
        domain.https,
        domain.httpswww,
    )

    return http.live or httpwww.live or https.live or httpswww.live


def is_https_live(domain):
    """Check if a domain has any live HTTPS endpoints."""
    https, httpswww = domain.https, domain.httpswww

    return https.live or httpswww.live


def is_full_connection(domain):
    """Check if a domain is fully connected.

    Domain is "fully connected" if any HTTPS endpoint is fully connected.
    """
    https, httpswww = domain.https, domain.httpswww

    return https.https_full_connection or httpswww.https_full_connection


def is_client_auth_required(domain):
    """Check if a domain requires client authentication.

    Domain requires client authentication if *any* HTTPS endpoint requires it for full
    TLS connection.
    """
    https, httpswww = domain.https, domain.httpswww

    return https.https_client_auth_required or httpswww.https_client_auth_required


def is_redirect_or_down(endpoint):
    """Check if an endpoint redirects to an external site or is down.

    Endpoint is a redirect or down if it is a redirect to an external site or it is
    down in any of 3 ways: it is not live, it is HTTPS and has a bad hostname in the
    cert, or it responds with a 4xx error code
    """
    return (
        endpoint.redirect_eventually_to_external
        or not endpoint.live
        or (endpoint.protocol == "https" and endpoint.https_bad_hostname)
        or (endpoint.status is not None and endpoint.status >= 400)
    )


def is_redirect(endpoint):
    """Check if an endpoint is a redirect to an external site."""
    return endpoint.redirect_eventually_to_external


def is_redirect_domain(domain):
    """Check if a domain redirects HTTP or HTTPS traffic.

    Domain is "a redirect domain" if at least one endpoint is
    a redirect, and all endpoints are either redirects or down.
    """
    http, httpwww, https, httpswww = (
        domain.http,
        domain.httpwww,
        domain.https,
        domain.httpswww,
    )

    return is_live(domain) and (
        (
            is_redirect(http)
            or is_redirect(httpwww)
            or is_redirect(https)
            or is_redirect(httpswww)
        )
        and is_redirect_or_down(https)
        and is_redirect_or_down(httpswww)
        and is_redirect_or_down(httpwww)
        and is_redirect_or_down(http)
    )


def is_http_redirect_domain(domain):
    """Check if a domain redirects HTTP traffic.

    Domain is "an http redirect domain" if at least one HTTP endpoint
    is a redirect, and all other http endpoints are either redirects
    or down.
    """
    (
        http,
        httpwww,
    ) = (
        domain.http,
        domain.httpwww,
    )

    return is_live(domain) and (
        (is_redirect(http) or is_redirect(httpwww))
        and is_redirect_or_down(httpwww)
        and is_redirect_or_down(http)
    )


def redirects_to(domain):
    """Check where a domain redirects to (if it redirects).

    If a domain is a "redirect domain", where does it redirect to?
    """
    canonical = domain.canonical

    if is_redirect_domain(domain):
        return canonical.redirect_eventually_to
    return None


def is_valid_https(domain):
    """Check if a domain has a valid HTTPS server.

    A domain has "valid HTTPS" if it responds on port 443 at its canonical
    hostname with an unexpired valid certificate for the hostname.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    # Evaluate the HTTPS version of the canonical hostname
    evaluate = https if canonical.host == "root" else httpswww

    return evaluate.live and evaluate.https_valid


def is_defaults_to_https(domain):
    """Check if a domain defaults to HTTPS.

    A domain "defaults to HTTPS" if its canonical endpoint uses HTTPS.
    """
    canonical = domain.canonical

    return canonical.protocol == "https"


def is_downgrades_https(domain):
    """Check if a domain allows downgrading HTTPS.

    Domain downgrades if HTTPS is supported in some way, but
    its canonical HTTPS endpoint immediately redirects internally to HTTP.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    # The domain "supports" HTTPS if any HTTPS endpoint responds with
    # a certificate valid for its hostname.
    supports_https = (https.live and not https.https_bad_hostname) or (
        httpswww.live and not httpswww.https_bad_hostname
    )

    canonical_https = httpswww if canonical.host == "www" else https

    # Explicitly convert to bool to avoid unintentionally returning None,
    # which may happen if the site doesn't redirect.
    return bool(
        supports_https
        and canonical_https.redirect_immediately_to_http
        and not canonical_https.redirect_immediately_to_external
    )


def is_strictly_forces_https(domain):
    """Check if a domain strictly forces HTTPS.

    A domain "Strictly Forces HTTPS" if one of the HTTPS endpoints is
    "live", and if both *HTTP* endpoints are either:

     * down, or
     * redirect immediately to an HTTPS URI.

    This is different than whether a domain "Defaults" to HTTPS.

    * An HTTP redirect can go to HTTPS on another domain, as long
      as it's immediate.
    * A domain with an invalid cert can still be enforcing HTTPS.
    """
    http, httpwww, https, httpswww = (
        domain.http,
        domain.httpwww,
        domain.https,
        domain.httpswww,
    )

    def down_or_redirects(endpoint):
        return not endpoint.live or endpoint.redirect_immediately_to_https

    https_somewhere = https.live or httpswww.live
    all_http_unused = down_or_redirects(http) and down_or_redirects(httpwww)

    return https_somewhere and all_http_unused


def is_publicly_trusted(domain):
    """Check if a domain has a publicly trusted certificate.

    A domain has a "Publicly Trusted" certificate if its canonical
    endpoint has a publicly trusted certificate.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    # Evaluate the HTTPS version of the canonical hostname
    evaluate = https if canonical.host == "root" else httpswww

    return evaluate.live and evaluate.https_public_trusted


def is_custom_trusted(domain):
    """Check if a domain has a custom trusted certificate.

    A domain has a "Custom Trusted" certificate if its canonical
    endpoint has a certificate that is trusted by the custom
    truststore.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    # Evaluate the HTTPS version of the canonical hostname
    evaluate = https if canonical.host == "root" else httpswww

    return evaluate.live and evaluate.https_custom_trusted


def is_bad_chain(domain):
    """Check if a domain has a bad certificate chain.

    Domain has a bad chain if its canonical HTTPS endpoint has a bad
    chain.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    canonical_https = httpswww if canonical.host == "www" else https

    return canonical_https.https_bad_chain


def is_bad_hostname(domain):
    """Check if a domain has a bad hostname.

    Domain has a bad hostname if its canonical HTTPS endpoint fails
    hostname validation.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    canonical_https = httpswww if canonical.host == "www" else https

    return canonical_https.https_bad_hostname


def is_expired_cert(domain):
    """Check if a domain's canonical endpoint has an expired certificate."""
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    canonical_https = httpswww if canonical.host == "www" else https

    return canonical_https.https_expired_cert


def is_self_signed_cert(domain):
    """Check if the domain's canonical endpoint has a self-signed certificate."""
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    canonical_https = httpswww if canonical.host == "www" else https

    return canonical_https.https_self_signed_cert


def cert_chain_length(domain):
    """Get the certificate chain length for a domain's canonical HTTPS endpoint."""
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    canonical_https = httpswww if canonical.host == "www" else https

    return canonical_https.https_cert_chain_len


def is_missing_intermediate_cert(domain):
    """Check if a domain's certificate chain is missing an intermediate certificate.

    Returns whether the served cert chain is probably missing the
    needed intermediate certificate for the canonical HTTPS endpoint.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    canonical_https = httpswww if canonical.host == "www" else https

    return canonical_https.https_missing_intermediate_cert


def is_hsts(domain):
    """Check if a domain's canonical endpoint has HSTS.

    Domain has HSTS if its canonical HTTPS endpoint has HSTS.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    canonical_https = httpswww if canonical.host == "www" else https

    return canonical_https.hsts


def hsts_header(domain):
    """Get a domain's canonical endpoint's HSTS header."""
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    canonical_https = httpswww if canonical.host == "www" else https

    return canonical_https.hsts_header


def hsts_max_age(domain):
    """Get a domain's canonical endpoint's HSTS max-age."""
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    canonical_https = httpswww if canonical.host == "www" else https

    return canonical_https.hsts_max_age


def is_hsts_entire_domain(domain):
    """Check if a domain's ROOT endpoint HSTS configuration includes all subdomains."""
    https = domain.https

    return https.hsts_all_subdomains


def is_hsts_preload_ready(domain):
    """Check if a domain's ROOT endpoint is HSTS preload-ready."""
    https = domain.https

    eighteen_weeks = (https.hsts_max_age is not None) and (
        https.hsts_max_age >= 10886400
    )
    preload_ready = eighteen_weeks and https.hsts_all_subdomains and https.hsts_preload

    return preload_ready


def is_hsts_preload_pending(domain):
    """Check if a domain is pending inclusion in Chrome's HSTS preload list.

    If PRELOAD_PENDING is None, the caches have not been initialized, so do
    that.
    """
    if PRELOAD_PENDING is None:
        logging.error("`PRELOAD_PENDING` has not yet been initialized!")
        raise RuntimeError(
            "`initialize_external_data()` must be called explicitly before "
            "using this function"
        )

    return domain.domain in PRELOAD_PENDING


def is_hsts_preloaded(domain):
    """Check if a domain is contained in Chrome's HSTS preload list.

    If PRELOAD_LIST is None, the caches have not been initialized, so do that.
    """
    if PRELOAD_LIST is None:
        logging.error("`PRELOAD_LIST` has not yet been initialized!")
        raise RuntimeError(
            "`initialize_external_data()` must be called explicitly before "
            "using this function"
        )

    return domain.domain in PRELOAD_LIST


def is_parent_hsts_preloaded(domain):
    """Check if a domain's parent domain is in Chrome's HSTS preload list."""
    return is_hsts_preloaded(Domain(parent_domain_for(domain.domain)))


def parent_domain_for(hostname):
    """Get the parent domain for a given domain name.

    For "x.y.domain.gov", return "domain.gov".

    If SUFFIX_LIST is None, the caches have not been initialized, so do that.
    """
    if SUFFIX_LIST is None:
        logging.error("`SUFFIX_LIST` has not yet been initialized!")
        raise RuntimeError(
            "`initialize_external_data()` must be called explicitly before "
            "using this function"
        )

    return SUFFIX_LIST.get_public_suffix(hostname)


def is_domain_supports_https(domain):
    """Check if a domain supports HTTPS.

    A domain 'Supports HTTPS' when it doesn't downgrade and has valid HTTPS,
    or when it doesn't downgrade and has a bad chain but not a bad hostname.
    Domains with a bad chain "support" HTTPS but user-side errors should be expected.
    """
    return (not is_downgrades_https(domain) and is_valid_https(domain)) or (
        not is_downgrades_https(domain)
        and is_bad_chain(domain)
        and not is_bad_hostname(domain)
    )


def is_domain_enforces_https(domain):
    """Check if a domain enforces HTTPS.

    A domain that 'Enforces HTTPS' must 'Support HTTPS' and default to
    HTTPS.  For websites (where Redirect is false) they are allowed to
    eventually redirect to an https:// URI. For "redirect domains"
    (domains where the Redirect value is true) they must immediately
    redirect clients to an https:// URI (even if that URI is on
    another domain) in order to be said to enforce HTTPS.
    """
    return (
        is_domain_supports_https(domain)
        and is_strictly_forces_https(domain)
        and (is_defaults_to_https(domain) or is_http_redirect_domain(domain))
    )


def is_domain_strong_hsts(domain):
    """Check if a domain is using strong HSTS."""
    if is_hsts(domain) and hsts_max_age(domain):
        return is_hsts(domain) and hsts_max_age(domain) >= 31536000
    return None


def get_domain_ip(domain):
    """Get the IP for the domain.

    This returns the first that is not None in the following priority:
    Canonical -> HTTPS -> www HTTPS -> www HTTP -> HTTP
    """
    if domain.canonical.ip is not None:
        return domain.canonical.ip
    if domain.https.ip is not None:
        return domain.https.ip
    if domain.httpswww.ip is not None:
        return domain.httpswww.ip
    if domain.httpwww.ip is not None:
        return domain.httpwww.ip
    if domain.http.ip is not None:
        return domain.http.ip
    return None


def get_domain_server_header(domain):
    """Get the Server header from the response for the domain.

    This returns the first that is not None in the following priority:
    Canonical -> HTTPS -> www HTTPS -> www HTTP -> HTTP
    """
    if domain.canonical.server_header is not None:
        return domain.canonical.server_header.replace(",", ";")
    if domain.https.server_header is not None:
        return domain.https.server_header.replace(",", ";")
    if domain.httpswww.server_header is not None:
        return domain.httpswww.server_header.replace(",", ";")
    if domain.httpwww.server_header is not None:
        return domain.httpwww.server_header.replace(",", ";")
    if domain.http.server_header is not None:
        return domain.http.server_header.replace(",", ";")
    return None


def get_domain_server_version(domain):
    """Get the server version for the remote web server.

    This returns the first that is not None in the following priority:
    Canonical -> HTTPS -> www HTTPS -> www HTTP -> HTTP
    The server version is based on the returned Server header.
    """
    if domain.canonical.server_version is not None:
        return domain.canonical.server_version
    if domain.https.server_version is not None:
        return domain.https.server_version
    if domain.httpswww.server_version is not None:
        return domain.httpswww.server_version
    if domain.httpwww.server_version is not None:
        return domain.httpwww.server_version
    if domain.http.server_version is not None:
        return domain.http.server_version
    return None


def get_domain_notes(domain):
    """Combine any notes for a domain."""
    all_notes = (
        domain.http.notes
        + domain.httpwww.notes
        + domain.https.notes
        + domain.httpswww.notes
    )
    all_notes = all_notes.replace(",", ";")
    return all_notes


def did_domain_error(domain):
    """Check a domain for any unknown errors.

    The main purpose of this is to flag any odd websites for
    further debugging with other tools.
    """
    http, httpwww, https, httpswww = (
        domain.http,
        domain.httpwww,
        domain.https,
        domain.httpswww,
    )

    return (
        http.unknown_error
        or httpwww.unknown_error
        or https.unknown_error
        or httpswww.unknown_error
    )


def load_preload_pending():
    """Fetch the Chrome preload pending list."""
    utils.debug("Fetching hstspreload.org pending list...", divider=True)
    pending_url = "https://hstspreload.org/api/v2/pending"

    try:
        request = requests.get(pending_url, timeout=TIMEOUT)
    except (
        requests.exceptions.SSLError,
        requests.exceptions.ConnectionError,
        requests.exceptions.ConnectTimeout,
    ) as err:
        logging.exception("Failed to fetch pending preload list: %s", pending_url)
        logging.debug(err)
        return []

    # TODO: abstract Py 2/3 check out to utils
    if sys.version_info[0] < 3:
        raw = request.content
    else:
        raw = str(request.content, "utf-8")

    pending_json = json.loads(raw)

    pending = []
    for entry in pending_json:
        if entry.get("include_subdomains", False) is True:
            pending.append(entry["name"])

    return pending


def load_preload_list():
    """Download and load the Chromium preload list."""
    preload_json = None

    utils.debug("Fetching Chrome preload list from source...", divider=True)

    # Downloads the chromium preloaded domain list and sets it to a global set
    file_url = "https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json?format=TEXT"

    try:
        request = requests.get(file_url, timeout=TIMEOUT)
    except (
        requests.exceptions.SSLError,
        requests.exceptions.ConnectionError,
        requests.exceptions.ConnectTimeout,
    ) as err:
        logging.exception("Failed to fetch preload list: %s", file_url)
        logging.debug(err)
        return []

    raw = request.content

    # To avoid parsing the contents of the file out of the source tree viewer's
    # HTML, we download it as a raw file. googlesource.com Base64-encodes the
    # file to avoid potential content injection issues, so we need to decode it
    # before using it. https://code.google.com/p/gitiles/issues/detail?id=7
    raw = base64.b64decode(raw).decode("utf-8")

    # The .json file contains '//' comments, which are not actually valid JSON,
    # and confuse Python's JSON decoder. Begone, foul comments!
    raw = "".join([re.sub(r"^\s*//.*$", "", line) for line in raw.splitlines()])

    preload_json = json.loads(raw)

    # For our purposes, we only care about entries that includeSubDomains
    fully_preloaded = []
    for entry in preload_json["entries"]:
        if entry.get("include_subdomains", False) is True:
            fully_preloaded.append(entry["name"])

    return fully_preloaded


# Returns an instantiated PublicSuffixList object.
def load_suffix_list(cache_suffix_list=None, update_list=False):
    """Download and load the public suffix list."""
    if update_list:
        utils.debug("Downloading the Public Suffix List...", divider=True)
        try:
            # Update the local copy
            if cache_suffix_list:
                updatePSL(cache_suffix_list)
            # Update the built-in copy
            else:
                updatePSL()
        except Exception as err:
            logging.exception("Unable to download the Public Suffix List...")
            utils.debug(err)
            return None

    # Use the local copy
    if cache_suffix_list:
        utils.debug("Using cached Public Suffix List.", divider=True)
        with codecs.open(cache_suffix_list, encoding="utf-8") as cache_file:
            suffixes = PublicSuffixList(cache_file)
    # Use the built-in copy
    else:
        suffixes = PublicSuffixList()

    return suffixes


def initialize_external_data(
    init_preload_list=None, init_preload_pending=None, init_suffix_list=None
):
    """Load any third party external data.

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
    global PRELOAD_LIST, PRELOAD_PENDING, SUFFIX_LIST

    # The preload list should be sent in as a list of domains.
    if init_preload_list is not None:
        PRELOAD_LIST = init_preload_list

    # The PRELOAD_PENDING list should be sent in as a list of domains.
    if init_preload_pending is not None:
        PRELOAD_PENDING = init_preload_pending

    # The public suffix list should be sent in as a list of file lines.
    if init_suffix_list is not None:
        SUFFIX_LIST = PublicSuffixList(init_suffix_list)

    # If there's a specified cache dir, prepare paths.
    # Only used when no data has been set yet for a source.
    if THIRD_PARTIES_CACHE:
        cache_preload_list = os.path.join(
            THIRD_PARTIES_CACHE, CACHE_PRELOAD_LIST_DEFAULT
        )
        cache_preload_pending = os.path.join(
            THIRD_PARTIES_CACHE, CACHE_PRELOAD_PENDING_DEFAULT
        )
        cache_suffix_list = os.path.join(THIRD_PARTIES_CACHE, CACHE_SUFFIX_LIST_DEFAULT)
    else:
        cache_preload_list, cache_preload_pending, cache_suffix_list = None, None, None

    # Load Chrome's latest versioned HSTS preload list.
    if PRELOAD_LIST is None:
        if cache_preload_list and os.path.exists(cache_preload_list):
            utils.debug("Using cached Chrome preload list.", divider=True)
            with open(cache_preload_list, encoding="utf-8") as cache_file:
                PRELOAD_LIST = json.loads(cache_file.read())
        else:
            PRELOAD_LIST = load_preload_list()

            if cache_preload_list:
                utils.debug(
                    "Caching preload list at %s", cache_preload_list, divider=True
                )
                utils.write(utils.json_for(PRELOAD_LIST), cache_preload_list)

    # Load Chrome's current HSTS pending preload list.
    if PRELOAD_PENDING is None:
        if cache_preload_pending and os.path.exists(cache_preload_pending):
            utils.debug("Using cached hstspreload.org pending list.", divider=True)
            with open(cache_preload_pending, encoding="utf-8") as cache_file:
                PRELOAD_PENDING = json.loads(cache_file.read())
        else:
            PRELOAD_PENDING = load_preload_pending()

            if cache_preload_pending:
                utils.debug(
                    "Caching preload pending list at %s",
                    cache_preload_pending,
                    divider=True,
                )
                utils.write(utils.json_for(PRELOAD_PENDING), cache_preload_pending)

    # Load Mozilla's current Public Suffix list.
    if SUFFIX_LIST is None:
        if cache_suffix_list:
            # Retrieve the list if the path does not exist otherwise use the cached copy
            SUFFIX_LIST = load_suffix_list(
                cache_suffix_list, not os.path.exists(cache_suffix_list)
            )
        else:
            # Load the built-in PSL
            SUFFIX_LIST = load_suffix_list()


def inspect_domains(domains, options):
    """Run inspect() against each of the given domains with the given options."""
    # Override timeout, user agent, preload cache, default CA bundle
    global TIMEOUT, USER_AGENT, THIRD_PARTIES_CACHE, CA_FILE, PT_INT_CA_FILE, STORE

    if options.get("timeout"):
        TIMEOUT = int(options["timeout"])
    if options.get("user_agent"):
        USER_AGENT = options["user_agent"]

    # Supported cache flag, a directory to store all third party requests.
    if options.get("cache-third-parties"):
        THIRD_PARTIES_CACHE = options["cache-third-parties"]

    if options.get("ca_file"):
        CA_FILE = options["ca_file"]
        # By default, the store that we want to check is the Mozilla store
        # However, if a user wants to use their own CA bundle, check the
        # "Custom" Option from the sslyze output.
        STORE = "Custom"

    if options.get("pt_int_ca_file"):
        PT_INT_CA_FILE = options["pt_int_ca_file"]

    # If this has been run once already by a Python API client, it
    # can be safely run without hitting the network or disk again,
    # and without overriding the data the Python user set for them.
    initialize_external_data()

    # For every given domain, get inspect data.
    for domain in domains:
        yield inspect(domain)

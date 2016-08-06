#!/usr/bin/env python

import port80
import port443
import requests
import re
import datetime
from time import strptime
import base64
import wget
import json
import os

from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin
from sslyze.plugins.hsts_plugin import HstsPlugin

USER_AGENT = "DHS NCATS: M-15-13 reporting tool"
TIMEOUT = 1

def main(url, outputname, str_print):
    http = port80.port80("http://" + url, url)
    httpwww = port80.port80("http://www." + url, url)
    https = port443.port443("https://" + url, url)
    httpswww = port443.port443("https://www." + url, url)

    basic_check(http)
    basic_check(httpwww)
    basic_check(https)
    basic_check(httpswww)

    https_check(https)
    https_check(httpswww)
    x = generate_tostring(http, httpwww, https, httpswww)
    if str_print:
        print_to_stdout(x)
    else:
        output_csv(x, outputname)

def basic_check(endpoint):
    # First check if the endpoint is live
    try:
        r = requests.get(
            endpoint.domain,
            data={'User-Agent': USER_AGENT},
            timeout=TIMEOUT
        )
        # If status code starts with a 3, it is a redirect
        if len(r.history) > 0 and  str(r.history[0].status_code).startswith('3'):
            endpoint.redirect = True
            endpoint.redirect_to = r.url
        endpoint.live = True
    # The endpoint is live but there is a bad cert
    except requests.exceptions.SSLError:
        endpoint.https_bad_chain = True
        endpoint.live = True
        # If there is a bad cert and the domain is not an https endpoint it is a redirect
        if endpoint.domain[5:] == "http:":
            endpoint.redirect = True
    # Endpoint is not live
    except:
        pass


def https_check(endpoint):
    has_hsts(endpoint)

def has_hsts(endpoint):
    # Use sslyze to check for HSTS
    try:
        # remove the https:// from prefix for sslyze
        hostname = endpoint.domain[8:]
        server_info = ServerConnectivityInfo(hostname=hostname, port=443)
        server_info.test_connectivity_to_server()

        # Call Plugin directly
        plugin = HstsPlugin()
        # Run HSTS plugin from sslyze returning HSTS header
        plugin_result = plugin.process_task(server_info, 'hsts')
        # Sslyze will return OK if HSTS exists
        if "OK" in plugin_result.as_text()[1]:
            endpoint.hsts = "True"
            # Send HSTS header for parsing
            hsts_header_handler(endpoint, plugin_result.as_text()[1])

        # Call plugin directly
        cert_plugin = CertificateInfoPlugin()
        cert_plugin_result = cert_plugin.process_task(server_info, 'certinfo_basic')
        # Parsing Sslzye output for results by line
        for i in cert_plugin_result.as_text():
            # Check for cert expiration
            if "Not After" in i:
                expired_cert(i, endpoint)
            # Check for Hostname validation
            elif "Hostname Validation" in i:
                bad_hostname(i, endpoint)
            # Check if Cert is trusted based on CA Stores
            elif "CA Store" in i:
                bad_chain(i,endpoint)
            # Check for s SHA1 Cert in the Cert Chain
            elif "Weak Signature" in i:
                weak_signature(i, endpoint)
                break
    except:
        # No valid hsts
        pass


def hsts_header_handler(endpoint, header):
    # Remove colons, semi colons, and commas from header
    var = re.sub('[;,:]', ' ', header)
    # Removes extra spaces from header
    x =' '.join(var.split())
    # Split sslyze text from header
    endpoint.hsts_header = x.partition("received ")[-1]
    temp = endpoint.hsts_header.split()
    # Set max age to the string after max-age
    endpoint.hsts_max_age = temp[0][len("max-age="):]
    # check if hsts includes sub domains
    if 'includesubdomains' in endpoint.hsts_header.lower():
        endpoint.hsts_all_subdomains = True
    # Check is hsts is preload
    if 'preload' in endpoint.hsts_header.lower():
        endpoint.hsts_preload = True


def bad_chain(trusted, endpoint):
    # If the cert is not trusted by mozilla it is a bad chain
    if "FAILED" in trusted:
        endpoint.https_bad_chain = True

def bad_hostname(hostname_validation, endpoint):
    # If hostname validation fails
    if "FAILED" in hostname_validation:
        endpoint.https_bad_hostname = True

def expired_cert(expired_date, endpoint):
    # Split the time into an list of subtrings
    temp = expired_date.split()
    # Convert the date returned by sslyze to be comparable to current time
    if datetime.datetime(int(temp[5]),strptime(temp[2], '%b').tm_mon,int(temp[3])) < datetime.datetime.now():
        endpoint.expired_cert = True

def weak_signature(weak_sig, endpoint):
    # If a SHA1 cert exists in the cert chain
    if "INSECURE" in weak_sig:
        endpoint.weak_signature = True

def str_live(http, httpwww, https, httpswww):
    # Domain is live if a single endpoint is live
    if http.live or httpwww.live or https.live or httpswww.live:
        return "True"
    else:
        return "False"

def str_redirect(http, httpwww, https, httpswww):
    # Domain is a redirect if any of the endpoints redirect
    if http.redirect or httpwww.redirect or https.redirect or httpswww.redirect:
        return "True"
    else:
        return "False"

def str_valid_https(http, httpwww, https, httpswww):
    # Domain has valid https if either https enpoints are live or a http redirects to https
    if https.live or httpswww.live:
        return "True"
    elif http.redirect_to[:5] == "https" or httpwww.redirect_to[:5] == "https":
        return "True"
    else:
        return "False"

def str_defaults_https(http, httpwww):
    # Domain defaults to https if http endpoint forwards to https
    if http.redirect or httpwww.redirect:
        if http.redirect_to[:5] == "https" or httpwww.redirect_to[:5] == "https":
            return "True"
        else:
            return "False"
    else:
        return "False"

def str_downgrades_https(https, httpswww):
    # Domain downgrades if https endpoint redirects to http
    if https.redirect or httpswww.redirect:
        if https.redirect_to[:5] == "http:" or httpswww.redirect_to[:5] == "http:":
            return "True"
        else:
            return "False"
    else:
        return "False"

def str_strictly_forces_https(http, httpwww, https, httpswww):
    # Domain Strictly forces https if https is live and http is not,
    # if both http forward to https endpoints or if one http forwards to https and the other is not live
    if ((not http.live and not httpwww.live) and (https.live or httpswww.live)):
        return "True"
    elif http.redirect_to[:5] == "https" and httpwww.redirect_to[:5] == "https":
        return "True"
    elif http.redirect_to[:5] == "https" and not httpwww.live:
        return "True"
    elif httpwww.redirect_to[:5] == "https" and not http.live:
        return "True"
    else:
        return "False"

def str_bad_chain(https, httpswww):
    # Domain has a bad chain if either https endpoints contain a bad chain
    if https.https_bad_chain or httpswww.https_bad_chain:
        return "True"
    else:
        return "False"

def str_bad_hostname(https, httpswww):
    # Domain has a bad hostname if either https endpoint fails hostname validation
    if https.https_bad_hostname or httpswww.https_bad_hostname:
        return "True"
    else:
        return "False"

def str_hsts(https):
    # Domain has hsts ONLY if the https and not the www subdomain has strict transport in the header
    if https.hsts:
        return "True"
    else:
        return "False"

def str_hsts_header(https):
    # Returns the https HSTS header
    if https.hsts:
        return https.hsts_header
    else:
        return ""

def str_max_age(https):
    # Returns the https HSTS max age
    if https.hsts:
        return https.hsts_max_age
    else:
        return ""

def str_hsts_all_subdomains(https):
    # Returns if the https endpoint has "includesubdomains"
    if https.hsts_all_subdomains:
        return "True"
    else:
        return "False"

def str_hsts_preload_ready(https):
    # returns if the hsts header exists, has a max age, includes subdomains, and includes preload
    if https.hsts and https.hsts_max_age != "" and https.hsts_all_subdomains and https.hsts_preload:
        return "True"
    else:
        return "False"

def str_hsts_preload(https):
    # Returns if https endpoint has preload in hsts header
    if https.hsts_preload:
        return "True"
    else:
        return "False"

def str_broken_root(http, https):
    # Returns if both root domains are unreachable
    if not http.live and not https.live:
        return "True"
    else:
        return "False"

def str_broken_www(httpwww, httpswww):
    # Returns if both www sub domains are unreachable
    if not httpwww.live and not httpswww.live:
        return "True"
    else:
        return "False"

def str_expired_cert(https, httpswww):
    # Returns if the either https endpoint has an expired cert
    if https.expired_cert or httpswww.expired_cert:
        return "True"
    else:
        return "False"

def str_weak_signature(https, httpswww):
    # Returns true if either https endpoint contains a SHA1 cert in the chain
    if https.weak_signature or httpswww.weak_signature:
        return "True"
    else:
        return "False"

# Preloaded will only be checked if the domain is preload ready for performance
def str_hsts_preloaded(https):
    # Returns if a domain is on the chromium preload list
    if https.hsts_preload and https.base_domain in preload_list:
        return "True"
    else:
        return "False"


def create_preload_list():
    # Downloads the chromium preloaded domain list and sets it to a global set
    file_url = 'https://chromium.googlesource.com/chromium/src/net/+/master/http/transport_security_state_static.json?format=TEXT'
    file_name = wget.download(file_url, bar=None)
    encoded_string = open(file_name, 'r').read()
    # Decode base64 representation of preload lsit
    decoded_string = base64.b64decode(encoded_string)
    decoded_lines = decoded_string.splitlines()
    json_string = ""
    for line in decoded_lines:
        # Regular Expression only returns lines of the json, ignore comment lines
        if re.search("^([ ]*\/\/|$)", line) is None:
            json_string += (line + "\n")
    json_data = json.loads(json_string)
    global preload_list
    preload_list = {entry['name'] for entry in json_data['entries']}
    # Remove file once the preload list is created
    os.remove(file_name)



def generate_tostring(http, httpwww, https, httpswww):
    # Converts all the domains attributes to a string
    finalstring = ""
    finalstring += http.base_domain + ","
    finalstring += str_live(http, httpwww, https, httpswww) + ","
    finalstring += str_redirect(http, httpwww, https, httpswww) + ","
    finalstring += str_valid_https(http, httpwww, https, httpswww)+ ","
    finalstring += str_defaults_https(http, httpwww)+ ","
    finalstring += str_downgrades_https(https, httpswww)+ ","
    finalstring += str_strictly_forces_https(http, httpwww, https, httpswww)+ ","
    finalstring += str_bad_chain(https, httpswww)+ ","
    finalstring += str_bad_hostname(https, httpswww)+ ","
    finalstring += str_expired_cert(https, httpswww) + ","
    finalstring += str_weak_signature(https, httpswww) + ","
    finalstring += str_hsts(https)+ ","
    finalstring += str_hsts_header(https)+ ","
    finalstring += str_max_age(https)+ ","
    finalstring += str_hsts_all_subdomains(https)+ ","
    finalstring += str_hsts_preload(https) + ","
    finalstring += str_hsts_preload_ready(https)+ ","
    finalstring += str_hsts_preloaded(https)+ ","
    finalstring += str_broken_root(http, https)+ ","
    finalstring += str_broken_www(httpwww, httpswww) + "\n"
    return finalstring

def print_to_stdout(x):
    # Splits the headers and CSV line and the concatinates them for stdout
    temp = ("\nDomain,Live,Redirect,Valid HTTPS,Defaults HTTPS,Downgrades HTTPS," +
    "Strictly Forces HTTPS,HTTPS Bad Chain,HTTPS Bad Host Name,Expired Cert,Weak Signature Chain,HSTS,HTST Header,HSTS Max Age,HSTS All Subdomains," +
    "HSTS Preload,HSTS Preload Ready,HSTS Preloaded,Broken Root,Broken WWW")
    y = temp.split(',')
    z = x.split(',')
    finalstr = ""
    for i in range (0,len(y)):
        finalstr += y[i] + ": " + z[i] + "\n"
    print finalstr

def output_csv(row, outputname):
    # Appends domains information to csv labeled results
    if outputname == None:
        outputname = "results.csv"
    else:
        outputname = outputname + ".csv"
    # appends the rows to the csv, this writes the row to the csv as soon as the results are returned
    output_csv = open(outputname, "a")
    output_csv.write(row)
    output_csv.close()

def parse_args(input, isfile, sorted, outputname, str_print):
    create_preload_list()
    # If not printing to stdout
    if not str_print:
        output_csv("Domain,Live,Redirect,Valid HTTPS,Defaults HTTPS,Downgrades HTTPS," +
            "Strictly Forces HTTPS,HTTPS Bad Chain,HTTPS Bad Host Name,Expired Cert,Weak Signature Chain,HSTS,HTST Header,HSTS Max Age,HSTS All Subdomains," +
            "HSTS Preload,HSTS Preload Ready,HSTS Preloaded,Broken Root,Broken WWW\n", outputname)
    if not isfile == None:
        domains = []
        with open(input) as f:
            for line in f:
                domains.append(line.rstrip('\n').lower())
        f.close()
    else:
        domains = input
    # If the user wants the results sorted sort them in place
    if sorted:
        domains.sort()
    for i in domains:
        main(i, outputname, str_print)



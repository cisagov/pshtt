#!/usr/bin/env python

import httplib
import urllib2
import port80
import port443
import requests
import re
import sslyze
import socket
#time for testing purposes
import time

from sslyze.plugins_finder import PluginsFinder
from sslyze.plugins_process_pool import PluginsProcessPool
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin
from sslyze.plugins.hsts_plugin import HstsPlugin

import sslyze.plugins.plugin_base

def main(url):
    print url
    http = port80.port80("http://" + url, url)
    httpwww = port80.port80("http://" + url, url)
    https = port443.port443("https://" + url, url)
    httpswww = port443.port443("https://www." + url, url)
    #Send all endpoints to basic connectivity check
    basic_check(http)
    basic_check(httpwww)
    basic_check(https)
    basic_check(httpswww)
    https_check(https)
    https_check(httpswww)
    x = generate_tostring(http, httpwww, https, httpswww)
    output_csv(x)

def basic_check(endpoint):
    #First check if the endpoint is live
    try:
        #Change User agent to get around python urllib2 blacklisting
        req = urllib2.Request(endpoint.domain, headers={'User-Agent': "DHS NCATS (M-15-13)"})
        #Attempt to resolve domain with timeout
        con = urllib2.urlopen(req, timeout=1)
        endpoint.live = True
        #if the domain is not equal to what is resolved the endpoint is a redirect
        if endpoint.domain != con.geturl():
            endpoint.redirect = True
            #set redirect to value of resolved domain
            endpoint.redirect_to = con.geturl()
    except:
        #Endpoint is not live
        pass

#Future: add check for expired Cert
def https_check(endpoint):
    #If https is live check for hsts
    if endpoint.live == True:
        has_hsts(endpoint)
    else:
        #If failed check for bad chain
        bad_chain(endpoint)
        #expired_cert(endpoint)

def has_hsts(endpoint):
    #Use sslyze to check for HSTS
    try:
        #remove the https:// from prefix for sslyze because reasons
        hostname = endpoint.domain[8:]
        server_info = ServerConnectivityInfo(hostname=hostname, port=443)
        server_info.test_connectivity_to_server()

        # Call Plugin directly
        plugin = HstsPlugin()
        #Run HSTS plugin from sslyze returning HSTS header
        plugin_result = plugin.process_task(server_info, 'hsts')
        # print plugin_result.as_text()[1]
        if "OK" in plugin_result.as_text()[1]:
            endpoint.hsts = "True"
            #Send HSTS header for parsing
            hsts_header_handler(endpoint, plugin_result.as_text()[1])
    except:
        #No valid hsts
        pass


def hsts_header_handler(endpoint, header):
    #Remove colons, semi colons, and commas from header
    var = re.sub('[;,:]', '', header)
    #Removes extra spaces from header
    x =' '.join(var.split())
    #Split sslyze text from header
    endpoint.hsts_header = x.partition("received ")[-1]
    #print endpoint.hsts_header
    #check if hsts includes sub domains
    if 'includeSubDomains' in endpoint.hsts_header:
        endpoint.hsts_all_subdomains = "True"
        #Pull max age between the string max-age and the beggining of includes subdomains
        endpoint.hsts_max_age = x.partition("max-age=")[-1].rpartition(" i")[0]
    else:
        #if the header doesnt inlcude sub domains max age is after max-age=
        endpoint.hsts_max_age = x.partition("max-age=")[-1]
    #Check is hsts is preloaded
    if 'preload' in endpoint.hsts_header:
        endpoint.hsts_preloaded = "True"

def bad_chain(endpoint):
    # Use ssylze to check for bad chain
    try:
        # remove the https:// from prefix for sslyze because reasons
        hostname = endpoint.domain[8:]
        server_info = ServerConnectivityInfo(hostname=hostname, port=443)
        server_info.test_connectivity_to_server()

        # Call Plugin directly
        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, 'certinfo_basic')
        if not plugin_result.is_certificate_chain_order_valid:
            url.https_bad_chain = "True"
    except:
        pass
        # Future: why is the bade chain happening
        # print plugin_result.as_text()

def str_live(http, httpwww, https, httpswww):
    if http.live or httpwww.live or https.live or httpswww.live:
        return "True"
    else:
        return "False"

def str_redirect(http, httpwww, https, httpswww):
    if http.redirect or httpwww.redirect or https.redirect or httpswww.redirect:
        return "True"
    else:
        return "False"

def str_valid_https(http, httpwww, https, httpswww):
    if https.live or httpswww.live:
        return "True"
    elif http.redirect_to[:5] == "https" or httpwww.redirect_to[:5] == "https":
        return "True"
    else:
        return "False"

def str_defaults_https(http, httpwww):
    if http.redirect or httpwww.redirect:
        if http.redirect_to[:5] == "https" or httpwww.redirect_to[:5] == "https":
            return "True"
        else:
            return "False"
    else:
        return "False"

def str_downgrades_https(https, httpswww):
    if https.redirect or httpswww.redirect:
        if https.redirect_to[:5] == "http:" or httpswww.redirect_to[:5] == "http:":
            return "True"
        else:
            return "False"
    else:
        return "False"

def str_strictly_forces_https(http, httpwww, https, httpswww):
    if ((not http.live and not httpwww.live) and (https.live or httpswww.live)):
        return "True"
    elif http.redirect or httpwww.redirect:
        if http.redirect_to[:5] == "https" or httpwww.redirect_to[:5] == "https":
            return "True"
        else:
            return "False"
    else:
        return "False"

def str_bad_chain(https, httpswww):
    if https.https_bad_chain or httpswww.https_bad_chain:
        return "True"
    else:
        return "False"

def str_bad_hostname(https, httpswww):
    if not https.live and not httpswww.live:
        return "True"
    else:
        return "False"

def str_hsts(https, httpswww):
    if https.hsts or httpswww.hsts:
        return "True"
    else:
        return "False"

def str_hsts_header(https, httpswww):
    if https.hsts:
        return https.hsts_header
    elif httpswww.hsts_header:
        return httpswww.hsts_header
    else:
        return ""

def str_max_age(https, httpswww):
    if https.hsts:
        return https.hsts_max_age
    elif httpswww.hsts:
        return httpswww.hsts_max_age
    else:
        return ""

def str_hsts_all_subdomains(https, httpswww):
    if https.hsts_all_subdomains or httpswww.hsts_all_subdomains:
        return "True"
    else:
        return "False"

def str_hsts_preload_ready(https, httpswww):
    if https.hsts and https.hsts_max_age != "" and https.hsts_all_subdomains and https.hsts_preloaded:
        return "True"
    elif httpswww.hsts and httpswww.hsts_max_age != "" and httpswww.hsts_all_subdomains and httpswww.hsts_preloaded:
        return "True"
    else:
        return "False"

def str_hsts_preloaded(https, httpswww):
    if https.hsts_preloaded or httpswww.hsts_preloaded:
        return "True"
    else:
        return "False"

def str_broken_root(httpwww, httpswww):
    if not httpwww.live and not httpswww.live:
      return "True"
    else:
        return "False"

def str_broken_www(httpwww, httpswww):
    if not httpwww.live or not httpswww.live:
        return "True"
    else:
        return "False"

def generate_tostring(http, httpwww, https, httpswww):
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
    finalstring += str_hsts(https, httpswww)+ ","
    finalstring += str_hsts_header(https, httpswww)+ ","
    finalstring += str_max_age(https, httpswww)+ ","
    finalstring += str_hsts_all_subdomains(https, httpswww)+ ","
    finalstring += str_hsts_preload_ready(https, httpswww)+ ","
    finalstring += str_hsts_preloaded(https, httpswww)+ ","
    finalstring += str_broken_root(httpwww, httpswww)+ ","
    finalstring += str_broken_www(httpwww, httpswww) + "\n"
    return finalstring

def output_csv(row):
    output_csv = open("results.csv", "a")
    output_csv.write(row)
    output_csv.close()


start_time = time.time()
output_csv("Domain,Live,Redirect,Valid HTTPS,Defaults HTTPS,Downgrades HTTPS," +
    "Strictly Forces HTTPS,HTTPS Bad Chain,HTTPS Bad Host Name,HSTS,HTST Header,HSTS Max Age,HSTS All Subdomains," +
    "HSTS Preload Ready,HSTS Preloaded,Broken Root,Broken WWW\n")
domains = []
# with open('feddomains.csv') as f:
#     for line in f:
#         domains.append(line.rstrip('\n').lower())
# f.close()
domains.append("atf.gov".lower())
domains.append("18f.gov".lower())

for i in domains:
    main(i)
sec = time.time() - start_time
print("--- %s minutes, %s seconds ---" % (sec/60, sec))

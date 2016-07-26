#!/usr/bin/python
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
import datetime
from time import strptime

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
    #https_check(httpswww)
    x = generate_tostring(http, httpwww, https, httpswww)
    output_csv(x)

def basic_check(endpoint):
    #First check if the endpoint is live
    try:
        #Change User agent to get around python urllib2 blacklisting
        req = urllib2.Request(endpoint.domain, headers={'User-Agent': "DHS NCATS (m-15-13)"})
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
    has_hsts(endpoint)


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
        #print plugin_result.as_text()
        if "OK" in plugin_result.as_text()[1]:
            endpoint.hsts = "True"
            #Send HSTS header for parsing
            hsts_header_handler(endpoint, plugin_result.as_text()[1])

        cert_plugin = CertificateInfoPlugin()
        cert_plugin_result = cert_plugin.process_task(server_info, 'certinfo_basic')
        #Parsing Sslzye output for results by line
        for i in cert_plugin_result.as_text():
            #print i
            if "Not After" in i:
                expired_cert(i, endpoint)
            elif "Hostname Validation" in i:
                bad_hostname(i, endpoint)
            elif "CA Store" in i:
                bad_chain(i,endpoint)
            #Used to avoid iterating through the entire results text
            elif "Weak Signature" in i:
                break

        """print cert_plugin_result.as_text()[1]
        print cert_plugin_result.as_text()[2]
        print cert_plugin_result.as_text()[3]
        print cert_plugin_result.as_text()[4]
        print cert_plugin_result.as_text()[5]
        print cert_plugin_result.as_text()[6]
        print cert_plugin_result.as_text()[7]
        print cert_plugin_result.as_text()[8]
        print cert_plugin_result.as_text()[9]
        print cert_plugin_result.as_text()[10]
        print cert_plugin_result.as_text()[11]
        print cert_plugin_result.as_text()[12]
        print cert_plugin_result.as_text()[13]+ " This is the hostname validation check"
        print cert_plugin_result.as_text()[14] + " This is the mozills store"
        print cert_plugin_result.as_text()[15]
        print cert_plugin_result.as_text()[16]
        print cert_plugin_result.as_text()[17]"""
    except:
        #No valid hsts
        pass


def hsts_header_handler(endpoint, header):
    #Remove colons, semi colons, and commas from header
    var = re.sub('[;,:]', ' ', header)
    #Removes extra spaces from header
    x =' '.join(var.split())
    #Split sslyze text from header
    endpoint.hsts_header = x.partition("received ")[-1]
    #print endpoint.hsts_header
    temp = endpoint.hsts_header.split()
    endpoint.hsts_max_age = temp[0][len("max-age="):]
    #check if hsts includes sub domains
    if 'includesubdomains' in endpoint.hsts_header.lower():
        endpoint.hsts_all_subdomains = True
        #Pull max age between the string max-age and the beggining of includes subdomains
        #endpoint.hsts_max_age = x.partition("max-age=")[-1].rpartition(" ")[0]
    else:
        #if the header doesnt inlcude sub domains max age is after max-age=
        #endpoint.hsts_max_age = x.partition("max-age=")[-1]
        pass
    #Check is hsts is preload
    if 'preload' in endpoint.hsts_header:
        endpoint.hsts_preload = True


def bad_chain(mozilla_trusted, endpoint):
    #If the cert is not trusted by mozilla it is a bad chain
    if "FAILED" in mozilla_trusted:
        endpoint.htts_bad_chain = True

def bad_hostname(hostname_validation, endpoint):
    if "FAILED" in hostname_validation:
        endpoint.https_bad_hostname = True

def expired_cert(expired_date, endpoint):
    #Split the time into an list of subtrings
    temp = expired_date.split()
    #Convert the date returned by sslyze to be comparable to current time
    if datetime.datetime(int(temp[5]),strptime(temp[2], '%b').tm_mon,int(temp[3])) < datetime.datetime.now():
        endpoint.expired_cert = True

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
    elif http.redirect_to[:5] == "https" and httpwww.redirect_to[:5] == "https":
        return "True"
    elif http.redirect_to[:5] == "https" and not httpwww.live:
        return "True"
    elif httpwww.redirect_to[:5] == "https" and not http.live:
        return "True"
    else:
        return "False"

def str_bad_chain(https, httpswww):
    if https.https_bad_chain or httpswww.https_bad_chain:
        return "True"
    else:
        return "False"

def str_bad_hostname(https, httpswww):
    if https.https_bad_hostname or httpswww.https_bad_hostname:
        return "True"
    else:
        return "False"

def str_hsts(https):
    if https.hsts:
        return "True"
    else:
        return "False"

def str_hsts_header(https):
    if https.hsts:
        return https.hsts_header
    else:
        return ""

def str_max_age(https):
    if https.hsts:
        return https.hsts_max_age
    else:
        return ""

def str_hsts_all_subdomains(https):
    if https.hsts_all_subdomains:
        return "True"
    else:
        return "False"

def str_hsts_preload_ready(https):
    if https.hsts and https.hsts_max_age != "" and https.hsts_all_subdomains and https.hsts_preload:
        return "True"
    else:
        return "False"

def str_hsts_preload(https):
    if https.hsts_preload:
        return "True"
    else:
        return "False"

def str_broken_root(http, https):
    if not http.live and not https.live:
      return "True"
    else:
        return "False"

def str_broken_www(httpwww, httpswww):
    if not httpwww.live and not httpswww.live:
        return "True"
    else:
        return "False"

def str_expired_cert(https, httpswww):
    if https.expired_cert or httpswww.expired_cert:
        return "True"
    else:
        return "False"

#Preloaded will only be checked if the domain is preload ready
def str_hsts_preloaded(https):
    if https.hsts_preload and https.base_domain in open('preloadedgov.txt').read():
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
    finalstring += str_expired_cert(https, httpswww) + ","
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

def output_csv(row):
    output_csv = open("results.csv", "a")
    output_csv.write(row)
    output_csv.close()


start_time = time.time()
output_csv("Domain,Live,Redirect,Valid HTTPS,Defaults HTTPS,Downgrades HTTPS," +
    "Strictly Forces HTTPS,HTTPS Bad Chain,HTTPS Bad Host Name,Expired Cert,HSTS,HTST Header,HSTS Max Age,HSTS All Subdomains," +
    "HSTS Preload,HSTS Preload Ready,HSTS Preloaded,Broken Root,Broken WWW\n")
domains = []
with open('feddomains.csv') as f:
    for line in f:
        domains.append(line.rstrip('\n').lower())
f.close()
#domains.append("airnow.gov".lower())
#domains.append("atf.gov".lower())
#domains.append("bnl.gov".lower())
#domains.append("chcoc.gov".lower())
#domains.append("cuidadodesalud.gov".lower())
#domains.append("dsac.gov".lower())
#domains.append("lmrcouncil.gov".lower())
#domains.append("whitehouse.gov".lower())
#domains.append("18f.gov".lower())

for i in domains:
    main(i)
sec = time.time() - start_time
print("--- %s minutes, %s seconds ---" % (sec/60, sec))

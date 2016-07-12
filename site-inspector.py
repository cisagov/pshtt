#!/usr/bin/python
import httplib
import urllib2
import Domain
import requests
import re
import sslyze
import socket

from sslyze.plugins_finder import PluginsFinder
from sslyze.plugins_process_pool import PluginsProcessPool
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.ssl_settings import TlsWrappedProtocolEnum
import sslyze.plugins.plugin_base


def main(url):
    #url.base_domain = url.domain
    if is_live(url):
        is_redirect(url)
    if is_valid_https(url):
        defaults_to_https(url)
        downgrades_or_forces_https(url)
        has_hsts(url)
        hsts_preload_ready(url)
        https_bad_chain(url)
        https_bad_hostname(url)
    else:
        url.defaults_to_https = "False"
        url.downgrades_https = "False"
        url.strictly_forces_https = "False"
        url.https_bad_chain = "False"
        url.https_bad_hostname = "False"
        url.hsts = "False"
        url.hsts_preloaded = "False"
        url.hsts_all_subdomains = "False"
        url.hsts_header = "False"
        url.hsts_max_age = "False"
    broken_www(url)


#Checks http:// and http://www for a domain and if neither are valid the site is not live
def is_live(url):
    try:
        a=urllib2.urlopen("http://" + url.base_domain)
        url.domain = "http://" + url.base_domain
        url.live = "True"
        return True
    except Exception:
        try:
            #if http:// domain does not exist try http://www
            a = urllib2.urlopen("http://www." + url.base_domain)
            url.domain = "http://www." + url.base_domain
            url.live = "True"
            return True
        except Exception:
            url.live = "False"
            return False


def is_redirect(url):
    req = urllib2.Request(url.domain)
    res = urllib2.build_opener()
    f = res.open(req)
    if url.domain == f.url:
        url.redirect = "False"
        url.canonical = str(url.domain)
    else:
        url.redirect = "True"
        url.canonical = f.url
        url.redirect_to = f.url
        #If the redirect starts with https then the redirect it the valid https
        if url.redirect_to[:5] == "https":
            url.https_domain = url.redirect_to
    #print f.headers.dict
    #print f.status

def is_valid_https(url):
    #change to split ur.domain to check for https and not only http
    try:
        a = urllib2.urlopen("https://" + url.base_domain)
        url.https_domain = "https://" + url.base_domain
        #print a.getcode()
        url.valid_https = "True"
        return True
    except Exception:
        try:
            a = urllib2.urlopen("https://www." + url.base_domain)
            url.https_domain = "https://www." + url.base_domain
            url.valid_https = "True"
            return True
        except Exception:
            url.valid_https = "False"
            return False

def defaults_to_https(url):
    if url.canonical[:5] == "https":
        url.defaults_to_https = "True"
    else:
        url.defaults_to_https = "False"

def downgrades_or_forces_https(url):
    try:
        req = urllib2.Request("https://" + url.base_domain)
        req2 = urllib2.Request("http://" + url.base_domain)
        res = urllib2.build_opener()
        f = res.open(req)
        f2 = res.open(req2)
        if f2.url == f.url and f2.url[:5] == "https":
            url.strictly_forces_https = "True"
            url.downgrades_https = "False"
        elif f2.url == f.url:
            url.strictly_forces_https = "False"
            url.downgrades_https = "True"
        else:
            url.strictly_forces_https = "False"
            url.downgrades_https = "False"
    except:
        #no valid https or http
        url.downgrades_https = "False"
        url.strictly_forces_https = "False"

#add checking certificate of all different valid chains
def https_bad_chain(url):
    # Script to get the list of SSLv3 cipher suites supported by smtp.gmail.com
    # You should use the process pool to make scans quick, but you can also call plugins directly
    hostname = url.base_domain
    server_info = ServerConnectivityInfo(hostname=hostname, port=443)
    server_info.test_connectivity_to_server()

    from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin
    #Call Plugin directly
    plugin = CertificateInfoPlugin()
    plugin_result = plugin.process_task(server_info, 'certinfo_basic')
    if plugin_result.is_certificate_chain_order_valid:
        url.https_bad_chain = "False"
    else:
        url.https_bad_chain = "True"
    #print plugin_result.as_text()




def https_bad_hostname(url):#
    try:
        req = urllib2.Request("https://" + url.base_domain)
        res = urllib2.build_opener()
        f = res.open(req)
        url.https_bad_hostname = "False"
    except:
        # no valid https or http
        url.https_bad_hostname = "True"

def has_hsts(url):
    if url.valid_https == "True":
        try:
            req = requests.get('https://' + url.base_domain)
            #req = requests.get(url.redirect_to)
            #print url.base_domain
            #print req.headers
            if 'strict-transport-security' in req.headers:
                url.hsts = "True"
                req_header_handlers(url, req.headers)
            else:
                url.hsts = "False"
                url.hsts_preloaded = "False"
                url.hsts_all_subdomains = "False"
        except requests.exceptions.SSLError as e:
            url.hsts = "False"#
            url.hsts_preloaded = "False"
            url.hsts_all_subdomains = "False"
    else:
        url.hsts = "False"
        url.hsts_preloaded = "False"
        url.hsts_all_subdomains = "False"
        url.hsts_header = "False"
        url.hsts_max_age = "False"

#preload should actually be based on Google list on github of preloaded websites
def req_header_handlers(url, headers):
    url.hsts_header = re.sub('[;,]', '', headers['strict-transport-security'])
    #print url.hsts_header"http://example.com"
    url.hsts_max_age = (url.hsts_header.partition(' ')[0])[8:]
    if 'includeSubDomains' in url.hsts_header:
        url.hsts_all_subdomains = "True"
    else:
        url.hsts_all_subdomains = "False"
    if 'preload' in url.hsts_header:
        url.hsts_preloaded = "True"
    else:
        url.hsts_preloaded = "False"

def hsts_preload_ready(url):
    if (url.hsts_preloaded == "True" and url.hsts_all_subdomains == "True"
            and url.strictly_forces_https == "True" and url.hsts_max_age != ""):
        url.hsts_preload_ready = "True"
    else:
        url.hsts_preload_ready = "False"

def broken_www(url):
    if broken_root(url, "https://www.") and broken_root(url, "http://www."):
        url.broken_root = "True"
        url.broken_www = "True"
    elif broken_root(url, "https://www.") or broken_root(url, "http://www."):
        url.broken_root = "False"
        url.broken_www = "True"
    else:
        url.broken_root = "False"
        url.broken_www = "False"

def broken_root(url, prefix):
    try:
        urllib2.urlopen(prefix + url.base_domain, timeout=1)

        return False
    except Exception:
        # no valid https://www or http://www
        return True

def out_csv(results):
    output_csv = open("results.csv", "wb")
    output_csv.write("Domain,Base Domain,Canonical,Live,Redirect,Redirect To,Valid HTTPS,Defaults HTTPS,Downgrades HTTPS," +
    "Strictly Forces HTTPS,HTTPS Bad Chain,HTTPS Bad Host Name,HSTS,HTST Header,HSTS Max Age,HSTS All Subdomains," +
    "HSTS Preload Ready,HSTS Preloaded,Broken Root,Broken WWW\n")
    for i in results:
        output_csv.write(i.output_to_csv())
    output_csv.close()





domains = []
with open('domains2.csv') as f:
    for line in f:
        domains.append(Domain.Domain(line.rstrip('\n')))
f.close()
#domains.append(Domain.Domain("cybercrime.gov"))
#domains.append(Domain.Domain("dea.gov"))
#domains.append(Domain.Domain("cwc.gov"))
#domains.append(Domain.Domain("dems.gov"))
#domains.append(Domain.Domain("aidrefugees.gov"))
#domains.append(Domain.Domain("aids.gov"))
#domains.append(Domain.Domain("bbg.gov"))
#domains.append(Domain.Domain("18f.gov"))
#domains.append(Domain.Domain("arctic.gov"))
#domains.append(Domain.Domain("aapi.GOV"))
for i in domains:
    main(i)
    #print "Testing"
out_csv(domains)
#for k in domains:
    #print k


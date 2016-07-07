#!/usr/bin/python
import httplib
import urllib2
import Domain
import requests
import re

def main(url):
    #url.base_domain = url.domain
    if is_live(url):
        is_redirect(url)
    is_valid_https(url)
    defaults_to_https(url)
    downgrades_or_forces_https(url)
    https_bad_hostname(url)
    has_hsts(url)
    broken_www(url)
    hsts_preload_ready(url)

def is_live(url):
    try:
        a=urllib2.urlopen(url.domain)
        #print a.getcode()
        url.live = "True"
        return True
    except urllib2.HTTPError, e:
        #print(e.code)
        url.live = "False"
        return False
    except urllib2.URLError, e:
        #print(e.args)
        url.live = "False"
        return False
    except Exception:
        #print "General Exception"
        url.live = "False"
        return False

def is_redirect(url):
    #opener = urllib2.build_opener(urllib2.HTTPRedirectHandler)
    #request = opener.open(url)
    #print request.url
    #httplib.HTTPConnection.debuglevel = 1
    req = urllib2.Request(url.domain)
    res = urllib2.build_opener()
    #test = urllib2.HTTPSHandler(req)
    #print test
    f = res.open(req)
    if url.domain == f.url:
        url.redirect = "False"
        url.canonical = str(url.domain)
    else:
        url.redirect = "True"
        url.canonical = str(f.url)
        url.redirect_to = str(f.url)
    #print f.headers.dict
    #print f.status

def is_valid_https(url):
    #change to split ur.domain to check for https and not only http
    try:
        a = urllib2.urlopen("https://" + url.base_domain)
        #print a.getcode()
        url.valid_https = "True"
        return True
    except urllib2.HTTPError, e:
        print(e.code)
        url.valid_https = "False"
        return False
    except urllib2.URLError, e:
        print(e.args)
        url.valid_https = "False"
        return False
    except Exception:
        #print "General Exception"
        url.valid_https = "False"

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

def https_bad_chain(url):
    return 4

def https_bad_hostname(url):
    try:
        req = urllib2.Request("https://" + url.base_domain)
        res = urllib2.build_opener()
        f = res.open(req)
        url.https_bad_hostname = "False"
    except:
        # no valid https or http
        url.https_bad_hostname = "True"

def has_hsts(url):
    try:
        req = requests.get('https://' + url.base_domain)
        #req = requests.get(url.redirect_to)
        #print url.base_domain
        #print req.headers
        if 'strict-transport-security' in req.headers:
            url.hsts = "True"
            req_header_handlers(url, req.headers)
            #url.hsts_header = (req.headers['strict-transport-security'])
            #url.hsts_max_age = url.hsts_header.replace("max-age=", "")
        else:
            url.hsts = "False"
            url.hsts_preloaded = "False"
            url.hsts_all_subdomains = "False"
    except requests.exceptions.SSLError as e:
        url.hsts = "False"
        url.hsts_preloaded = "False"
        url.hsts_all_subdomains = "False"


def req_header_handlers(url, headers):
    url.hsts_header = headers['strict-transport-security']
    url.hsts_max_age = re.findall(r'max-age=(.*?);', url.hsts_header)[0]
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
        req = urllib2.Request(prefix + url.base_domain)
        res = urllib2.build_opener()
        f = res.open(req)
        return False
    except:
        # no valid https://www or http://www
        return True




domains = []
domains.append(Domain.Domain("cybercrime.gov"))
domains.append(Domain.Domain("dea.gov"))
domains.append(Domain.Domain("cwc.gov"))
domains.append(Domain.Domain("dems.gov"))
domains.append(Domain.Domain("aidrefugees.gov"))
domains.append(Domain.Domain("aids.gov"))
domains.append(Domain.Domain("bbg.gov"))
domains.append(Domain.Domain("18f.gov"))
domains.append(Domain.Domain("arctic.gov"))
for i in domains:
    main(i)
for k in domains:
    print k

#domain = Domain.Domain("cybercrime.gov")
#domain1 = Domain.Domain("dea.gov")
#domain2 = Domain.Domain("cwc.gov")
#domain2 = Domain.Domain("dems.gov")
#domain2 = Domain.Domain("aidrefugees.gov")
#domain2 = Domain.Domain("aids.gov")
#domain1 = Domain.Domain("bbg.gov")
#domain1 = Domain.Domain("18f.gov")
#domain1 = Domain.Domain("arctic.gov")
#main(domain)
#main(domain1)
#main(domain2)
#print domain
#print domain1
#print domain2

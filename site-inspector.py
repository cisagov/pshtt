#!/usr/bin/python
import httplib
import urllib2
import Domain

def main(url):
    #url.base_domain = url.domain
    if is_live(url):
        is_redirect(url)
    is_valid_https(url)
    defaults_to_https(url)
    downgrades_or_forces_https(url)

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




domain = Domain.Domain("cybercrime.gov")
#domain1 = Domain.Domain("dea.gov")
#domain2 = Domain.Domain("cwc.gov")
#domain2 = Domain.Domain("dems.gov")
#domain2 = Domain.Domain("aidrefugees.gov")
domain1 = Domain.Domain("bbg.gov")
domain2 = Domain.Domain("18f.gov")
main(domain)
main(domain1)
main(domain2)
print domain
print domain1
print domain2

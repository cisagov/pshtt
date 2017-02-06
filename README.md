## Pushing HTTPS :lock:
`pshtt` (_"pushed"_) is a tool to scan domains for HTTPS best practices. It saves its results to a CSV (or JSON).

`pshtt` was developed to _push_ organizations— especially large ones like the US Federal Government :us: — to adopt HTTPS across the enterprise. Federal .gov domains must comply with [M-15-13](https://https.cio.gov), a 2015 memorandum from the White House Office of Management and Budget that requires federal agencies to enforce HTTPS on their web sites and services by the end of 2016. Much has been done, and [still more yet to do](https://18f.gsa.gov/2017/01/04/tracking-the-us-governments-progress-on-moving-https/).

`pshtt` is a collaboration between GSA's 18F and the DHS National Cybersecurity Assessments and Technical Services team.

## Getting Started
`pshtt` can be installed directly via pip:
```bash
pip install pshtt
```

#### Usage and examples

```bash
pshtt [options] DOMAIN...
pshtt [options] INPUT

pshtt dhs.gov
pshtt --output=homeland.csv --debug dhs.gov us-cert.gov usss.gov
pshtt --sorted current-federal.csv
```
Note: if INPUT ends with `.csv`, domains will be read from CSV. CSV output will always be written to disk (unless --json is specified), defaulting to `results.csv`.

#### Options
```bash
  -h --help                   Show this message.
  -s --sorted                 Sort output by domain, A-Z.
  -o --output=OUTFILE         Name output file. (Defaults to "results".)
  -j --json                   Get results in JSON. (Defaults to CSV.)
  -d --debug                  Print debug output.
  -u --user-agent=AGENT       Override user agent.
  -t --timeout=TIMEOUT        Override timeout (in seconds).
  -p --preload-cache=PRELOAD  Cache preload list, and where to cache it.
```
##### Using Docker (optional)
```bash
docker build -t pshtt/cli .

docker run --rm -it \
  --name pshtt \
  -v $(pwd):/data \
  -e USER_ID=1042 \           /* Change the ownership of the files (**e.g** results)
  -e GROUP_ID=1042 \         to the user with id 1042 and to the group with id 1042. */
  pshtt/cli
```

## What's Checked?
A domain is checked on its four endpoints:
* `http://`
* `http://www`
* `https://`
* `https://www`

The following values are returned in `results.csv`:
#### Domain and redirect info
>* `Domain` - The domain you're scanning!
* `Base Domain` - The second-level domain of `Domain`.
* `Canonical URL` - A judgment call based on the observed redirect logic of the domain.
* `Live` - The domain is "live" if any endpoint is live.
* `Redirect` - The domain is a "redirect domain" if at least one endpoint is a redirect, and all endpoints are either redirects or down.
* `Redirect to` - If a domain is a "redirect domain", where does it redirect to?

#### Landing on HTTPS
>* `Valid HTTPS` - A domain has "valid HTTPS" if it responds on port 443 at its canonical hostname with an unexpired valid certificate for the hostname.
* `Defaults to HTTPS` - A domain "defaults to HTTPS" if its canonical endpoint uses HTTPS.
* `Downgrades HTTPS` -  A domain "downgrades HTTPS" if HTTPS is supported in some way, but its canonical HTTPS endpoint immediately redirects internally to HTTP.
* `Strictly Forces HTTPS` - This is different than whether a domain "defaults" to HTTPS. A domain "Strictly Forces HTTPS" if one of the HTTPS endpoints is "live", and if both HTTP endpoints are either down or redirect immediately to any HTTPS URI. An HTTP redirect can go to HTTPS on another domain, as long as it's immediate. (A domain with an invalid cert can still be enforcing HTTPS.)

#### Common errors
>* `HTTPS Bad Chain` - A domain has a bad chain if either HTTPS endpoints contain a bad chain.
* `HTTPS Bad Hostname` - A domain has a bad hostname if either HTTPS endpoint fails hostname validation
* `HTTPS Expired Cert` - A domain has an expired certificate if the either HTTPS endpoint has an expired certificate.

#### HSTS
>* `HSTS` - A domain has HTTP Strict Transport Security enabled if its canonical HTTPS endpoint has HSTS enabled.
* `HSTS Header` - This field provides a domain's HSTS header at its canonical endpoint.
* `HSTS Max Age` - A domain's HSTS max-age is its canonical endpoint's max-age.
* `HSTS Entire Domain` - A domain has HSTS enabled for the entire domain if its **root HTTPS endpoint** (_not the canonical HTTPS endpoint_) has HSTS enabled and uses the HSTS `includeSubDomains` flag.
* `HSTS Preload Ready` - A domain is HSTS "preload ready" if its **root HTTPS endpoint** (_not the canonical HTTPS endpoint_) has HSTS enabled, has a max-age of at least 18 weeks, and uses the `includeSubDomains` and `preload` flag.
* `HSTS Preload Pending` - A domain is "preload pending" when it appears in the [Chrome preload pending list](https://hstspreload.org/api/v2/pending).
* `HSTS Preloaded` - A domain is HSTS preloaded if its domain name appears in the [Chrome preload list](https://chromium.googlesource.com/chromium/src/net/+/master/http/transport_security_state_static.json), regardless of what header is present on any endpoint.

#### Scoring
These three fields use the previous results to come to high-level conclusions about a domain's behavior.
>* `Domain Supports HTTPS` - A domain 'Supports HTTPS' when it doesn't downgrade and has valid HTTPS, or when it doesn't downgrade and has a bad chain but not a bad hostname (a bad hostname makes it clear the domain isn't actively attempting to support HTTPS, whereas an incomplete chain is just a mistake.). Domains with a bad chain "support" HTTPS but user-side errors can be expected.
* `Domain Enforces HTTPS` - A domain that 'Enforces HTTPS' must 'Support HTTPS' and default to HTTPS. For websites (where `Redirect` is `false`) they are allowed to _eventually_ redirect to an `https://` URI. For "redirect domains" (domains where the `Redirect` value is `true`) they must _immediately_ redirect clients to an `https://` URI (even if that URI is on another domain) in order to be said to enforce HTTPS.
* `Domain Uses Strong HSTS` - A domain 'Uses Strong HSTS' when the max-age ≥ 31536000.

## Who uses pshtt?
* GSA maintains [Pulse](https://pulse.cio.gov), a dashboard that tracks how federal government domains are meeting best practices on the web. [Pulse is open source](https://github.com/18F/pulse).
* The Freedom of the Press Foundation runs [securethe.news](https://securethe.news), a site that aims to "track and promote the adoption of HTTPS encryption by major news organizations' websites". [Secure the News is open source](https://securethe.news/blog/secure-news-open-source/).
* DHS issues [HTTPS Reports](https://18f.gsa.gov/2017/01/06/open-source-collaboration-across-agencies-to-improve-https-deployment/) to federal executive branch agencies.

## Acknowledgements
This code was modeled after [Ben Balter](https://github.com/benbalter)'s [site-inspector](https://github.com/benbalter/site-inspector), with significant guidance from [konklone](https://github.com/konklone).

## Public domain
This project is in the worldwide [public domain](LICENSE.md).

This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.

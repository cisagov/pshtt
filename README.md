pshtt
======================

Scans domains and returns data based HTTPS best practices. 

______________________________________________________________________________________
Description:

  Site-inspector-python is a Python tool for testing domains for HTTPs best practices and
  identifying security/usability issues. The results of this tool should be used to help
  improve the Cyber Hygiene of domains in the interest of their stakeholders.


______________________________________________________________________________________
Getting Started:

  You must first install all dependencies via pip:
  
    pip install -r requirments.txt
  
______________________________________________________________________________________  
Usage:

    site_inspector_python.py (INPUT ... | --file INFILE) [--output OUTFILE | --print] [--sorted]
    site_inspector_python.py (-h | --help)
  
  Options:
    -h --help             show this
    -s --sorted           sort output csv
    -o --output=OUTFILE   specify output name for csv
    -f --file=INFILE      specify input for domains from a csv
    -p --print            Print results to terminal
    
    
Examples:
    
  python site_inspector_python example.com --print 
  
  python site_inspector_python --file domains.csv --outpout myresults --sorted
  
  python site_inspector_python google.com example.com dhs.gov --sorted  


______________________________________________________________________________________
What's Checked:

  Domain- A domain is checked on it's four endpoints http://example.com, http://www.example.com, 
  https://example.com, https://www.example.com 
  
  Live-If any of the endpoint respond it is True
  Redirect- If any of the endpoints redirect it is True 
  
  Valid HTTPS- True if a either HTTPS endpoint is live or HTTP endpoints forward to HTTPS
  
  Defaults HTTPS-If the HTTP endpoint forwards to a HTTPS
  Downgrades HTTPS- If a HTTPS endpoint forwards to HTTP
  
  Strictly Forces HTTPS- If only HTTPS endpoints are live or if a HTTP endpoint is live it forwards to HTTPS
  
  HTTPS Bad Chain- If the cert is not trusted based on CA stores 
  
  HTTPS Bad Host Name- If the cert fails hostname validation
  
  Expired Cert- If the cert has expired
  
  Weak Signature Chain-A SHA1 cert exists in the cert chain
  
  HSTS- If Strict Transport is in the header of the HTTPS endpoint (not the https://www subdomain)
  
  HSTS Header- The contents of the HSTS Header
  
  HSTS Max Age- The Max Age of the HSTS Header
  
  HSTS All Subdomain-If "include sub subdomains" is in the HSTS header
  
  HSTS Preload- If "preload" is in the HSTS Header
  
  HSTS Preload Ready- If the domains has HSTS, HSTS Max Age, HSTS All Subdomains, and HSTS Preload
  
  HSTS Preloaded- If the domain is on the Google Chrome Preload list
  
  Broken Root- If the http:// and https:// domains are no live
  
  Broken WWW- if the http://www. and https://www. are not live
  
  ______________________________________________________________________________________
  
  
  This tool was developed in order to help the .gov domain space comply with Memorandum- Policy to Require 
  Secure Connections across Federal Website and Web Services (m-15-13) and push for preloading *.gov
  
  Compliance guide: https://https.cio.gov/guide/
  Preload Check list: https://hstspreload.appspot.com/
  
  ______________________________________________________________________________________
   Acknowledgements:
   
   This code was modeled after site-inspector on benbalter github written in ruby.
   General Services Administration staff was essential in developing the methodology for this tool. 









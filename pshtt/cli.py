#!/usr/bin/env python

"""pshtt ("pushed") is a tool to test domains for HTTPS best practices.

Usage:
  pshtt (INPUT ...) [--output OUTFILE] [--sorted] [--json] [--markdown] [--debug] [--timeout TIMEOUT] [--user-agent AGENT] [--preload-cache PRELOAD] [--cache] [--suffix-cache SUFFIX] [--ca-file PATH]
  pshtt (-h | --help)

Options:
  -h --help                   Show this message.
  -s --sorted                 Sort output by domain, A-Z.
  -o --output=OUTFILE         Name output file. (Defaults to "results".)
  -j --json                   Get results in JSON. (Defaults to CSV.)
  -m --markdown               Get results in Markdown. (Defaults to CSV.)
  -d --debug                  Print debug output.
  -u --user-agent=AGENT       Override user agent
  -t --timeout=TIMEOUT        Override timeout (in seconds)
  -p --preload-cache=PRELOAD  Cache preload list, and where to cache it.
  -c --cache                  Cache network requests to a directory.
  -l --suffix-cache=SUFFIX    Cache suffix list, and where to cache it.
  -f --ca-file=PATH           Specify custom CA bundle (PEM format)

Notes:
  If the first INPUT ends with .csv, domains will be read from CSV.
  CSV output will always be written to disk, defaulting to results.csv.
"""

from . import pshtt
from . import utils

import docopt
import logging
import sys


def main():
    args = docopt.docopt(__doc__, version='v0.0.1')
    utils.configure_logging(args['--debug'])

    out_file = args['--output']

    # Read from a .csv, or allow domains on the command line.
    domains = []
    if args['INPUT'][0].endswith(".csv"):
        domains = utils.load_domains(args['INPUT'][0])
    else:
        domains = args['INPUT']

    domains = utils.format_domains(domains)

    # If the user wants to sort them, sort them in place.
    if args['--sorted']:
        domains.sort()

    options = {
        'user_agent': args['--user-agent'],
        'timeout': args['--timeout'],
        'preload_cache': args['--preload-cache'],
        'suffix_cache': args['--suffix-cache'],
        'cache': args['--cache'],
        'ca_file': args['--ca-file']
    }
    results = pshtt.inspect_domains(domains, options)

    # JSON can go to STDOUT, or to a file.
    if args['--json']:
        output = utils.json_for(results)
        if out_file is None:
            print(output)
        else:
            utils.write(output, out_file)
            logging.warn("Wrote results to %s." % out_file)
    # Markdwon can go to STDOUT, or to a file
    elif args['--markdown']:
        output = sys.stdout
        if out_file is not None:
            output = open(out_file, 'w')

        pshtt.md_for(results, output)

        if out_file is not None:
            output.close()
    # CSV always goes to a file.
    else:
        if args['--output'] is None:
            out_file = 'results.csv'
        pshtt.csv_for(results, out_file)
        logging.warn("Wrote results to %s." % out_file)


if __name__ == '__main__':
    main()

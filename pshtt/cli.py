#!/usr/bin/env python

"""pshtt ("pushed") is a tool to test domains for HTTPS best practices.

Usage:
  pshtt (INPUT ...) [--output OUTFILE] [--sorted] [--json] [--debug] [--timeout TIMEOUT] [--user-agent AGENT] [--preload-cache PRELOAD] [--cache]
  pshtt (-h | --help)

Options:
  -h --help                   Show this message.
  -s --sorted                 Sort output by domain, A-Z.
  -o --output=OUTFILE         Name output file. (Defaults to "results".)
  -j --json                   Get results in JSON. (Defaults to CSV.)
  -d --debug                  Print debug output.
  -u --user-agent=AGENT       Override user agent
  -t --timeout=TIMEOUT        Override timeout (in seconds)
  -p --preload-cache=PRELOAD  Cache preload list, and where to cache it.
  -c --cache                  Cache network requests to a directory.

Notes:
  If the first INPUT ends with .csv, domains will be read from CSV.
  CSV output will always be written to disk, defaulting to results.csv.
"""

import docopt
import pshtt
import utils
import logging


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

    # If the user wants to sort them, sort them in place.
    if args['--sorted']:
        domains.sort()

    options = {
        'user_agent': args['--user-agent'],
        'timeout': args['--timeout'],
        'preload_cache': args['--preload-cache'],
        'cache': args['--cache']
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
    # CSV always goes to a file.
    else:
        if args['--output'] is None:
            out_file = 'results.csv'
        pshtt.csv_for(results, out_file)
        logging.warn("Wrote results to %s." % out_file)

if __name__ == '__main__':
    main()

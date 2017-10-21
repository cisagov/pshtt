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
from . import __version__

import contextlib
import csv
import docopt
import logging
import sys

import pytablewriter


@contextlib.contextmanager
def smart_open(filename=None):
    """Context manager that can handle writing to a file or stdout"""
    if filename is None:
        fh = sys.stdout
    else:
        fh = open(filename, 'w')

    try:
        yield fh
    finally:
        if fh is not sys.stdout:
            fh.close()


def main():
    args = docopt.docopt(__doc__, version=__version__)
    utils.configure_logging(args['--debug'])

    out_filename = args['--output']

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

    # Do the domain inspections
    results = pshtt.inspect_domains(domains, options)

    # JSON can go to STDOUT, or to a file.
    if args['--json']:
        # Generate (yield) all the results before exporting to JSON
        results = list(results)

        with smart_open(out_filename) as out_file:
            json_content = utils.json_for(results)

            out_file.write(json_content + '\n')

            if out_file is not sys.stdout:
                logging.warn("Wrote results to %s.", out_filename)

    # Markdwon can go to STDOUT, or to a file
    elif args['--markdown']:
        # Generate all the results before exporting to Markdown
        table = [
            [" %s" % result[header] for header in pshtt.HEADERS]
            for result in results
        ]

        utils.debug("Printing Markdown...", divider=True)
        with smart_open(out_filename) as out_file:
            writer = pytablewriter.MarkdownTableWriter()

            writer.header_list = pshtt.HEADERS
            writer.value_matrix = table
            writer.stream = out_file

            writer.write_table()

    # CSV always goes to a file.
    else:
        if out_filename is None:
            out_filename = 'results.csv'

        utils.debug("Opening CSV file: {}".format(out_filename))
        with smart_open(out_filename) as out_file:
            writer = csv.writer(out_file)

            # Write out header
            writer.writerow(pshtt.HEADERS)

            # Write out the row data as it completes
            for result in results:
                row = [result[header] for header in pshtt.HEADERS]
                writer.writerow(row)

        logging.warn("Wrote results to %s.", out_filename)


if __name__ == '__main__':
    main()

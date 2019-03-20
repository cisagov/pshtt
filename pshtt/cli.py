#!/usr/bin/env python

"""pshtt ("pushed") is a tool to test domains for HTTPS best practices.

Usage:
  pshtt (INPUT ...) [--output OUTFILE] [--sorted] [--json] [--markdown] [--debug] [--timeout TIMEOUT] [--user-agent AGENT] [--cache-third-parties DIR] [--ca-file PATH] [--pt-int-ca-file PATH]
  pshtt (-h | --help)

Options:
  -h --help                     Show this message.
  -s --sorted                   Sort output by domain, A-Z.
  -o --output=OUTFILE           Name output file. (Defaults to "results".)
  -j --json                     Get results in JSON. (Defaults to CSV.)
  -m --markdown                 Get results in Markdown. (Defaults to CSV.)
  -d --debug                    Print debug output.
  -u --user-agent=AGENT         Override user agent.
  -t --timeout=TIMEOUT          Override timeout (in seconds).
  -c --cache-third-parties=DIR  Cache third party data, and what directory to cache it in.
  -f --ca-file=PATH             Specify custom CA bundle (PEM format)
  -p --pt-int-ca-file=PATH       Specify public trust CA bundle with intermediates (PEM format)

Notes:
  If the first INPUT ends with .csv, domains will be read from CSV.
  CSV output will always be written to disk, defaulting to results.csv.
"""

from . import pshtt
from . import utils
from . import __version__
from .utils import smart_open

import csv
import docopt
import logging
import sys

import pytablewriter


def to_csv(results, out_filename):
    utils.debug("Opening CSV file: {}".format(out_filename))
    with smart_open(out_filename) as out_file:
        writer = csv.writer(out_file)

        # Write out header
        writer.writerow(pshtt.HEADERS)

        # Write out the row data as it completes
        for result in results:
            row = [result[header] for header in pshtt.HEADERS]
            writer.writerow(row)

    logging.warning("Wrote results to %s.", out_filename)


def to_json(results, out_filename):
    # Generate (yield) all the results before exporting to JSON
    results = list(results)

    with smart_open(out_filename) as out_file:
        json_content = utils.json_for(results)

        out_file.write(json_content + '\n')

        if out_file is not sys.stdout:
            logging.warning("Wrote results to %s.", out_filename)


def to_markdown(results, out_filename):
    # Generate (yield) all the results before exporting to Markdown
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
        'cache-third-parties': args['--cache-third-parties'],
        'ca_file': args['--ca-file'],
        'pt_int_ca_file': args['--pt-int-ca-file']
    }

    # Do the domain inspections
    results = pshtt.inspect_domains(domains, options)

    # JSON can go to STDOUT, or to a file.
    if args['--json']:
        to_json(results, out_filename)

    # Markdown can go to STDOUT, or to a file
    elif args['--markdown']:
        to_markdown(results, out_filename)

    # CSV always goes to a file.
    else:
        if out_filename is None:
            out_filename = 'results.csv'

        to_csv(results, out_filename)


if __name__ == '__main__':
    main()

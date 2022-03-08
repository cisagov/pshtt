#!/usr/bin/env python

import contextlib
import os
import json
import errno
import csv
import logging
import datetime
import sys
import traceback
import re


# Display exception without re-throwing it.
def format_last_exception():
    exc_type, exc_value, exc_traceback = sys.exc_info()
    return "\n".join(traceback.format_exception(exc_type, exc_value, exc_traceback))


# mkdir -p in python, from:
# http://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST:
            pass
        else:
            raise


def json_for(object):
    return json.dumps(object, sort_keys=True,
                      indent=2, default=format_datetime)


def write(content, destination, binary=False):
    parent = os.path.dirname(destination)
    if parent != "":
        mkdir_p(parent)

    if binary:
        f = open(destination, 'bw')
    else:
        f = open(destination, 'w')  # no utf-8 in python 2
    f.write(content)
    f.close()


def format_datetime(obj):
    if isinstance(obj, datetime.date):
        return obj.isoformat()
    elif isinstance(obj, str):
        return obj
    else:
        return None


# Load domains from a CSV, skip a header row
def load_domains(domain_csv):
    domains = []
    with open(domain_csv) as csvfile:
        for row in csv.reader(csvfile):
            # Skip empty rows.
            if (not row) or (not row[0].strip()):
                continue

            row[0] = row[0].lower()
            # Skip any header row.
            if (not domains) and (row[0].startswith("domain")):
                continue

            domains.append(row[0])
    return domains


# Configure logging level, so logging.debug can hinge on --debug.
def configure_logging(debug=False):
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARNING

    logging.basicConfig(format='%(message)s', level=log_level)


def format_domains(domains):
    formatted_domains = []

    for domain in domains:
        # Replace a single instance of http://, https://, and www. if present.
        formatted_domains.append(re.sub(r"^(https?://)?(www\.)?", "", domain))

    return formatted_domains


def debug(message, divider=False):
    if divider:
        logging.debug("\n-------------------------\n")

    if message:
        logging.debug("%s\n" % message)


@contextlib.contextmanager
def smart_open(filename=None):
    """
    Context manager that can handle writing to a file or stdout

    Adapted from: https://stackoverflow.com/a/17603000
    """
    if filename is None:
        fh = sys.stdout
    else:
        fh = open(filename, 'w')

    try:
        yield fh
    finally:
        if fh is not sys.stdout:
            fh.close()
